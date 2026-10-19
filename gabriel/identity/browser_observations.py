"""Bounded approved observation admission through existing evidence/custody, with durable recovery."""
from hashlib import sha256
import re
from uuid import uuid4

from gabriel.identity.browser_sessions import BrowserSessionService,approved_context,browser_digest
from gabriel.identity.cases import timestamp,iso
from gabriel.identity.checkpoints import canonical
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,_digest,connection,identifier
from gabriel.identity.tasks import task_record,available

SOURCE_LABEL = 'Browser approved observation'
FIELDS = {'schema_version','operation','request_id','sequence','context','observed_at','visibility','client_minimized','content'}
SECRET = re.compile(r'''\b(?:authorization|set-cookie|cookie|password|passwd|otp|access_token|refresh_token|api_key|api-key|client_secret|secret_access_key)["']?\s*[:=]\s*\S+''',re.I)


def envelope(value):
    if (not isinstance(value,dict) or set(value)!=FIELDS or type(value['schema_version']) is not int
            or value['schema_version']!=1 or value['operation']!='browser.observe'
            or type(value['sequence']) is not int or not 1<=value['sequence']<=1000
            or not isinstance(value['visibility'],str) or value['visibility'] not in {'visible_text_only','partial'} or value['client_minimized'] is not True
            or not isinstance(value['observed_at'],str) or not isinstance(value['content'],str)):
        raise InvalidIdentityInput('invalid_browser_observation')
    try:
        data = value['content'].encode('utf-8')
    except UnicodeError:
        raise InvalidIdentityInput('invalid_browser_content') from None
    if not 1<=len(data)<=65536 or any(ord(c)<32 and c not in '\n\t\r' for c in value['content']):
        raise InvalidIdentityInput('browser_content_limit')
    if SECRET.search(value['content']):
        raise AccessDenied('browser_privacy_review_required')
    normalized = dict(value,request_id=str(identifier(value['request_id'])),context=approved_context(value['context']))
    observed = timestamp(value['observed_at'])
    return normalized,data,observed,sha256(canonical(normalized)).hexdigest()


def observation_metadata(row):
    return dict(row,collection_type='engineer_approved_browser_claim',source_verified=False,
        normalization_status='unverified_browser_supplied_text',current_page_visibility_verified=False)


class BrowserObservationService(BrowserSessionService):
    def _observer(self,conn,human_token,peer_token,context):
        preliminary = self._principal(conn,human_token)
        hint = conn.execute('SELECT organization_id,human_session_digest FROM gabriel_identity.browser_leases WHERE token_digest=%s',
            (browser_digest(peer_token),)).fetchone()
        if not hint or hint['organization_id']!=preliminary.organization_id or hint['human_session_digest']!=_digest(human_token):
            raise AccessDenied('browser_human_binding_mismatch')
        p = self._human(conn,human_token,write=True)
        _,lease = self._browser(conn,peer_token)
        self._browser_context(lease,context)
        now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        if not lease['intake_enabled']:
            raise AccessDenied('browser_sharing_not_approved')
        if not lease['last_seen'] or not 0<=(now-lease['last_seen']).total_seconds()<=45:
            raise AccessDenied('browser_heartbeat_gap_repair_required')
        return p,lease,now

    def _observation(self,conn,p,observation_id):
        row = conn.execute('SELECT * FROM gabriel_identity.browser_observations WHERE organization_id=%s AND id=%s FOR UPDATE',
            (p.organization_id,identifier(observation_id))).fetchone()
        if not row:
            raise AccessDenied('browser_observation_not_accessible')
        return row

    def _receipt(self,conn,p,row):
        result = conn.execute('SELECT * FROM gabriel_identity.browser_observation_receipts WHERE organization_id=%s AND observation_id=%s',
            (p.organization_id,row['id'])).fetchone()
        if not result or result['evidence_id']!=row['evidence_id']:
            raise EvidenceError('browser_observation_receipt_invalid')
        return dict(result,source_verified=False,current_page_visibility_verified=False)

    def _captured_artifact(self,conn,p,row,lease):
        artifact = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s AND ingestion_id=%s',
            (p.organization_id,lease['case_id'],row['id'])).fetchone()
        if (not artifact or artifact['digest']!=row['content_digest'] or artifact['byte_length']!=row['byte_length']
                or artifact['source_label']!=SOURCE_LABEL or artifact['source_event_time']!=row['observed_at']
                or artifact['redaction_state']!='user_declared_redacted'):
            raise EvidenceError('browser_evidence_binding_invalid')
        return artifact

    def _complete_observation(self,conn,p,row,lease,mode,admit):
        artifact = self._captured_artifact(conn,p,row,lease)
        self._verify(conn,artifact)
        admit()
        result = conn.execute('''INSERT INTO gabriel_identity.browser_observation_receipts
            (organization_id,observation_id,evidence_id,completed_by,mode) VALUES (%s,%s,%s,%s,%s) RETURNING *''',
            (p.organization_id,row['id'],artifact['id'],p.user_id,mode)).fetchone()
        conn.execute("UPDATE gabriel_identity.browser_observations SET state='captured',evidence_id=%s WHERE organization_id=%s AND id=%s",
            (artifact['id'],p.organization_id,row['id']))
        _audit(conn,'browser.observation_captured',p,row['id'])
        return dict(result,source_verified=False,current_page_visibility_verified=False)

    def observe_browser(self,human_token,peer_token,payload):
        payload,data,observed,request_digest = envelope(payload)
        with connection(self._dsn) as conn:
            p,lease,now = self._observer(conn,human_token,peer_token,payload['context'])
            row = conn.execute('SELECT * FROM gabriel_identity.browser_observations WHERE organization_id=%s AND lease_id=%s AND request_id=%s FOR UPDATE',
                (p.organization_id,lease['id'],payload['request_id'])).fetchone()
            if row:
                if row['request_digest']!=request_digest or row['sequence']!=payload['sequence']:
                    raise AccessDenied('browser_observation_retry_conflict')
                if row['state']=='captured':
                    _audit(conn,'browser.observation_replayed',p,row['id'])
                    return self._receipt(conn,p,row)
            else:
                if not -5<=(now-observed).total_seconds()<=60:
                    raise AccessDenied('browser_observation_not_fresh')
                task = task_record(conn,p.organization_id,lease['task_id'])
                available(task)
                previous = conn.execute('SELECT COALESCE(max(sequence),0) AS n FROM gabriel_identity.browser_observations WHERE organization_id=%s AND lease_id=%s',
                    (p.organization_id,lease['id'])).fetchone()['n']
                if payload['sequence']!=previous+1 or conn.execute("SELECT 1 FROM gabriel_identity.browser_observations WHERE organization_id=%s AND lease_id=%s AND state='prepared'",
                        (p.organization_id,lease['id'])).fetchone():
                    raise AccessDenied('browser_observation_order_or_pending')
                row = conn.execute('''INSERT INTO gabriel_identity.browser_observations
                    (organization_id,id,lease_id,request_id,sequence,request_digest,content_digest,byte_length,observed_at,visibility)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                    (p.organization_id,uuid4(),lease['id'],payload['request_id'],payload['sequence'],request_digest,
                     sha256(data).hexdigest(),len(data),observed,payload['visibility'])).fetchone()
                conn.execute("UPDATE gabriel_identity.investigation_tasks SET used_steps=used_steps+1,state=CASE WHEN used_steps+1=max_steps THEN 'exhausted' ELSE state END WHERE organization_id=%s AND id=%s",
                    (p.organization_id,task['id']))
                _audit(conn,'browser.observation_prepared',p,row['id'])
            observation_id,case_id = row['id'],lease['case_id']
        # This recheck precedes the existing separately durable evidence acquisition protocol.
        with connection(self._dsn) as conn:
            self._observer(conn,human_token,peer_token,payload['context'])
        self.acquire(human_token,case_id,observation_id,payload['content'],SOURCE_LABEL,approved=True,
            event_time=iso(observed),redaction_state='user_declared_redacted')
        with connection(self._dsn) as conn:
            p,lease,_ = self._observer(conn,human_token,peer_token,payload['context'])
            row = self._observation(conn,p,observation_id)
            if row['state']=='captured':
                return self._receipt(conn,p,row)
            return self._complete_observation(conn,p,row,lease,'peer_intake',
                lambda:self._observer(conn,human_token,peer_token,payload['context']))

    def reconcile_browser_observation(self,human_token,observation_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,human_token,write=True)
            row = self._observation(conn,p,observation_id)
            lease = conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',
                (p.organization_id,row['lease_id'])).fetchone()
            if p.role not in {'owner','admin'} and p.user_id!=lease['issued_by']:
                raise AccessDenied('browser_observation_reconcile_denied')
            if row['state']=='captured':
                _audit(conn,'browser.observation_reconcile_replayed',p,row['id'])
                return self._receipt(conn,p,row)
            artifact = self._captured_artifact(conn,p,row,lease)
            data = self._verify(conn,artifact,ready=False)
            evidence_id = artifact['id']
        self._finish_acquisition(human_token,evidence_id,data)
        with connection(self._dsn) as conn:
            p = self._human(conn,human_token,write=True)
            row = self._observation(conn,p,observation_id)
            lease = conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',
                (p.organization_id,row['lease_id'])).fetchone()
            if p.role not in {'owner','admin'} and p.user_id!=lease['issued_by']:
                raise AccessDenied('browser_observation_reconcile_denied')
            if row['state']=='captured':
                return self._receipt(conn,p,row)
            return self._complete_observation(conn,p,row,lease,'engineer_reconciled',
                lambda:self._principal(conn,human_token,lock=True))

    def get_browser_observation(self,human_token,observation_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,human_token)
            return observation_metadata(self._observation(conn,p,observation_id))

    def connect_browser(self,token,context):
        result = super().connect_browser(token,context)
        with connection(self._dsn) as conn:
            _,lease = self._browser(conn,token)
            if lease['intake_enabled']:
                result['capabilities'].append('observation.submit')
            result['sharing_approved']=lease['intake_enabled']
        return result

    def get_browser_lease(self,human_token,lease_id):
        result = super().get_browser_lease(human_token,lease_id)
        with connection(self._dsn) as conn:
            p = self._human(conn,human_token)
            total = conn.execute("SELECT count(*) AS n FROM gabriel_identity.browser_observations WHERE organization_id=%s AND lease_id=%s AND state='captured'",
                (p.organization_id,identifier(lease_id))).fetchone()['n']
            result['captured_observations']=total
            result['page_content_received']=total>0
            result['current_page_visibility_verified']=False
        return result
