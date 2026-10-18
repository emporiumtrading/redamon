"""Durable holds and separately consented deletion of primary encrypted content."""
from datetime import timedelta
from hashlib import sha256
import re
from uuid import uuid4

from gabriel.identity.actions import ActionService,digest
from gabriel.identity.cases import object_aad,iso
from gabriel.identity.evidence_store import EvidenceError,canonical
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,_digest,connection,identifier


def reason(value):
    if not isinstance(value,str) or not 1<=len(value.strip())<=400 or any(ord(c)<32 or ord(c)==127 for c in value):
        raise InvalidIdentityInput('invalid_retention_reason')
    return value.strip()


def public(row):
    return {k:v for k,v in row.items() if k not in {'requester_session','approver_session'}}


class RetentionService(ActionService):
    def _event(self,conn,p,target,event,detail=None):
        conn.execute('''INSERT INTO gabriel_identity.retention_events
            (organization_id,id,actor_id,target_id,event,detail) VALUES (%s,%s,%s,%s,%s,%s::jsonb)''',
            (p.organization_id,uuid4(),p.user_id,target,event,canonical(detail or {}).decode()))
        _audit(conn,'retention.'+event,p,target)

    def set_retention(self,token,days):
        if type(days) is not int or not 1<=days<=3650:
            raise InvalidIdentityInput('invalid_retention_days')
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            revision = conn.execute('SELECT COALESCE(max(revision),0)+1 AS n FROM gabriel_identity.retention_policies WHERE organization_id=%s',
                (p.organization_id,)).fetchone()['n']
            if revision>1024:
                raise AccessDenied('retention_policy_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.retention_policies
                (organization_id,revision,days,created_by) VALUES (%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,revision,days,p.user_id)).fetchone()
            _audit(conn,'retention.policy_changed',p)
            return row

    def _retention(self,conn,p):
        row = conn.execute('''SELECT *,max(days) OVER () AS floor_days FROM gabriel_identity.retention_policies
            WHERE organization_id=%s ORDER BY revision DESC LIMIT 1''',(p.organization_id,)).fetchone()
        if not row:
            raise AccessDenied('retention_policy_required')
        return row

    def get_retention(self,token):
        with connection(self._dsn) as conn:
            return self._retention(conn,self._human(conn,token))

    def _generation(self,conn,p,case_id):
        row = conn.execute('SELECT revision FROM gabriel_identity.case_hold_versions WHERE organization_id=%s AND case_id=%s',
            (p.organization_id,case_id)).fetchone()
        return row['revision'] if row else 0

    def _bump(self,conn,p,case_id):
        conn.execute('''INSERT INTO gabriel_identity.case_hold_versions VALUES (%s,%s,1)
            ON CONFLICT (organization_id,case_id) DO UPDATE SET revision=case_hold_versions.revision+1''',
            (p.organization_id,case_id))

    def place_hold(self,token,case_id,hold_reason):
        hold_reason = reason(hold_reason)
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            case = self._case(conn,p,case_id)
            if conn.execute("SELECT count(*) AS n FROM gabriel_identity.legal_holds WHERE organization_id=%s AND case_id=%s AND state='active'",
                    (p.organization_id,case['id'])).fetchone()['n']>=64:
                raise AccessDenied('active_hold_limit')
            rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s ORDER BY id',
                (p.organization_id,case['id'])).fetchall()
            coverage = []
            for row in rows:
                code = 'verified_present'
                try:
                    self._verify(conn,row,allow_disposition=True)
                except EvidenceError as exc:
                    code = str(exc)
                disposition = self._disposition(conn,row)
                coverage.append({'evidence_id':str(row['id']),'content':code,
                    'disposition':disposition['state'] if disposition else None})
            hold_id = uuid4()
            bound = digest([str(p.organization_id),str(case['id']),str(hold_id),str(p.user_id),hold_reason,coverage])
            row = conn.execute('''INSERT INTO gabriel_identity.legal_holds
                (organization_id,id,case_id,created_by,reason,digest,coverage) VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb) RETURNING *''',
                (p.organization_id,hold_id,case['id'],p.user_id,hold_reason,bound,canonical(coverage).decode())).fetchone()
            self._bump(conn,p,case['id'])
            self._event(conn,p,hold_id,'hold_placed',{'case_id':str(case['id']),'digest':bound})
            return row

    def release_hold(self,token,hold_id,expected_digest,release_reason):
        release_reason = reason(release_reason)
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            row = conn.execute('SELECT * FROM gabriel_identity.legal_holds WHERE organization_id=%s AND id=%s FOR UPDATE',
                (p.organization_id,identifier(hold_id))).fetchone()
            if (not row or row['state']!='active' or row['created_by']==p.user_id or row['digest']!=expected_digest
                    or digest([str(p.organization_id),str(row['case_id']),str(row['id']),str(row['created_by']),row['reason'],row['coverage']])!=row['digest']):
                raise AccessDenied('hold_release_not_permitted')
            conn.execute('INSERT INTO gabriel_identity.hold_releases (organization_id,hold_id,released_by,digest,reason) VALUES (%s,%s,%s,%s,%s)',
                (p.organization_id,row['id'],p.user_id,row['digest'],release_reason))
            conn.execute("UPDATE gabriel_identity.legal_holds SET state='released' WHERE organization_id=%s AND id=%s",(p.organization_id,row['id']))
            self._bump(conn,p,row['case_id'])
            self._event(conn,p,row['id'],'hold_released',{'digest':row['digest']})

    def governance(self,token,case_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            case = self._case(conn,p,case_id)
            holds = conn.execute("SELECT * FROM gabriel_identity.legal_holds WHERE organization_id=%s AND case_id=%s ORDER BY (state='active') DESC,created_at DESC,id LIMIT 164",
                (p.organization_id,case['id'])).fetchall()
            attempts = conn.execute('''SELECT a.* FROM gabriel_identity.purge_attempts a JOIN gabriel_identity.evidence_objects e
                ON (e.organization_id,e.id)=(a.organization_id,a.evidence_id) WHERE e.organization_id=%s AND e.case_id=%s
                ORDER BY (a.state IN ('prepared','completed')) DESC,a.created_at DESC,a.id LIMIT 164''',
                (p.organization_id,case['id'])).fetchall()
            holds_total = conn.execute('SELECT count(*) AS n FROM gabriel_identity.legal_holds WHERE organization_id=%s AND case_id=%s',
                (p.organization_id,case['id'])).fetchone()['n']
            attempts_total = conn.execute('''SELECT count(*) AS n FROM gabriel_identity.purge_attempts a
                JOIN gabriel_identity.evidence_objects e ON (e.organization_id,e.id)=(a.organization_id,a.evidence_id)
                WHERE e.organization_id=%s AND e.case_id=%s''',(p.organization_id,case['id'])).fetchone()['n']
            return {'case_id':str(case['id']),'hold_version':self._generation(conn,p,case['id']),
                    'holds':holds,'dispositions':attempts,'history_limit_per_list':164,
                    'history_truncated':{'holds':holds_total>len(holds),'dispositions':attempts_total>len(attempts)},
                    'history_counts':{'holds':holds_total,'dispositions':attempts_total}}

    def _snapshot_purge(self,conn,p,row,*,allow_prepared=False,enroll=False):
        case = self._case(conn,p,row['case_id'])
        if case['state']!='closed':
            raise AccessDenied('purge_requires_closed_case')
        policy = self._retention(conn,p)
        now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        until = row['observed_at']+timedelta(days=policy['floor_days'])
        if until>now:
            raise AccessDenied('evidence_retention_not_elapsed')
        if conn.execute("SELECT 1 FROM gabriel_identity.legal_holds WHERE organization_id=%s AND case_id=%s AND state='active' LIMIT 1",
                (p.organization_id,case['id'])).fetchone():
            raise AccessDenied('evidence_on_legal_hold')
        if conn.execute("SELECT 1 FROM gabriel_identity.evidence_exports WHERE organization_id=%s AND evidence_id=%s AND state='prepared' LIMIT 1",
                (p.organization_id,row['id'])).fetchone():
            raise AccessDenied('evidence_export_unresolved')
        disposition = self._disposition(conn,row)
        if disposition and (disposition['state']=='completed' or not allow_prepared):
            raise AccessDenied('evidence_disposition_exists')
        self._verify(conn,row,allow_disposition=allow_prepared)
        chain = self._chain(conn,row)
        return {'schema_version':1,'operation':'evidence.content.purge','case_id':str(case['id']),
            'evidence_id':str(row['id']),'context_digest':sha256(object_aad(row)).hexdigest(),
            'closed_at':iso(case['closed_at']),'policy_revision':policy['revision'],
            'policy_digest':digest([policy['revision'],policy['days'],policy['floor_days']]),
            'hold_version':self._generation(conn,p,case['id']),'retain_until':iso(until),
            'custody_sequence':chain[-1]['sequence'],'custody_head':chain[-1]['event_hash'],
            'store_id':self.store.identity(enroll=enroll)}

    def _purge_request(self,conn,p,request_id):
        row = conn.execute('SELECT * FROM gabriel_identity.purge_requests WHERE organization_id=%s AND id=%s FOR UPDATE',
            (p.organization_id,identifier(request_id))).fetchone()
        if not row:
            raise AccessDenied('purge_request_not_accessible')
        payload = row['payload']
        fields = {'schema_version','operation','case_id','evidence_id','context_digest','closed_at','policy_revision',
                  'policy_digest','hold_version','retain_until','custody_sequence','custody_head','rationale','store_id'}
        if (digest(payload)!=row['digest'] or set(payload)!=fields or payload.get('evidence_id')!=str(row['evidence_id'])
                or type(payload['schema_version']) is not int or payload['schema_version']!=1
                or payload['operation']!='evidence.content.purge' or type(payload['custody_sequence']) is not int
                or not 1<=payload['custody_sequence']<=4096
                or any(not isinstance(payload[k],str) or not re.fullmatch('[a-f0-9]{64}',payload[k]) for k in ('context_digest','policy_digest','custody_head'))):
            raise AccessDenied('purge_payload_invalid')
        return row

    def _actor(self,conn,org,user,session):
        row = conn.execute('''SELECT m.role FROM gabriel_identity.sessions s
            JOIN gabriel_identity.memberships m USING (organization_id,user_id)
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(s.organization_id,s.user_id)
            WHERE s.organization_id=%s AND s.user_id=%s AND s.token_digest=%s AND s.audience='gabriel-identity-v1'
            AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active AND u.active''',
            (org,user,session)).fetchone()
        if not row or row['role'] not in {'owner','admin'}:
            raise AccessDenied('purge_actor_revoked')

    def _validate_purge(self,conn,p,request,*,approval=False,allow_prepared=False):
        now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        if request['expires_at']<=now:
            raise AccessDenied('purge_request_expired')
        self._actor(conn,p.organization_id,request['requested_by'],request['requester_session'])
        row = self._evidence(conn,p,request['evidence_id'])
        snapshot = self._snapshot_purge(conn,p,row,allow_prepared=allow_prepared)
        expected = request['payload']
        if any(snapshot.get(k)!=v for k,v in expected.items() if k not in {'rationale','custody_sequence','custody_head'}):
            raise AccessDenied('purge_context_changed')
        prefix = conn.execute('SELECT event_hash FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s AND sequence=%s',
            (p.organization_id,row['id'],expected['custody_sequence'])).fetchone()
        if not prefix or prefix['event_hash']!=expected['custody_head']:
            raise AccessDenied('purge_custody_changed')
        if approval:
            consent = conn.execute('SELECT * FROM gabriel_identity.purge_approvals WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,request['id'])).fetchone()
            if (not consent or consent['digest']!=request['digest'] or consent['expires_at']<=now
                    or consent['approved_by']==request['requested_by']):
                raise AccessDenied('purge_approval_invalid_or_expired')
            self._actor(conn,p.organization_id,consent['approved_by'],consent['approver_session'])
        return row

    def propose_purge(self,token,evidence_id,request_id,purge_reason):
        purge_reason,request_id = reason(purge_reason),identifier(request_id)
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            row = self._evidence(conn,p,evidence_id)
            old = conn.execute('SELECT id FROM gabriel_identity.purge_requests WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,request_id)).fetchone()
            if old:
                old = self._purge_request(conn,p,old['id'])
                if old['evidence_id']!=row['id'] or old['requested_by']!=p.user_id or old['payload']['rationale']!=purge_reason:
                    raise AccessDenied('purge_request_conflict')
                _audit(conn,'retention.proposal_replayed',p,old['id'])
                return public(old)
            if conn.execute("SELECT count(*) AS n FROM gabriel_identity.purge_requests WHERE organization_id=%s AND state IN ('proposed','approved') AND expires_at>clock_timestamp()",
                    (p.organization_id,)).fetchone()['n']>=100:
                raise AccessDenied('active_purge_limit')
            payload = self._snapshot_purge(conn,p,row,enroll=True)
            payload['rationale'] = purge_reason
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            request = conn.execute('''INSERT INTO gabriel_identity.purge_requests
                (organization_id,id,request_id,evidence_id,requested_by,requester_session,payload,digest,created_at,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) RETURNING *''',
                (p.organization_id,uuid4(),request_id,row['id'],p.user_id,_digest(token),canonical(payload).decode(),digest(payload),now,now+timedelta(minutes=15))).fetchone()
            self._event(conn,p,request['id'],'purge_proposed',{'digest':request['digest']})
            return public(request)

    def approve_purge(self,token,request_id,expected_digest):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            request = self._purge_request(conn,p,request_id)
            if request['state']!='proposed' or request['digest']!=expected_digest or request['requested_by']==p.user_id:
                raise AccessDenied('purge_approval_not_permitted')
            self._validate_purge(conn,p,request)
            self._principal(conn,token,lock=True)
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            if request['expires_at']<=now:
                raise AccessDenied('purge_request_expired')
            conn.execute('''INSERT INTO gabriel_identity.purge_approvals
                (organization_id,request_id,approved_by,approver_session,digest,created_at,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                (p.organization_id,request['id'],p.user_id,_digest(token),request['digest'],now,min(request['expires_at'],now+timedelta(minutes=5))))
            conn.execute("UPDATE gabriel_identity.purge_requests SET state='approved' WHERE organization_id=%s AND id=%s",(p.organization_id,request['id']))
            self._event(conn,p,request['id'],'purge_approved',{'digest':request['digest']})

    def prepare_purge(self,token,request_id):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            request = self._purge_request(conn,p,request_id)
            existing = conn.execute('SELECT * FROM gabriel_identity.purge_attempts WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,request['id'])).fetchone()
            if existing:
                if existing['prepared_by']!=p.user_id or existing['state']=='aborted':
                    raise AccessDenied('purge_attempt_conflict')
                if existing['state']=='prepared':
                    self._validate_purge(conn,p,request,approval=True,allow_prepared=True)
                _audit(conn,'retention.preparation_replayed',p,existing['id'])
                return existing
            if request['state']!='approved':
                raise AccessDenied('purge_request_not_approved')
            row = self._validate_purge(conn,p,request,approval=True)
            attempt = conn.execute('''INSERT INTO gabriel_identity.purge_attempts
                (organization_id,id,evidence_id,request_id,prepared_by) VALUES (%s,%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,uuid4(),row['id'],request['id'],p.user_id)).fetchone()
            self._event(conn,p,attempt['id'],'purge_prepared',{'request_id':str(request['id']),'digest':request['digest']})
            return attempt

    def _attempt(self,conn,p,attempt_id):
        row = conn.execute('SELECT * FROM gabriel_identity.purge_attempts WHERE organization_id=%s AND id=%s FOR UPDATE',
            (p.organization_id,identifier(attempt_id))).fetchone()
        if not row:
            raise AccessDenied('purge_attempt_not_accessible')
        request = self._purge_request(conn,p,row['request_id'])
        if request['evidence_id']!=row['evidence_id']:
            raise AccessDenied('purge_attempt_binding_invalid')
        return row

    def _complete(self,conn,p,attempt,outcome,event):
        conn.execute("UPDATE gabriel_identity.purge_attempts SET state='completed',outcome=%s WHERE organization_id=%s AND id=%s",(outcome,p.organization_id,attempt['id']))
        conn.execute("UPDATE gabriel_identity.purge_requests SET state='completed' WHERE organization_id=%s AND id=%s",(p.organization_id,attempt['request_id']))
        self._event(conn,p,attempt['id'],event,{'outcome':outcome,'evidence_id':str(attempt['evidence_id'])})
        return {'attempt_id':str(attempt['id']),'evidence_id':str(attempt['evidence_id']),'state':'completed','outcome':outcome}

    def execute_purge(self,token,attempt_id):
        # The separately committed prepared intent survives a crash after unlink.
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            attempt = self._attempt(conn,p,attempt_id)
            if attempt['state']!='prepared' or attempt['prepared_by']!=p.user_id:
                raise AccessDenied('purge_attempt_not_executable')
            row = self._evidence(conn,p,attempt['evidence_id'])
            request = self._purge_request(conn,p,attempt['request_id'])
            if self.store.identity()!=request['payload']['store_id']:
                raise AccessDenied('purge_store_changed')
            if self.store.absent(row):
                raise AccessDenied('purge_absence_requires_reconciliation')
            if request['state']!='approved':
                raise AccessDenied('purge_request_not_approved')
            self._validate_purge(conn,p,request,approval=True,allow_prepared=True)
            consent = conn.execute('SELECT * FROM gabriel_identity.purge_approvals WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,request['id'])).fetchone()
            def admit():
                self._principal(conn,token,lock=True)
                self._actor(conn,p.organization_id,request['requested_by'],request['requester_session'])
                self._actor(conn,p.organization_id,consent['approved_by'],consent['approver_session'])
                now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
                if min(request['expires_at'],consent['expires_at'])<=now:
                    raise AccessDenied('purge_approval_invalid_or_expired')
                _audit(conn,'retention.unlink_admitted',p,attempt['id'])
            outcome = self.store.remove(row,object_aad(row),admit=admit)
            if not self.store.absent(row,sync=True):
                raise EvidenceError('purge_absence_unconfirmed')
            return self._complete(conn,p,attempt,outcome,'purge_completed')

    def cancel_purge(self,token,request_id):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            request = self._purge_request(conn,p,request_id)
            if request['state'] not in {'proposed','approved'} or conn.execute('SELECT 1 FROM gabriel_identity.purge_attempts WHERE organization_id=%s AND request_id=%s',
                    (p.organization_id,request['id'])).fetchone():
                raise AccessDenied('purge_request_not_cancellable')
            conn.execute("UPDATE gabriel_identity.purge_requests SET state='cancelled' WHERE organization_id=%s AND id=%s",(p.organization_id,request['id']))
            self._event(conn,p,request['id'],'purge_cancelled')

    def reconcile_purge(self,token,attempt_id,*,abort=False):
        if type(abort) is not bool:
            raise InvalidIdentityInput('invalid_purge_reconciliation')
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            attempt = self._attempt(conn,p,attempt_id)
            row = self._evidence(conn,p,attempt['evidence_id'])
            request = self._purge_request(conn,p,attempt['request_id'])
            if self.store.identity()!=request['payload']['store_id']:
                raise AccessDenied('purge_store_changed')
            if attempt['state']=='completed' and not abort:
                if not self.store.absent(row,sync=True):
                    raise EvidenceError('purged_content_reappeared')
                _audit(conn,'retention.absence_rechecked',p,attempt['id'])
                return {'attempt_id':str(attempt['id']),'state':'completed','outcome':attempt['outcome']}
            if attempt['state']!='prepared':
                raise AccessDenied('purge_attempt_not_reconcilable')
            if abort:
                self._verify(conn,row,allow_disposition=True)
                conn.execute("UPDATE gabriel_identity.purge_attempts SET state='aborted',outcome='verified_present' WHERE organization_id=%s AND id=%s",(p.organization_id,attempt['id']))
                conn.execute("UPDATE gabriel_identity.purge_requests SET state='cancelled' WHERE organization_id=%s AND id=%s",(p.organization_id,attempt['request_id']))
                self._event(conn,p,attempt['id'],'purge_aborted',{'outcome':'verified_present'})
                return {'attempt_id':str(attempt['id']),'state':'aborted','outcome':'verified_present'}
            if not self.store.absent(row,sync=True):
                raise AccessDenied('purge_content_still_present')
            return self._complete(conn,p,attempt,'absence_confirmed','purge_reconciled')

    def get_purge(self,token,request_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            request = self._purge_request(conn,p,request_id)
            result = public(request)
            approval = conn.execute('SELECT * FROM gabriel_identity.purge_approvals WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,request['id'])).fetchone()
            result['approval'] = public(approval) if approval else None
            result['attempt'] = conn.execute('SELECT * FROM gabriel_identity.purge_attempts WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,request['id'])).fetchone()
            result['effective_state'] = request['state']
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            if request['state'] in {'proposed','approved'} and (request['expires_at']<=now or approval and approval['expires_at']<=now):
                result['effective_state'] = 'expired'
            return result
