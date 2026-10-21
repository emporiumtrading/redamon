"""Tenant cases and audited evidence custody; supplied artifacts are never source truth."""
from datetime import datetime,timezone
from hashlib import sha256
import re
from uuid import uuid4

from gabriel.identity.service import (AccessDenied,IdentityError,IdentityService,InvalidIdentityInput,
    _audit,connection,identifier)
from gabriel.identity.tasks import task_record
from gabriel.identity.evidence_store import (EvidenceContent,EvidenceError,LocalEvidenceStore,
    MAX_BYTES,canonical)
from gabriel.identity.evidence_crypto import admit_epoch,available,epoch,register_key,storage_row,verified_read

ZERO_HASH = '0'*64


def timestamp(value):
    if value is None:
        return None
    try:
        value = datetime.fromisoformat(value) if isinstance(value,str) else value
        if not isinstance(value,datetime) or value.utcoffset() is None or not 1970<=value.year<=2100:
            raise ValueError
        return value.astimezone(timezone.utc)
    except (ValueError,TypeError,OverflowError):
        raise InvalidIdentityInput('invalid_source_time') from None


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec='microseconds') if value else None


def custody_hash(org,evidence,sequence,actor,event,previous,created):
    return sha256(canonical([str(org),str(evidence),sequence,str(actor),event,previous,iso(created)])).hexdigest()


def object_aad(row):
    return canonical(['evidence-v1',str(row['organization_id']),str(row['case_id']),str(row['id']),
        str(row['object_id']),str(row['ingestion_id']),row['intake_digest'],row['digest'],row['byte_length'],
        row['key_id'],str(row['acquired_by']),row['source_kind'],row['source_label'],iso(row['source_event_time']),
        iso(row['observed_at']),row['schema_version'],row['parser_version'],row['redaction_state'],
        str(row['parent_id']) if row['parent_id'] else None,row['acquisition_hash']])


def metadata(row):
    result = {k:v for k,v in row.items() if k not in {'object_id','intake_digest','acquisition_hash'}}
    result['source_verified'] = False
    result['normalization_status'] = 'unverified_user_supplied'
    result['storage_state'] = 'active'
    return result


class CaseService(IdentityService):
    def begin_coordinator(self,token,case_id,request_id,**limits):
        from gabriel.identity.coordinator import begin
        return begin(self,token,case_id,request_id,**limits)

    def get_coordinator(self,token,run_id):
        from gabriel.identity.coordinator import get
        return get(self,token,run_id)

    def list_coordinator_runs(self,token,case_id):
        from gabriel.identity.coordinator import history
        return history(self,token,case_id)

    def advance_coordinator(self,token,run_id,**options):
        from gabriel.identity.coordinator import advance
        return advance(self,token,run_id,**options)

    def stop_coordinator(self,token,run_id):
        from gabriel.identity.coordinator import stop
        return stop(self,token,run_id)

    def propose_memory(self,token,case_id,evidence_id,request_id,kind,scope,topic,**options):
        from gabriel.identity.memory import propose
        return propose(self,token,case_id,evidence_id,request_id,kind,scope,topic,**options)

    def review_memory(self,token,memory_id,decision,expected_digest,acknowledged=False):
        from gabriel.identity.memory import review
        return review(self,token,memory_id,decision,expected_digest,acknowledged)

    def list_memory(self,token,case_id):
        from gabriel.identity.memory import list_memory
        return list_memory(self,token,case_id)

    def retrieve_memory(self,token,case_id):
        from gabriel.identity.memory import retrieve
        return retrieve(self,token,case_id)

    def forget_memory(self,token,memory_id,reason='analyst_requested'):
        from gabriel.identity.memory import forget
        return forget(self,token,memory_id,reason)

    def reset_memory(self,token,expected_epoch):
        from gabriel.identity.memory import reset
        return reset(self,token,expected_epoch)

    def run_specialist(self,token,case_id,request_id,role):
        from gabriel.identity.specialists import run_specialist
        return run_specialist(self,token,case_id,request_id,role)

    def get_specialist_run(self,token,case_id,run_id):
        from gabriel.identity.specialists import get_run
        return get_run(self,token,case_id,run_id)

    def list_specialist_runs(self,token,case_id):
        from gabriel.identity.specialists import list_runs
        return list_runs(self,token,case_id)

    def assign_case(self,token,case_id,request_id,assigned_to):
        from gabriel.identity.case_workflow import assign_case
        return assign_case(self,token,case_id,request_id,assigned_to)

    def add_question(self,token,case_id,request_id,question):
        from gabriel.identity.case_workflow import add_question
        return add_question(self,token,case_id,request_id,question)

    def answer_question(self,token,case_id,question_id,evidence_id,answer):
        from gabriel.identity.case_workflow import answer_question
        return answer_question(self,token,case_id,question_id,evidence_id,answer)

    def case_workflow(self,token,case_id):
        from gabriel.identity.case_workflow import case_workflow
        return case_workflow(self,token,case_id)

    def __init__(self,dsn,store):
        super().__init__(dsn)
        if not isinstance(store,LocalEvidenceStore):
            raise InvalidIdentityInput('evidence_store_required')
        self.store = store

    def _human(self,conn,token,*,write=False,content=False):
        principal = self._principal(conn,token,lock=True)
        if (write or content) and principal.role not in {'owner','admin','analyst'}:
            raise AccessDenied('operation_not_permitted')
        if write:
            admit_epoch(conn,principal.organization_id,self.store.keys)
        return principal

    def _case(self,conn,principal,case_id,*,open_only=False):
        row = conn.execute('SELECT * FROM gabriel_identity.cases WHERE organization_id=%s AND id=%s FOR UPDATE',
            (principal.organization_id,identifier(case_id))).fetchone()
        if not row:
            raise AccessDenied('case_not_accessible')
        if open_only and row['state']!='open':
            raise AccessDenied('case_not_open')
        return row

    def _evidence(self,conn,principal,evidence_id):
        row = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND id=%s FOR UPDATE',
            (principal.organization_id,identifier(evidence_id))).fetchone()
        if not row:
            raise AccessDenied('evidence_not_accessible')
        return row

    def _chain(self,conn,row):
        rows = conn.execute('''SELECT * FROM gabriel_identity.custody_events
            WHERE organization_id=%s AND evidence_id=%s ORDER BY sequence LIMIT 4097''',
            (row['organization_id'],row['id'])).fetchall()
        if len(rows)>4096:
            raise EvidenceError('evidence_custody_limit')
        previous = ZERO_HASH
        for sequence,event in enumerate(rows,1):
            expected = custody_hash(row['organization_id'],row['id'],sequence,event['actor_id'],event['event'],previous,event['created_at'])
            if event['sequence']!=sequence or event['previous_hash']!=previous or event['event_hash']!=expected:
                raise EvidenceError('evidence_custody_invalid')
            previous = expected
        if not rows or rows[0]['event']!='acquisition_intent' or rows[0]['event_hash']!=row['acquisition_hash']:
            raise EvidenceError('evidence_custody_missing')
        if row['state']=='ready' and not any(event['event']=='acquired' for event in rows):
            raise EvidenceError('evidence_acquisition_missing')
        return rows

    def _custody(self,conn,principal,row,event):
        chain = self._chain(conn,row)
        if len(chain)>=4096:
            raise EvidenceError('evidence_custody_limit')
        sequence,previous = len(chain)+1,chain[-1]['event_hash']
        created = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        event_hash = custody_hash(principal.organization_id,row['id'],sequence,principal.user_id,event,previous,created)
        conn.execute('''INSERT INTO gabriel_identity.custody_events
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
            (principal.organization_id,row['id'],sequence,principal.user_id,event,previous,event_hash,created))

    def _disposition(self,conn,row):
        # Historical migration tests and older readable snapshots may predate disposition tables.
        if conn.execute("SELECT to_regclass('gabriel_identity.purge_attempts') AS t").fetchone()['t'] is None:
            return None
        return conn.execute("SELECT * FROM gabriel_identity.purge_attempts WHERE organization_id=%s AND evidence_id=%s AND state IN ('prepared','completed')",
            (row['organization_id'],row['id'])).fetchone()

    def _verify(self,conn,row,*,ready=True,allow_disposition=False):
        admit_epoch(conn,row['organization_id'],self.store.keys)
        disposition = self._disposition(conn,row)
        if disposition and not allow_disposition:
            raise EvidenceError('evidence_purged' if disposition['state']=='completed' else 'evidence_disposition_pending')
        chain = self._chain(conn,row)
        if ready and row['state']!='ready':
            raise EvidenceError('evidence_not_ready')
        aad = object_aad(row)
        return verified_read(self.store,conn,storage_row(conn,row,aad),aad)

    def create_case(self,token,title):
        if not isinstance(title,str) or not 1<=len(title.strip())<=160 or any(ord(c)<32 or ord(c)==127 for c in title):
            raise InvalidIdentityInput('invalid_case_title')
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,write=True)
            count = conn.execute("SELECT count(*) AS n FROM gabriel_identity.cases WHERE organization_id=%s AND state='open'",
                (principal.organization_id,)).fetchone()['n']
            if count>=100:
                raise AccessDenied('open_case_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.cases (organization_id,id,title,created_by)
                VALUES (%s,%s,%s,%s) RETURNING *''',(principal.organization_id,uuid4(),title.strip(),principal.user_id)).fetchone()
            _audit(conn,'case.created',principal,row['id'])
            return row

    def list_cases(self,token):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token)
            return conn.execute('SELECT * FROM gabriel_identity.cases WHERE organization_id=%s ORDER BY created_at DESC,id LIMIT 100',
                (principal.organization_id,)).fetchall()

    def case_report(self,token,case_id):
        from gabriel.identity.reports import case_report
        return case_report(self,token,case_id)

    def case_graph(self,token,case_id):
        from gabriel.identity.case_graph import case_graph
        return case_graph(self,token,case_id)

    def get_case(self,token,case_id):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token)
            case = self._case(conn,principal,case_id)
            rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s ORDER BY observed_at,id',
                (principal.organization_id,case['id'])).fetchall()
            tasks = conn.execute('SELECT task_id FROM gabriel_identity.case_tasks WHERE organization_id=%s AND case_id=%s ORDER BY task_id',
                (principal.organization_id,case['id'])).fetchall()
            entries = []
            for row in rows:
                item = metadata(row)
                disposition = self._disposition(conn,row)
                if disposition:
                    item['storage_state'] = 'purged' if disposition['state']=='completed' else 'disposition_pending'
                entries.append(item)
            return {'case':case,'evidence':entries,'task_ids':[row['task_id'] for row in tasks]}

    def link_task(self,token,case_id,task_id):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,write=True)
            case = self._case(conn,principal,case_id,open_only=True)
            task = task_record(conn,principal.organization_id,task_id)
            row = conn.execute('''INSERT INTO gabriel_identity.case_tasks VALUES (%s,%s,%s)
                ON CONFLICT DO NOTHING RETURNING task_id''',(principal.organization_id,case['id'],task['id'])).fetchone()
            if row:
                _audit(conn,'case.task_linked',principal,case['id'])

    def acquire(self,token,case_id,ingestion_id,content,source_label,*,approved=False,event_time=None,
                redaction_state='not_redacted',parent_id=None,_model_generated=False):
        if type(_model_generated) is not bool: raise InvalidIdentityInput('invalid_evidence_origin')
        if approved is not True:
            raise AccessDenied('evidence_approval_required')
        try:
            data = content.encode('utf-8') if isinstance(content,str) else b''
        except UnicodeError:
            raise InvalidIdentityInput('invalid_evidence_content') from None
        if not 1<=len(data)<=MAX_BYTES:
            raise InvalidIdentityInput('invalid_evidence_content')
        if not isinstance(source_label,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9 ._:/-]{0,127}',source_label):
            raise InvalidIdentityInput('invalid_source_label')
        if not isinstance(redaction_state,str) or redaction_state not in {'not_redacted','user_declared_redacted'}:
            raise InvalidIdentityInput('invalid_redaction_state')
        ingestion_id,event_time = identifier(ingestion_id),timestamp(event_time)
        parent_id = identifier(parent_id) if parent_id is not None else None
        digest = sha256(data).hexdigest()
        intake_fields=[digest,len(data),source_label,iso(event_time),redaction_state,str(parent_id) if parent_id else None]
        if _model_generated: intake_fields.append('model-generated-json-v1')
        intake_digest = sha256(canonical(intake_fields)).hexdigest()
        # This durable intent precedes object creation; interrupted writes stay visible.
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,write=True)
            case = self._case(conn,principal,case_id)
            if _model_generated and not conn.execute('''SELECT 1 FROM gabriel_identity.model_answer_intents
                WHERE organization_id=%s AND case_id=%s AND ingestion_id=%s AND created_by=%s AND normalized_evidence_id=%s''',
                (principal.organization_id,case['id'],ingestion_id,principal.user_id,parent_id)).fetchone():
                raise AccessDenied('model_answer_intent_required')
            row = conn.execute('''SELECT * FROM gabriel_identity.evidence_objects
                WHERE organization_id=%s AND case_id=%s AND ingestion_id=%s FOR UPDATE''',
                (principal.organization_id,case['id'],ingestion_id)).fetchone()
            if row:
                if self._disposition(conn,row):
                    raise AccessDenied('evidence_content_unavailable')
                if row['intake_digest']!=intake_digest:
                    raise AccessDenied('evidence_intake_conflict')
            else:
                if case['state']!='open':
                    raise AccessDenied('case_not_open')
                count = conn.execute('SELECT count(*) AS n FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s',
                    (principal.organization_id,case['id'])).fetchone()['n']
                if count>=64:
                    raise AccessDenied('case_evidence_limit')
                if parent_id:
                    parent = self._evidence(conn,principal,parent_id)
                    if parent['case_id']!=case['id']:
                        raise AccessDenied('parent_evidence_not_accessible')
                key_id = self.store.keys.active
                fingerprint = sha256(self.store.keys._key(key_id)).hexdigest()
                conn.execute('INSERT INTO gabriel_identity.evidence_key_registry VALUES (%s,%s) ON CONFLICT (key_id) DO NOTHING',(key_id,fingerprint))
                actual = conn.execute('SELECT fingerprint FROM gabriel_identity.evidence_key_registry WHERE key_id=%s',(key_id,)).fetchone()['fingerprint']
                if actual!=fingerprint:
                    raise EvidenceError('evidence_key_identity_mismatch')
                if available(conn) and not epoch(conn,principal.organization_id):
                    conn.execute('''INSERT INTO gabriel_identity.evidence_key_epochs
                        (organization_id,generation,active_key_id,created_by) VALUES (%s,%s,%s,%s)''',
                        (principal.organization_id,self.store.keys.generation,key_id,principal.user_id))
                admit_epoch(conn,principal.organization_id,self.store.keys)
                observed = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
                evidence_id = uuid4()
                acquisition_hash = custody_hash(principal.organization_id,evidence_id,1,principal.user_id,'acquisition_intent',ZERO_HASH,observed)
                row = conn.execute('''INSERT INTO gabriel_identity.evidence_objects
                    (organization_id,id,case_id,ingestion_id,intake_digest,object_id,acquired_by,digest,byte_length,key_id,
                     source_kind,source_label,source_event_time,observed_at,schema_version,parser_version,redaction_state,parent_id,acquisition_hash)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s) RETURNING *''',
                    (principal.organization_id,evidence_id,case['id'],ingestion_id,intake_digest,uuid4(),principal.user_id,
                     digest,len(data),key_id,'model_generated_text' if _model_generated else 'user_supplied_text',
                     source_label,event_time,observed,'model-json-v1' if _model_generated else 'supplied-utf8-v1',
                     redaction_state,parent_id,acquisition_hash)).fetchone()
                conn.execute('INSERT INTO gabriel_identity.custody_events VALUES (%s,%s,1,%s,%s,%s,%s,%s)',
                    (principal.organization_id,evidence_id,principal.user_id,'acquisition_intent',ZERO_HASH,acquisition_hash,observed))
                _audit(conn,'evidence.acquisition_started',principal,evidence_id)
        try:
            return self._finish_acquisition(token,row['id'],data)
        except EvidenceError as exc:
            self._quarantine(token,row['id'],str(exc))
            raise

    def _finish_acquisition(self,token,evidence_id,data):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,write=True)
            row = self._evidence(conn,principal,evidence_id)
            self._case(conn,principal,row['case_id'],open_only=row['state']!='ready')
            # Serialize retries under the tenant lock after the durable intent commits.
            if row['state']!='ready':
                self.store.write(row,data,object_aad(row))
            self._verify(conn,row,ready=False)
            if row['state']!='ready':
                acquired = any(event['event']=='acquired' for event in self._chain(conn,row))
                self._custody(conn,principal,row,'recovered' if acquired else 'acquired')
                conn.execute("UPDATE gabriel_identity.evidence_objects SET state='ready',failure_code=NULL WHERE organization_id=%s AND id=%s",(principal.organization_id,row['id']))
                _audit(conn,'evidence.acquisition_completed',principal,row['id'])
                row['state'],row['failure_code'] = 'ready',None
            else:
                _audit(conn,'evidence.acquisition_replayed',principal,row['id'])
            return metadata(row)

    def _quarantine(self,token,evidence_id,code):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,write=True)
            row = self._evidence(conn,principal,evidence_id)
            # A damaged chain must not be rewritten just to record the failure.
            try:
                self._custody(conn,principal,row,'quarantined')
            except EvidenceError:
                pass
            conn.execute("UPDATE gabriel_identity.evidence_objects SET state='quarantined',failure_code=%s WHERE organization_id=%s AND id=%s",
                (code,principal.organization_id,row['id']))
            _audit(conn,'evidence.quarantined',principal,row['id'])

    def read_evidence(self,token,evidence_id):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,content=True)
            row = self._evidence(conn,principal,evidence_id)
            value = self._verify(conn,row)
            self._custody(conn,principal,row,'accessed')
            _audit(conn,'evidence.accessed',principal,row['id'])
            result = EvidenceContent(metadata(row),value)
        return result

    def custody(self,token,evidence_id):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token)
            return self._chain(conn,self._evidence(conn,principal,evidence_id))

    def _findings(self,conn,principal,case_id):
        rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s ORDER BY observed_at,id',
            (principal.organization_id,case_id)).fetchall()
        findings = []
        for row in rows:
            code = 'verified'
            try:
                self._verify(conn,row)
            except EvidenceError as exc:
                code = str(exc)
            findings.append({'evidence_id':str(row['id']),'state':row['state'],'integrity':code,'source_verified':False})
        return findings

    def verify_case(self,token,case_id):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token)
            case = self._case(conn,principal,case_id)
            findings = self._findings(conn,principal,case['id'])
            _audit(conn,'case.integrity_checked',principal,case['id'])
            return {'case_id':str(case['id']),'evidence':findings,'complete':bool(findings) and all(f['integrity']=='verified' for f in findings)}

    def close_case(self,token,case_id,*,approval_id=None,checkpoint_digest=None):
        blocked = False
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,write=True)
            case = self._case(conn,principal,case_id)
            findings = self._findings(conn,principal,case['id'])
            if not findings or any(f['integrity']!='verified' for f in findings):
                _audit(conn,'case.closure_blocked',principal,case['id'])
                blocked = True
            else:
                if approval_id is None:
                    raise AccessDenied('case_closure_approval_required')
                from gabriel.identity.actions import ActionService
                return ActionService(self._dsn,self.store)._execute_close(conn,principal,case,approval_id,token,checkpoint_digest=checkpoint_digest)
        if blocked:
            raise EvidenceError('case_evidence_integrity_failed')

    def prepare_export(self,token,evidence_id):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,content=True)
            row = self._evidence(conn,principal,evidence_id)
            value = self._verify(conn,row)
            export_id = uuid4()
            conn.execute('''INSERT INTO gabriel_identity.evidence_exports
                (organization_id,id,evidence_id,prepared_by,digest) VALUES (%s,%s,%s,%s,%s)''',
                (principal.organization_id,export_id,row['id'],principal.user_id,row['digest']))
            self._custody(conn,principal,row,'export_prepared')
            _audit(conn,'evidence.export_prepared',principal,row['id'])
            result = EvidenceContent(metadata(row),value,export_id)
        return result

    def finish_export(self,token,export_id,*,completed,written_digest=None):
        if type(completed) is not bool:
            raise InvalidIdentityInput('invalid_export_result')
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,content=True)
            row = conn.execute('''SELECT * FROM gabriel_identity.evidence_exports
                WHERE organization_id=%s AND id=%s FOR UPDATE''',(principal.organization_id,identifier(export_id))).fetchone()
            if not row or row['prepared_by']!=principal.user_id:
                raise AccessDenied('export_not_accessible')
            if completed and written_digest!=row['digest']:
                raise EvidenceError('export_digest_mismatch')
            state = 'completed' if completed else 'file_write_failed'
            if row['state']==state:
                return
            if row['state']!='prepared':
                raise AccessDenied('export_already_finalized')
            evidence = self._evidence(conn,principal,row['evidence_id'])
            self._custody(conn,principal,evidence,'export_completed' if completed else 'export_failed')
            conn.execute('UPDATE gabriel_identity.evidence_exports SET state=%s WHERE organization_id=%s AND id=%s',
                (state,principal.organization_id,row['id']))
            _audit(conn,'evidence.export_'+state,principal,evidence['id'])

    def list_exports(self,token):
        with connection(self._dsn) as conn:
            principal = self._human(conn,token,content=True)
            return conn.execute('SELECT * FROM gabriel_identity.evidence_exports WHERE organization_id=%s ORDER BY created_at DESC,id LIMIT 100',
                (principal.organization_id,)).fetchall()
