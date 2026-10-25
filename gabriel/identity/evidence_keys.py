"""Tenant key rollover with durable intent, authenticated replacement and observation-only recovery."""
from hashlib import sha256
from uuid import uuid4

from gabriel.identity.checkpoint_policy import CheckpointPolicyService
from gabriel.identity.cases import object_aad
from gabriel.identity.evidence_crypto import admit_epoch,epoch,register_key,storage_row,verified_read
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,_audit,connection,identifier


class EvidenceKeyService(CheckpointPolicyService):
    def activate_evidence_key(self,token):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            current = epoch(conn,p.organization_id)
            if current:
                if self.store.keys.generation==current['generation'] and self.store.keys.active==current['active_key_id']:
                    register_key(conn,self.store.keys,self.store.keys.active)
                    _audit(conn,'evidence.key_activation_replayed',p)
                    return current
                if self.store.keys.generation!=current['generation']+1 or self.store.keys.active==current['active_key_id']:
                    raise AccessDenied('evidence_key_epoch_not_next')
            if conn.execute('SELECT 1 FROM gabriel_identity.evidence_key_epochs WHERE organization_id=%s AND active_key_id=%s',
                    (p.organization_id,self.store.keys.active)).fetchone():
                raise AccessDenied('evidence_key_reactivation_denied')
            if conn.execute("SELECT 1 FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND state='prepared' LIMIT 1",
                    (p.organization_id,)).fetchone():
                raise AccessDenied('evidence_rewrap_unresolved')
            rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s ORDER BY id LIMIT 4097',
                (p.organization_id,)).fetchall()
            if len(rows)>4096:
                raise AccessDenied('evidence_rollover_limit')
            for row in rows:
                disposition = self._disposition(conn,row)
                if disposition and disposition['state']=='completed':
                    continue
                if row['state']!='ready' or disposition:
                    raise AccessDenied('evidence_storage_unresolved')
                self._chain(conn,row)
                aad = object_aad(row)
                verified_read(self.store,conn,storage_row(conn,row,aad),aad)
            register_key(conn,self.store.keys,self.store.keys.active)
            self._principal(conn,token,lock=True)
            result = conn.execute('''INSERT INTO gabriel_identity.evidence_key_epochs
                (organization_id,generation,active_key_id,created_by) VALUES (%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,self.store.keys.generation,self.store.keys.active,p.user_id)).fetchone()
            _audit(conn,'evidence.key_activated',p)
            return result

    def prepare_rewrap(self,token,evidence_id):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            current = admit_epoch(conn,p.organization_id,self.store.keys)
            if not current:
                raise AccessDenied('evidence_key_epoch_required')
            row = self._evidence(conn,p,evidence_id)
            existing = conn.execute("SELECT * FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND evidence_id=%s AND state='prepared'",
                (p.organization_id,row['id'])).fetchone()
            if existing:
                _audit(conn,'evidence.rewrap_prepare_replayed',p,row['id'])
                return existing
            self._verify(conn,row)
            aad = object_aad(row)
            source = storage_row(conn,row,aad)['key_id']
            if source==self.store.keys.active:
                return {'evidence_id':str(row['id']),'state':'already_current','key_id':source}
            sequence = conn.execute('SELECT COALESCE(max(sequence),0)+1 AS n FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND evidence_id=%s',
                (p.organization_id,row['id'])).fetchone()['n']
            if sequence>64:
                raise AccessDenied('evidence_rewrap_limit')
            self._principal(conn,token,lock=True)
            result = conn.execute('''INSERT INTO gabriel_identity.evidence_rewraps
                (organization_id,id,evidence_id,sequence,generation,source_key_id,target_key_id,context_digest,prepared_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,uuid4(),row['id'],sequence,current['generation'],source,self.store.keys.active,
                 sha256(aad).hexdigest(),p.user_id)).fetchone()
            _audit(conn,'evidence.rewrap_prepared',p,row['id'])
            return result

    def _rewrap(self,conn,p,attempt_id):
        attempt = conn.execute('SELECT * FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND id=%s FOR UPDATE',
            (p.organization_id,identifier(attempt_id))).fetchone()
        if not attempt:
            raise AccessDenied('evidence_rewrap_not_accessible')
        row = self._evidence(conn,p,attempt['evidence_id'])
        aad = object_aad(row)
        self._chain(conn,row)
        if sha256(aad).hexdigest()!=attempt['context_digest']:
            raise EvidenceError('evidence_encryption_context_changed')
        return attempt,row,aad

    def _finish_rewrap(self,conn,p,attempt,outcome):
        conn.execute('INSERT INTO gabriel_identity.evidence_rewrap_results (organization_id,attempt_id,actor_id,outcome) VALUES (%s,%s,%s,%s)',
            (p.organization_id,attempt['id'],p.user_id,outcome))
        conn.execute('UPDATE gabriel_identity.evidence_rewraps SET state=%s WHERE organization_id=%s AND id=%s',
            (outcome,p.organization_id,attempt['id']))
        _audit(conn,'evidence.rewrap_'+outcome,p,attempt['evidence_id'])
        return {'attempt_id':str(attempt['id']),'evidence_id':str(attempt['evidence_id']),'state':outcome}

    def execute_rewrap(self,token,attempt_id):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            current = admit_epoch(conn,p.organization_id,self.store.keys)
            attempt,row,aad = self._rewrap(conn,p,attempt_id)
            if (attempt['state']!='prepared' or not current or attempt['generation']!=current['generation']
                    or attempt['target_key_id']!=current['active_key_id']):
                raise AccessDenied('evidence_rewrap_not_executable')
            if self._disposition(conn,row):
                raise AccessDenied('evidence_disposition_exists')
            source = storage_row(conn,row,aad,allow_prepared=True)
            if source['key_id']!=attempt['source_key_id']:
                raise EvidenceError('evidence_rewrap_source_changed')
            verified_read(self.store,conn,source,aad)
            def admit():
                self._principal(conn,token,lock=True)
                admit_epoch(conn,p.organization_id,self.store.keys)
                _audit(conn,'evidence.rewrap_replace_admitted',p,row['id'])
            self.store.replace_encryption(source,aad,attempt['target_key_id'],admit=admit)
            verified_read(self.store,conn,dict(row,key_id=attempt['target_key_id']),aad)
            return self._finish_rewrap(conn,p,attempt,'completed')

    def reconcile_rewrap(self,token,attempt_id):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            admit_epoch(conn,p.organization_id,self.store.keys)
            attempt,row,aad = self._rewrap(conn,p,attempt_id)
            if attempt['state']!='prepared':
                result = conn.execute('SELECT * FROM gabriel_identity.evidence_rewrap_results WHERE organization_id=%s AND attempt_id=%s',
                    (p.organization_id,attempt['id'])).fetchone()
                if not result or result['outcome']!=attempt['state']:
                    raise EvidenceError('evidence_rewrap_receipt_invalid')
                physical = storage_row(conn,row,aad)
                verified_read(self.store,conn,physical,aad)
                _audit(conn,'evidence.rewrap_rechecked',p,row['id'])
                return {'attempt_id':str(attempt['id']),'state':attempt['state']}
            target = dict(row,key_id=attempt['target_key_id'])
            try:
                verified_read(self.store,conn,target,aad)
            except EvidenceError:
                source = dict(row,key_id=attempt['source_key_id'])
                verified_read(self.store,conn,source,aad)
                outcome = 'aborted'
            else:
                outcome = 'completed'
            self.store.sync()
            self._principal(conn,token,lock=True)
            return self._finish_rewrap(conn,p,attempt,outcome)

    def get_rewrap(self,token,attempt_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            attempt,_,_ = self._rewrap(conn,p,attempt_id)
            return attempt

    def key_retirement_check(self,token,key_id):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            admit_epoch(conn,p.organization_id,self.store.keys)
            current = epoch(conn,p.organization_id)
            rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s LIMIT 4097',(p.organization_id,)).fetchall()
            if len(rows)>4096:
                raise AccessDenied('evidence_retirement_scope_limit')
            references = 0
            for row in rows:
                disposition = self._disposition(conn,row)
                if disposition and disposition['state']=='completed':
                    continue
                if storage_row(conn,row,object_aad(row),allow_prepared=True)['key_id']==key_id:
                    references += 1
            prepared = conn.execute("SELECT count(*) AS n FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND state='prepared' AND (source_key_id=%s OR target_key_id=%s)",
                (p.organization_id,key_id,key_id)).fetchone()['n']
            known = conn.execute('SELECT 1 FROM gabriel_identity.evidence_key_registry WHERE key_id=%s',(key_id,)).fetchone() is not None
            active = bool(current and current['active_key_id']==key_id)
            _audit(conn,'evidence.key_retirement_checked',p)
            return {'key_id':key_id,'scope':'tenant_live_database','known_key':known,'live_references':references,
                'prepared_attempts':prepared,'active_key':active,'tenant_live_ready':known and not(active or references or prepared),
                'physical_key_deletion_authorized':False,'other_tenants_and_backups':'not_verified'}
