"""Compare trusted independent checkpoints with current tenant custody prefixes."""
from hashlib import sha256
from uuid import uuid4

from gabriel.identity.checkpoints import (CheckpointError,PURPOSE,canonical,fingerprint,validate_snapshot,verify)
from gabriel.identity.cases import object_aad,iso
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.retention import RetentionService
from gabriel.identity.service import AccessDenied,_audit,connection


def case_digest(row):
    return fingerprint(canonical([str(row['organization_id']),str(row['id']),row['title'],str(row['created_by']),iso(row['created_at'])]))


def compare_checkpoint(service,conn,p,case,snapshot,*,require_all=False):
    if snapshot['organization_id']!=str(p.organization_id) or snapshot['case_id']!=str(case['id']):
        raise AccessDenied('checkpoint_scope_mismatch')
    if snapshot['case_digest']!=case_digest(case):
        raise EvidenceError('checkpoint_case_changed')
    if require_all:
        current = conn.execute('SELECT id FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s ORDER BY id',
            (p.organization_id,case['id'])).fetchall()
        if [str(r['id']) for r in current]!=[b['evidence_id'] for b in snapshot['evidence']]:
            raise EvidenceError('checkpoint_coverage_incomplete')
    for bound in snapshot['evidence']:
        row = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s AND id=%s',
            (p.organization_id,case['id'],bound['evidence_id'])).fetchone()
        if not row:
            raise EvidenceError('checkpoint_evidence_missing')
        if sha256(object_aad(row)).hexdigest()!=bound['context_digest']:
            raise EvidenceError('checkpoint_context_changed')
        chain = service._chain(conn,row)
        if len(chain)<bound['sequence'] or chain[bound['sequence']-1]['event_hash']!=bound['head']:
            raise EvidenceError('checkpoint_custody_changed')


class CheckpointService(RetentionService):
    def capture_checkpoint(self,token,case_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            case = self._case(conn,p,case_id)
            rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s ORDER BY id LIMIT 65',
                (p.organization_id,case['id'])).fetchall()
            if len(rows)>64:
                raise EvidenceError('checkpoint_case_limit')
            entries = []
            for row in rows:
                chain = self._chain(conn,row)
                entries.append({'evidence_id':str(row['id']),'context_digest':sha256(object_aad(row)).hexdigest(),
                    'sequence':chain[-1]['sequence'],'head':chain[-1]['event_hash']})
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            snapshot = {'schema_version':1,'purpose':PURPOSE,'organization_id':str(p.organization_id),'case_id':str(case['id']),
                'case_digest':case_digest(case),'captured_at':iso(now),'nonce':str(uuid4()),'evidence':entries}
            validate_snapshot(snapshot)
            count = conn.execute('SELECT count(*) AS n FROM gabriel_identity.checkpoint_captures WHERE organization_id=%s AND case_id=%s',
                (p.organization_id,case['id'])).fetchone()['n']
            if count>=4096:
                raise AccessDenied('checkpoint_capture_limit')
            conn.execute('''INSERT INTO gabriel_identity.checkpoint_captures
                (organization_id,case_id,nonce,snapshot_digest,captured_at,created_by) VALUES (%s,%s,%s,%s,%s,%s)''',
                (p.organization_id,case['id'],snapshot['nonce'],fingerprint(canonical(snapshot)),now,p.user_id))
            self._principal(conn,token,lock=True)
            _audit(conn,'checkpoint.captured',p,case['id'])
            return snapshot

    def verify_checkpoint(self,token,case_id,envelope,public_key,expected_digest):
        try:
            snapshot = verify(envelope,public_key,expected_digest)
        except CheckpointError:
            raise EvidenceError('checkpoint_trust_validation_failed') from None
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            case = self._case(conn,p,case_id)
            compare_checkpoint(self,conn,p,case,snapshot)
            self._principal(conn,token,lock=True)
            _audit(conn,'checkpoint.verified',p,case['id'])
            return {'checkpoint_digest':expected_digest,'case_id':str(case['id']),
                'anchored_evidence_count':len(snapshot['evidence']),'custody_prefixes_match':True,
                'captured_at':snapshot['captured_at'],'source_authenticity':'unverified',
                'content_integrity':'not_checked','new_evidence':'not_covered','governance_history':'not_covered'}
