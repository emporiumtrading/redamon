"""Immutable tenant trust receipts and database-clock freshness for local closure."""
from datetime import timedelta
from uuid import uuid4

from gabriel.identity.checkpoints import CheckpointError,canonical,fingerprint,public_fingerprint,verify
from gabriel.identity.checkpoint_service import CheckpointService,compare_checkpoint
from gabriel.identity.cases import iso
from gabriel.identity.retention import reason
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection


def current_policy(conn,p,*,required=True):
    if conn.execute("SELECT to_regclass('gabriel_identity.checkpoint_policies') AS t").fetchone()['t'] is None:
        row = None
    else:
        row = conn.execute('SELECT * FROM gabriel_identity.checkpoint_policies WHERE organization_id=%s ORDER BY revision DESC LIMIT 1',
            (p.organization_id,)).fetchone()
    if not row and required:
        raise AccessDenied('checkpoint_policy_required')
    return row


def active_key(conn,p,pin):
    row = conn.execute('''SELECT k.* FROM gabriel_identity.checkpoint_keys k
        WHERE k.organization_id=%s AND k.fingerprint=%s AND NOT EXISTS (
            SELECT 1 FROM gabriel_identity.checkpoint_key_revocations r
            WHERE (r.organization_id,r.fingerprint)=(k.organization_id,k.fingerprint))''',
        (p.organization_id,pin)).fetchone()
    try:
        if not row or public_fingerprint(row['public_document'])!=pin:
            raise ValueError
    except (CheckpointError,ValueError):
        raise AccessDenied('checkpoint_key_untrusted_or_revoked') from None
    return row


def capture_record(conn,p,case,snapshot):
    row = conn.execute('''SELECT * FROM gabriel_identity.checkpoint_captures
        WHERE organization_id=%s AND case_id=%s AND nonce=%s''',
        (p.organization_id,case['id'],snapshot['nonce'])).fetchone()
    if (not row or row['snapshot_digest']!=fingerprint(canonical(snapshot))
            or iso(row['captured_at'])!=snapshot['captured_at']):
        raise AccessDenied('checkpoint_capture_not_registered')
    return row


def fresh(conn,capture,policy):
    now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
    expires = capture['captured_at']+timedelta(seconds=policy['max_age_seconds'])
    if capture['captured_at']>now or expires<=now:
        raise AccessDenied('checkpoint_not_fresh')
    return expires


def receipt_metadata(row):
    return {k:v for k,v in row.items() if k not in {'envelope','captured_at'}}


def validate_current(service,conn,p,case,expected_digest):
    policy = current_policy(conn,p)
    key = active_key(conn,p,policy['fingerprint'])
    row = conn.execute('SELECT * FROM gabriel_identity.checkpoint_receipts WHERE organization_id=%s AND case_id=%s ORDER BY revision DESC LIMIT 1',
        (p.organization_id,case['id'])).fetchone()
    if not row or row['digest']!=expected_digest or row['policy_revision']!=policy['revision']:
        raise AccessDenied('checkpoint_current_receipt_required')
    try:
        snapshot = verify(row['envelope'],key['public_document'],expected_digest)
    except CheckpointError:
        raise EvidenceError('checkpoint_trust_validation_failed') from None
    capture = capture_record(conn,p,case,snapshot)
    if str(row['nonce'])!=snapshot['nonce']:
        raise AccessDenied('checkpoint_receipt_binding_invalid')
    compare_checkpoint(service,conn,p,case,snapshot,require_all=True)
    expires = fresh(conn,capture,policy)
    return row,expires


def admit_close(service,conn,p,case,expected_digest):
    if not current_policy(conn,p,required=False):
        return
    receipt,_ = validate_current(service,conn,p,case,expected_digest)
    conn.execute("SELECT set_config('gabriel.checkpoint_receipt',%s,true)",(str(receipt['id']),))
    conn.execute("SELECT set_config('gabriel.checkpoint_digest',%s,true)",(receipt['digest'],))
    _audit(conn,'checkpoint.closure_admitted',p,case['id'])


class CheckpointPolicyService(CheckpointService):
    def trust_checkpoint_key(self,token,document,expected_fingerprint):
        try:
            pin = public_fingerprint(document)
            if pin!=expected_fingerprint:
                raise ValueError
        except (CheckpointError,ValueError,TypeError):
            raise InvalidIdentityInput('checkpoint_key_pin_mismatch') from None
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            old = conn.execute('SELECT * FROM gabriel_identity.checkpoint_keys WHERE organization_id=%s AND fingerprint=%s',
                (p.organization_id,pin)).fetchone()
            if old:
                active_key(conn,p,pin)
                _audit(conn,'checkpoint.key_replayed',p)
                return old
            if conn.execute('SELECT count(*) AS n FROM gabriel_identity.checkpoint_keys WHERE organization_id=%s',
                    (p.organization_id,)).fetchone()['n']>=128:
                raise AccessDenied('checkpoint_key_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.checkpoint_keys
                (organization_id,fingerprint,public_document,created_by) VALUES (%s,%s,%s::jsonb,%s) RETURNING *''',
                (p.organization_id,pin,canonical(document).decode(),p.user_id)).fetchone()
            _audit(conn,'checkpoint.key_trusted',p)
            return row

    def revoke_checkpoint_key(self,token,pin,rationale):
        rationale = reason(rationale)
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            active_key(conn,p,pin)
            conn.execute('INSERT INTO gabriel_identity.checkpoint_key_revocations (organization_id,fingerprint,revoked_by,reason) VALUES (%s,%s,%s,%s)',
                (p.organization_id,pin,p.user_id,rationale))
            _audit(conn,'checkpoint.key_revoked',p)

    def set_checkpoint_policy(self,token,pin,max_age_seconds):
        if type(max_age_seconds) is not int or not 60<=max_age_seconds<=86400:
            raise InvalidIdentityInput('invalid_checkpoint_max_age')
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            active_key(conn,p,pin)
            revision = conn.execute('SELECT COALESCE(max(revision),0)+1 AS n FROM gabriel_identity.checkpoint_policies WHERE organization_id=%s',
                (p.organization_id,)).fetchone()['n']
            if revision>1024:
                raise AccessDenied('checkpoint_policy_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.checkpoint_policies
                (organization_id,revision,fingerprint,max_age_seconds,created_by) VALUES (%s,%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,revision,pin,max_age_seconds,p.user_id)).fetchone()
            _audit(conn,'checkpoint.policy_changed',p)
            return row

    def get_checkpoint_policy(self,token):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            return current_policy(conn,p)

    def accept_checkpoint(self,token,case_id,envelope,expected_digest):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            case = self._case(conn,p,case_id)
            policy = current_policy(conn,p)
            key = active_key(conn,p,policy['fingerprint'])
            try:
                snapshot = verify(envelope,key['public_document'],expected_digest)
            except CheckpointError:
                raise EvidenceError('checkpoint_trust_validation_failed') from None
            compare_checkpoint(self,conn,p,case,snapshot,require_all=True)
            capture = capture_record(conn,p,case,snapshot)
            fresh(conn,capture,policy)
            self._principal(conn,token,lock=True)
            fresh(conn,capture,policy)
            old = conn.execute('''SELECT r.*,c.captured_at FROM gabriel_identity.checkpoint_receipts r
                JOIN gabriel_identity.checkpoint_captures c USING (organization_id,case_id,nonce)
                WHERE r.organization_id=%s AND r.case_id=%s ORDER BY revision DESC LIMIT 1''',
                (p.organization_id,case['id'])).fetchone()
            if old and old['digest']==expected_digest:
                if old['policy_revision']!=policy['revision']:
                    raise AccessDenied('checkpoint_receipt_context_changed')
                _audit(conn,'checkpoint.acceptance_replayed',p,case['id'])
                return receipt_metadata(old)
            if old and capture['captured_at']<=old['captured_at']:
                raise AccessDenied('checkpoint_capture_not_newer')
            revision = old['revision']+1 if old else 1
            if revision>4096:
                raise AccessDenied('checkpoint_receipt_limit')
            self._principal(conn,token,lock=True)
            fresh(conn,capture,policy)
            row = conn.execute('''INSERT INTO gabriel_identity.checkpoint_receipts
                (organization_id,id,case_id,revision,nonce,policy_revision,digest,envelope,accepted_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) RETURNING *''',
                (p.organization_id,uuid4(),case['id'],revision,snapshot['nonce'],policy['revision'],expected_digest,
                 canonical(envelope).decode(),p.user_id)).fetchone()
            _audit(conn,'checkpoint.accepted',p,case['id'])
            return receipt_metadata(row)

    def check_checkpoint_policy(self,token,case_id,expected_digest):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            case = self._case(conn,p,case_id)
            row,expires = validate_current(self,conn,p,case,expected_digest)
            self._principal(conn,token,lock=True)
            _audit(conn,'checkpoint.policy_checked',p,case['id'])
            return {'case_id':str(case['id']),'receipt_id':str(row['id']),'digest':row['digest'],
                'policy_revision':row['policy_revision'],'fresh_until':iso(expires),'full_current_evidence_coverage':True,
                'source_authenticity':'unverified','content_integrity':'not_checked','governance_history':'not_covered'}
