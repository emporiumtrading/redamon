"""Resolve encryption bindings without changing immutable evidence metadata or custody."""
from hashlib import sha256

from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,IdentityError


def available(conn):
    return conn.execute("SELECT to_regclass('gabriel_identity.evidence_key_epochs') AS t").fetchone()['t'] is not None


def epoch(conn,org):
    if not available(conn):
        return None
    return conn.execute('SELECT * FROM gabriel_identity.evidence_key_epochs WHERE organization_id=%s ORDER BY generation DESC LIMIT 1',
        (org,)).fetchone()


def admit_epoch(conn,org,keys):
    current = epoch(conn,org)
    if current:
        if current['generation']!=keys.generation or current['active_key_id']!=keys.active:
            raise EvidenceError('evidence_key_configuration_stale')
        conn.execute("SELECT set_config('gabriel.evidence_generation',%s,true)",(str(current['generation']),))
    return current


def register_key(conn,keys,key_id):
    value = sha256(keys._key(key_id)).hexdigest()
    conn.execute('INSERT INTO gabriel_identity.evidence_key_registry VALUES (%s,%s) ON CONFLICT (key_id) DO NOTHING',(key_id,value))
    actual = conn.execute('SELECT fingerprint FROM gabriel_identity.evidence_key_registry WHERE key_id=%s',(key_id,)).fetchone()
    if not actual or actual['fingerprint']!=value:
        raise EvidenceError('evidence_key_identity_mismatch')


def storage_row(conn,row,aad,*,allow_prepared=False):
    if not available(conn):
        return row
    if not allow_prepared and conn.execute("SELECT 1 FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND evidence_id=%s AND state='prepared'",
            (row['organization_id'],row['id'])).fetchone():
        raise EvidenceError('evidence_rewrap_pending')
    binding = conn.execute("SELECT * FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND evidence_id=%s AND state='completed' ORDER BY sequence DESC LIMIT 1",
        (row['organization_id'],row['id'])).fetchone()
    if binding:
        if binding['context_digest']!=sha256(aad).hexdigest():
            raise EvidenceError('evidence_encryption_context_changed')
        return dict(row,key_id=binding['target_key_id'])
    return row


def verified_read(store,conn,row,aad):
    try:
        key = store.keys._key(row['key_id'])
    except IdentityError:
        raise EvidenceError('evidence_key_unavailable') from None
    known = conn.execute('SELECT fingerprint FROM gabriel_identity.evidence_key_registry WHERE key_id=%s',(row['key_id'],)).fetchone()
    if not known or known['fingerprint']!=sha256(key).hexdigest():
        raise EvidenceError('evidence_key_identity_mismatch')
    return store.read(row,aad)
