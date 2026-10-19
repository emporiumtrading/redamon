"""Migration-operator live-reference report; never removes keys or certifies backup destruction."""
import argparse
import json
import os

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityError,InvalidIdentityInput,AccessDenied,connection
from gabriel.identity.vault import KEY_ID


def report(dsn,key_id):
    if not isinstance(key_id,str) or not KEY_ID.fullmatch(key_id):
        raise InvalidIdentityInput('invalid_evidence_key_id')
    with connection(dsn,runtime=False) as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        owner = conn.execute("SELECT pg_has_role(current_user,nspowner,'MEMBER') AS allowed FROM pg_namespace WHERE nspname='gabriel_identity'").fetchone()
        if not owner or not owner['allowed']:
            raise AccessDenied('migration_operator_required')
        known = conn.execute('SELECT 1 FROM gabriel_identity.evidence_key_registry WHERE key_id=%s',(key_id,)).fetchone() is not None
        refs = conn.execute('''SELECT count(*) AS n FROM gabriel_identity.evidence_objects e
            LEFT JOIN LATERAL (SELECT target_key_id FROM gabriel_identity.evidence_rewraps r
                WHERE r.organization_id=e.organization_id AND r.evidence_id=e.id AND r.state='completed'
                ORDER BY sequence DESC LIMIT 1) b ON true
            WHERE COALESCE(b.target_key_id,e.key_id)=%s AND NOT EXISTS (
                SELECT 1 FROM gabriel_identity.purge_attempts p WHERE p.organization_id=e.organization_id
                AND p.evidence_id=e.id AND p.state='completed')''',(key_id,)).fetchone()['n']
        active = conn.execute('''SELECT count(*) AS n FROM (
            SELECT DISTINCT ON (organization_id) active_key_id FROM gabriel_identity.evidence_key_epochs
            ORDER BY organization_id,generation DESC) s WHERE active_key_id=%s''',(key_id,)).fetchone()['n']
        pending = conn.execute("SELECT count(*) AS n FROM gabriel_identity.evidence_rewraps WHERE state='prepared' AND (source_key_id=%s OR target_key_id=%s)",
            (key_id,key_id)).fetchone()['n']
        return {'key_id':key_id,'scope':'all_tenants_live_database_snapshot','known_key':known,
            'live_references':refs,'active_tenants':active,'prepared_attempts':pending,
            'live_database_clear':known and not(refs or active or pending),
            'physical_key_deletion_authorized':False,'backup_and_export_inventory':'not_verified'}


def main():
    parser = argparse.ArgumentParser(description='Read-only global evidence-key retirement report')
    parser.add_argument('--key-id',required=True)
    args = parser.parse_args()
    try:
        result = report(read_secret(os.environ.get('GABRIEL_MIGRATION_DSN_FILE')),args.key_id)
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except (IdentityError,OSError,ValueError,TypeError):
        print(json.dumps({'status':'denied','code':'evidence_key_report_unavailable'}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
