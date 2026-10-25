"""Real encrypted files, epoch guards, interrupted replacement and retained backup keys."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import base64
import subprocess
import sys
import time
from pathlib import Path
import secrets
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.evidence_keys import EvidenceKeyService
from gabriel.identity.evidence_store import EvidenceError,EvidenceKeys,LocalEvidenceStore
from gabriel.identity.key_retirement import report
from gabriel.identity.cases import object_aad
from gabriel.identity.checkpoints import canonical,fingerprint,new_keypair,public_fingerprint,seal
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,migrate,provision_organization
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,row_and_file,audit_permission,CONTENT
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_retention_integration import retention,aged
from testing.gabriel_identity.db_history import remove_v10

pytestmark = pytest.mark.integration


def next_service(tenant,cases):
    ring = cases.store.keys
    target = 'k_'+uuid4().hex
    keys = EvidenceKeys(target,dict(ring._keys,**{target:secrets.token_bytes(32)}),ring.generation+1)
    return EvidenceKeyService(tenant.db.app,LocalEvidenceStore(cases.store.root,keys))


@pytest.fixture
def rollover(tenant,cases,evidence):
    service = next_service(tenant,cases)
    service.activate_evidence_key(tenant.token)
    return service


@pytest.fixture
def prepared(tenant,rollover,evidence):
    return rollover.prepare_rewrap(tenant.token,evidence['id'])


def test_rewrap_preserves_original_metadata_hashes_custody_and_checkpoint(tenant,cases,case,evidence,rollover,prepared):
    private,public = new_keypair()
    snapshot = rollover.capture_checkpoint(tenant.token,case['id'])
    envelope = seal(snapshot,private)
    expected = fingerprint(canonical(envelope))
    before = rollover.custody(tenant.token,evidence['id'])
    row,path = row_and_file(tenant,cases,evidence)
    old_bytes = path.read_bytes()
    with pytest.raises(EvidenceError,match='evidence_rewrap_pending'): rollover.read_evidence(tenant.token,evidence['id'])
    assert rollover.execute_rewrap(tenant.token,prepared['id'])['state']=='completed'
    assert path.read_bytes()!=old_bytes and rollover.custody(tenant.token,evidence['id'])==before
    assert rollover.verify_checkpoint(tenant.token,case['id'],envelope,public,expected)['custody_prefixes_match']
    assert rollover.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    with owner_connection(tenant.db) as conn:
        actual = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND id=%s',(tenant.org,evidence['id'])).fetchone()
    assert object_aad(actual)==object_aad(row)
    with pytest.raises(EvidenceError): cases.store.read(row,object_aad(row))
    assert rollover.prepare_rewrap(tenant.token,evidence['id'])['state']=='already_current'


def test_current_live_ring_can_drop_old_secret_after_verified_rewrap(tenant,cases,evidence,rollover,prepared):
    old = cases.store.keys.active
    assert not rollover.key_retirement_check(tenant.token,old)['tenant_live_ready']
    rollover.execute_rewrap(tenant.token,prepared['id'])
    active = rollover.store.keys.active
    ring = EvidenceKeys(active,{active:rollover.store.keys._key(active)},rollover.store.keys.generation)
    fresh = EvidenceKeyService(tenant.db.app,LocalEvidenceStore(cases.store.root,ring))
    assert fresh.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    result = fresh.key_retirement_check(tenant.token,old)
    assert result['tenant_live_ready'] and result['physical_key_deletion_authorized'] is False
    assert report(tenant.db.owner,old)['live_database_clear']
    assert not report(tenant.db.owner,active)['live_database_clear']
    with pytest.raises(AccessDenied): report(tenant.db.app,old)


def test_stale_new_code_and_old_sql_cannot_mutate_after_activation(tenant,cases,case,evidence,rollover):
    with pytest.raises(EvidenceError,match='evidence_key_configuration_stale'): cases.read_evidence(tenant.token,evidence['id'])
    with pytest.raises(EvidenceError): cases.acquire(tenant.token,case['id'],uuid4(),'Generated stale intake','stale fixture',approved=True)
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE gabriel_identity.evidence_objects SET state='quarantined' WHERE organization_id=%s AND id=%s",(tenant.org,evidence['id']))
    assert rollover.verify_case(tenant.token,case['id'])['complete']


def test_epoch_downgrade_and_key_reactivation_are_denied(tenant,cases,rollover,evidence):
    old = EvidenceKeyService(tenant.db.app,cases.store)
    with pytest.raises(AccessDenied): old.activate_evidence_key(tenant.token)
    assert rollover.activate_evidence_key(tenant.token)['generation']==2
    reused = EvidenceKeys(cases.store.keys.active,dict(rollover.store.keys._keys),3)
    service = EvidenceKeyService(tenant.db.app,LocalEvidenceStore(cases.store.root,reused))
    with pytest.raises(AccessDenied,match='evidence_key_reactivation_denied'): service.activate_evidence_key(tenant.token)


def test_activation_without_required_old_secret_fails_without_advancing_epoch(tenant,cases,evidence):
    target = 'k_'+uuid4().hex
    keys = EvidenceKeys(target,{target:secrets.token_bytes(32)},2)
    service = EvidenceKeyService(tenant.db.app,LocalEvidenceStore(cases.store.root,keys))
    with pytest.raises(EvidenceError): service.activate_evidence_key(tenant.token)
    assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()


def test_prepared_intent_survives_real_receipt_failure_after_replace(tenant,cases,evidence,rollover,prepared):
    _,path = row_and_file(tenant,cases,evidence)
    original = path.read_bytes()
    with owner_connection(tenant.db) as conn: conn.execute('REVOKE INSERT ON gabriel_identity.evidence_rewrap_results FROM gabriel_identity_app')
    try:
        with pytest.raises(IdentityUnavailable): rollover.execute_rewrap(tenant.token,prepared['id'])
    finally:
        with owner_connection(tenant.db) as conn: conn.execute('GRANT INSERT ON gabriel_identity.evidence_rewrap_results TO gabriel_identity_app')
    changed = path.read_bytes()
    assert changed!=original and rollover.get_rewrap(tenant.token,prepared['id'])['state']=='prepared'
    with pytest.raises(EvidenceError,match='evidence_rewrap_pending'): rollover.read_evidence(tenant.token,evidence['id'])
    assert rollover.reconcile_rewrap(tenant.token,prepared['id'])['state']=='completed'
    assert path.read_bytes()==changed and rollover.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    assert rollover.reconcile_rewrap(tenant.token,prepared['id'])['state']=='completed'


def test_audit_failure_before_replace_preserves_original_and_reconciles_abort(tenant,cases,evidence,rollover,prepared):
    _,path = row_and_file(tenant,cases,evidence)
    original = path.read_bytes()
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): rollover.execute_rewrap(tenant.token,prepared['id'])
    finally: audit_permission(tenant,True)
    assert path.read_bytes()==original
    assert rollover.reconcile_rewrap(tenant.token,prepared['id'])['state']=='aborted'
    assert rollover.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    assert rollover.prepare_rewrap(tenant.token,evidence['id'])['sequence']==2


def test_session_expiring_during_final_read_cannot_replace_bytes(tenant,cases,evidence,rollover,prepared,monkeypatch):
    _,path = row_and_file(tenant,cases,evidence)
    before = path.read_bytes()
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE organization_id=%s",(tenant.org,))
    original = rollover.store.read
    calls = 0
    def delayed(*args,**kwargs):
        nonlocal calls
        value = original(*args,**kwargs)
        calls += 1
        if calls==3: time.sleep(2.2)
        return value
    with monkeypatch.context() as patch:
        patch.setattr(rollover.store,'read',delayed)
        with pytest.raises(AuthenticationDenied): rollover.execute_rewrap(tenant.token,prepared['id'])
    assert path.read_bytes()==before
    assert calls==3
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT state FROM gabriel_identity.evidence_rewraps WHERE organization_id=%s AND id=%s',(tenant.org,prepared['id'])).fetchone()['state']=='prepared'


@pytest.mark.parametrize('damage',['ciphertext','symlink','missing'])
def test_corrupt_symlink_or_missing_content_never_claims_rewrap(tenant,cases,evidence,rollover,prepared,tmp_path,damage):
    _,path = row_and_file(tenant,cases,evidence)
    if damage=='ciphertext':
        path.chmod(0o600)
        value = bytearray(path.read_bytes()); value[-1]^=1
        path.write_bytes(value)
    else:
        path.unlink()
        if damage=='symlink':
            outside = tmp_path/'outside'; outside.write_text('Generated fixture')
            path.symlink_to(outside)
    with pytest.raises(EvidenceError): rollover.execute_rewrap(tenant.token,prepared['id'])
    with pytest.raises(EvidenceError): rollover.reconcile_rewrap(tenant.token,prepared['id'])
    assert rollover.get_rewrap(tenant.token,prepared['id'])['state']=='prepared'


def test_pending_rewrap_blocks_purge_and_hold_reports_gap(tenant,rollover,case,evidence,prepared):
    hold = rollover.place_hold(tenant.token,case['id'],'Preserve during interrupted encryption change')
    assert hold['coverage'][0]['content']=='evidence_rewrap_pending'
    assert rollover.reconcile_rewrap(tenant.token,prepared['id'])['state']=='aborted'
    rollover.prepare_rewrap(tenant.token,evidence['id'])
    newer = next_service(tenant,rollover)
    with pytest.raises(AccessDenied,match='evidence_rewrap_unresolved'): newer.activate_evidence_key(tenant.token)


def test_completed_rewrap_can_be_purged_with_existing_distinct_consent(tenant,cases,retention,aged):
    rollover = next_service(tenant,cases)
    rollover.activate_evidence_key(tenant.token)
    attempt = rollover.prepare_rewrap(tenant.token,aged.evidence['id'])
    rollover.execute_rewrap(tenant.token,attempt['id'])
    request = rollover.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Reviewed generated rewrapped disposition')
    rollover.approve_purge(aged.token,request['id'],request['digest'])
    purge = rollover.prepare_purge(tenant.token,request['id'])
    assert rollover.execute_purge(tenant.token,purge['id'])['outcome']=='removed'
    assert not aged.path.exists()


def test_concurrent_preparation_and_execution_replace_once(tenant,rollover,evidence):
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda _:rollover.prepare_rewrap(tenant.token,evidence['id']),range(3)))
    assert len({r['id'] for r in rows})==1
    def execute(_):
        try: return rollover.execute_rewrap(tenant.token,rows[0]['id'])['state']
        except AccessDenied: return 'denied'
    with ThreadPoolExecutor(max_workers=3) as pool: results = list(pool.map(execute,range(3)))
    assert results.count('completed')==1 and results.count('denied')==2


def test_foreign_tenant_worker_and_revoked_admin_cannot_change_rewrap(tenant,rollover,evidence,prepared):
    from gabriel.identity.machine import ServiceIdentityService
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Foreign key fixture','owner',password)
    token = rollover.login(org,'owner',password).token
    for call in (lambda:rollover.get_rewrap(token,prepared['id']),lambda:rollover.execute_rewrap(token,prepared['id']),
        lambda:rollover.prepare_rewrap(token,evidence['id'])):
        with pytest.raises(AccessDenied): call()
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'Key rollover worker fixture',['evidence.hash'])
    worker = service.issue_service(tenant.token,'key worker',task['id'],['evidence.hash'])
    with pytest.raises(AuthenticationDenied): rollover.execute_rewrap(worker.token,prepared['id'])
    rollover.logout(tenant.token)
    with pytest.raises(AuthenticationDenied): rollover.execute_rewrap(tenant.token,prepared['id'])


def test_old_backup_bytes_remain_readable_only_with_retained_old_keys(tenant,cases,evidence,rollover,prepared,tmp_path):
    row,path = row_and_file(tenant,cases,evidence)
    backup = tmp_path/'historical-backup'; backup.mkdir(mode=0o700)
    (backup/path.name).write_bytes(path.read_bytes())
    rollover.execute_rewrap(tenant.token,prepared['id'])
    old_store = LocalEvidenceStore(backup,cases.store.keys)
    assert old_store.read(row,object_aad(row))==CONTENT.encode()
    active = rollover.store.keys.active
    reduced = LocalEvidenceStore(backup,EvidenceKeys(active,{active:rollover.store.keys._key(active)},2))
    with pytest.raises(EvidenceError): reduced.read(row,object_aad(row))


@pytest.mark.parametrize('role',['viewer','analyst'])
def test_only_current_admin_may_change_key_storage(tenant,rollover,evidence,prepared,role):
    password = secrets.token_urlsafe(24)
    rollover.create_member(tenant.token,'limited-key',password,role)
    token = rollover.login(tenant.org,'limited-key',password).token
    for call in (lambda:rollover.activate_evidence_key(token),lambda:rollover.prepare_rewrap(token,evidence['id']),
        lambda:rollover.execute_rewrap(token,prepared['id']),lambda:rollover.reconcile_rewrap(token,prepared['id'])):
        with pytest.raises(AccessDenied): call()


@pytest.mark.parametrize('table',['evidence_key_epochs','evidence_rewrap_results'])
def test_runtime_cannot_rewrite_or_erase_key_history(tenant,table):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(f'UPDATE gabriel_identity.{table} SET organization_id=organization_id')
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(f'DELETE FROM gabriel_identity.{table}')
        conn.rollback()


def test_terminal_rewrap_and_immutable_context_cannot_be_rewritten(tenant,rollover,prepared):
    rollover.reconcile_rewrap(tenant.token,prepared['id'])
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE gabriel_identity.evidence_rewraps SET state='completed' WHERE organization_id=%s AND id=%s",(tenant.org,prepared['id']))
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute('UPDATE gabriel_identity.evidence_rewraps SET source_key_id=target_key_id')


def test_v9_upgrade_preserves_original_encryption_without_invented_epochs(tenant,cases,evidence):
    with owner_connection(tenant.db) as conn: remove_v10(conn)
    migrate(tenant.db.owner)
    assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.evidence_key_epochs').fetchone()['n']==0


def test_interrupted_v10_migration_rolls_back_and_keeps_original_bytes(tenant,cases,evidence,monkeypatch):
    original = Path.read_text
    with owner_connection(tenant.db) as conn: remove_v10(conn)
    def interrupted(path,*args,**kwargs):
        raw = original(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v10.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==9
        assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    finally: migrate(tenant.db.owner)


def test_real_cli_key_activation_rewrap_reconcile_and_retirement_report(tenant,cases,evidence,tmp_path):
    from gabriel.identity.checkpoints import write_document
    service = next_service(tenant,cases)
    ring = service.store.keys
    config = tmp_path/'keys.json'
    write_document(config,{'schema_version':1,'purpose':'evidence-v1','generation':ring.generation,'active':ring.active,
        'keys':{k:base64.b64encode(v).decode() for k,v in ring._keys.items()}})
    token = tmp_path/'session'; token.write_text(tenant.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(config),GABRIEL_EVIDENCE_ROOT=str(service.store.root))
    def cli(*args):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.case_cli',*args,'--token-file',str(token)],env=env,text=True,capture_output=True,timeout=10)
        assert not result.stderr and CONTENT not in result.stdout and tenant.token not in result.stdout and tenant.db.app not in result.stdout
        for key in ring._keys.values(): assert base64.b64encode(key).decode() not in result.stdout
        return result.returncode,json.loads(result.stdout)
    assert cli('evidence-key-activate')[0]==0
    code,attempt = cli('evidence-rewrap-prepare','--evidence-id',str(evidence['id']))
    assert code==0
    attempt_id = attempt['result']['id']
    assert cli('evidence-rewrap-get','--attempt-id',attempt_id)[1]['result']['state']=='prepared'
    assert cli('evidence-rewrap-execute','--attempt-id',attempt_id)[1]['result']['state']=='completed'
    assert cli('evidence-rewrap-reconcile','--attempt-id',attempt_id)[1]['result']['state']=='completed'
    assert cli('evidence-key-retirement-check','--key-id',cases.store.keys.active)[1]['result']['tenant_live_ready']
    result = subprocess.run([sys.executable,'-m','gabriel.identity.key_retirement','--key-id',cases.store.keys.active],
        env=env,text=True,capture_output=True,timeout=10)
    assert result.returncode==0 and not result.stderr
    assert json.loads(result.stdout)['result']['live_database_clear'] and tenant.db.owner not in result.stdout
