"""Generated historical encrypted artifacts, real holds and primary-file disposition."""
from concurrent.futures import ThreadPoolExecutor
import base64
from datetime import timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.cases import ZERO_HASH,custody_hash,object_aad
from gabriel.identity.evidence_store import EvidenceError,LocalEvidenceStore
from gabriel.identity.retention import RetentionService
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import (AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,
    migrate,provision_organization)
from testing.gabriel_identity.db_history import remove_v8
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,intake,row_and_file,audit_permission,CONTENT
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection

pytestmark = pytest.mark.integration


def historical_artifact(tenant,store,evidence,days=2):
    """Construct a declared historical fixture, including real GCM and custody hashes."""
    row,path = row_and_file(tenant,SimpleNamespace(store=store),evidence)
    data = store.read(row,object_aad(row))
    with owner_connection(tenant.db) as conn:
        observed = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']-timedelta(days=days)
        events = conn.execute('SELECT * FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s ORDER BY sequence',
            (tenant.org,row['id'])).fetchall()
        previous = ZERO_HASH
        acquisition = None
        for event in events:
            created = observed if event['sequence']==1 else event['created_at']
            bound = custody_hash(tenant.org,row['id'],event['sequence'],event['actor_id'],event['event'],previous,created)
            conn.execute('UPDATE gabriel_identity.custody_events SET previous_hash=%s,event_hash=%s,created_at=%s WHERE organization_id=%s AND evidence_id=%s AND sequence=%s',
                (previous,bound,created,tenant.org,row['id'],event['sequence']))
            if event['sequence']==1:
                acquisition = bound
            previous = bound
        row = conn.execute('UPDATE gabriel_identity.evidence_objects SET observed_at=%s,acquisition_hash=%s WHERE organization_id=%s AND id=%s RETURNING *',
            (observed,acquisition,tenant.org,row['id'])).fetchone()
    path.unlink()
    store.write(row,data,object_aad(row))
    return row,path


@pytest.fixture
def retention(tenant,cases):
    return RetentionService(tenant.db.app,cases.store)


@pytest.fixture
def aged(tenant,retention,case,evidence):
    row,path = historical_artifact(tenant,retention.store,evidence)
    retention.set_policy(tenant.token,distinct_approver=False)
    close = retention.propose_close(tenant.token,case['id'],uuid4(),'Close generated historical fixture')
    retention.submit(tenant.token,close['id'])
    retention.approve(tenant.token,close['id'],close['digest'])
    retention.execute(tenant.token,close['id'])
    retention.set_retention(tenant.token,1)
    password = secrets.token_urlsafe(24)
    admin = retention.create_member(tenant.token,'retention-admin',password,'admin')
    token = retention.login(tenant.org,'retention-admin',password).token
    return SimpleNamespace(case=case,evidence=row,path=path,admin=admin,token=token)


@pytest.fixture
def approved_purge(tenant,retention,aged):
    request = retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Reviewed primary content disposition')
    retention.approve_purge(aged.token,request['id'],request['digest'])
    return request


@pytest.fixture
def prepared(tenant,retention,approved_purge):
    return retention.prepare_purge(tenant.token,approved_purge['id'])


def test_approved_primary_purge_retains_metadata_custody_and_tombstone(tenant,retention,aged,prepared):
    before = retention.custody(tenant.token,aged.evidence['id'])
    assert aged.path.exists() and retention.store.identity()
    with pytest.raises(EvidenceError,match='evidence_disposition_pending'):
        retention.read_evidence(tenant.token,aged.evidence['id'])
    result = retention.execute_purge(tenant.token,prepared['id'])
    assert result['outcome']=='removed' and not aged.path.exists()
    assert retention.custody(tenant.token,aged.evidence['id'])==before
    record = retention.get_case(tenant.token,aged.case['id'])['evidence'][0]
    assert record['storage_state']=='purged' and record['digest']==sha256(CONTENT.encode()).hexdigest()
    with pytest.raises(EvidenceError,match='evidence_purged'):
        retention.read_evidence(tenant.token,aged.evidence['id'])
    with pytest.raises(EvidenceError):
        retention.prepare_export(tenant.token,aged.evidence['id'])
    fresh = RetentionService(tenant.db.app,retention.store)
    assert fresh.reconcile_purge(tenant.token,prepared['id'])['outcome']=='removed'
    with pytest.raises(AccessDenied):
        fresh.execute_purge(tenant.token,prepared['id'])
    assert fresh.get_purge(tenant.token,prepared['request_id'])['state']=='completed'
    with pytest.raises(AccessDenied,match='evidence_content_unavailable'):
        fresh.acquire(tenant.token,aged.case['id'],aged.evidence['ingestion_id'],CONTENT,
            aged.evidence['source_label'],approved=True,event_time=aged.evidence['source_event_time'])
    assert not aged.path.exists()


def test_missing_policy_open_case_and_recent_evidence_deny_purge(tenant,retention,case,evidence):
    with pytest.raises(AccessDenied,match='purge_requires_closed_case'):
        retention.propose_purge(tenant.token,evidence['id'],uuid4(),'Denied open-case purge')
    retention.set_policy(tenant.token,distinct_approver=False)
    close = retention.propose_close(tenant.token,case['id'],uuid4(),'Reviewed fixture closure')
    retention.submit(tenant.token,close['id'])
    retention.approve(tenant.token,close['id'],close['digest'])
    retention.execute(tenant.token,close['id'])
    with pytest.raises(AccessDenied,match='retention_policy_required'):
        retention.propose_purge(tenant.token,evidence['id'],uuid4(),'Missing policy')
    retention.set_retention(tenant.token,1)
    with pytest.raises(AccessDenied,match='evidence_retention_not_elapsed'):
        retention.propose_purge(tenant.token,evidence['id'],uuid4(),'Too recent')


def test_retention_shortening_never_reduces_historical_floor(tenant,retention,aged):
    retention.set_retention(tenant.token,30)
    retention.set_retention(tenant.token,1)
    policy = retention.get_retention(tenant.token)
    assert policy['days']==1 and policy['floor_days']==30
    with pytest.raises(AccessDenied,match='evidence_retention_not_elapsed'):
        retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Denied shortened retention')


def test_default_two_person_purge_cannot_be_disabled_by_case_policy(tenant,retention,aged):
    request = retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Two-person purge')
    with pytest.raises(AccessDenied):
        retention.approve_purge(tenant.token,request['id'],request['digest'])
    with pytest.raises(AccessDenied):
        retention.approve_purge(aged.token,request['id'],'0'*64)
    with pytest.raises(AccessDenied):
        retention.prepare_purge(tenant.token,request['id'])
    retention.approve_purge(aged.token,request['id'],request['digest'])
    assert retention.get_purge(tenant.token,request['id'])['approval']['approved_by']==aged.admin


def test_hold_release_requires_different_admin_exact_digest_and_preserves_history(tenant,retention,aged):
    hold = retention.place_hold(tenant.token,aged.case['id'],'Preserve generated fixture')
    assert hold['coverage'][0]['content']=='verified_present'
    for token,bound in [(tenant.token,hold['digest']),(aged.token,'0'*64)]:
        with pytest.raises(AccessDenied):
            retention.release_hold(token,hold['id'],bound,'Reviewed hold release')
    with pytest.raises(AccessDenied,match='evidence_on_legal_hold'):
        retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Blocked by hold')
    retention.release_hold(aged.token,hold['id'],hold['digest'],'Reviewed hold release')
    result = retention.governance(tenant.token,aged.case['id'])
    assert result['hold_version']==2 and result['holds'][0]['state']=='released'
    with pytest.raises(AccessDenied):
        retention.release_hold(aged.token,hold['id'],hold['digest'],'Cannot release twice')


def test_hold_between_preparation_and_unlink_wins_and_release_does_not_revive_consent(tenant,retention,aged,prepared):
    hold = retention.place_hold(tenant.token,aged.case['id'],'Hold wins over prepared intent')
    with pytest.raises(AccessDenied,match='evidence_on_legal_hold'):
        retention.execute_purge(tenant.token,prepared['id'])
    assert aged.path.exists()
    retention.release_hold(aged.token,hold['id'],hold['digest'],'Approved release with retained history')
    with pytest.raises(AccessDenied,match='purge_context_changed'):
        retention.execute_purge(tenant.token,prepared['id'])
    result = retention.reconcile_purge(tenant.token,prepared['id'],abort=True)
    assert result['outcome']=='verified_present' and aged.path.exists()
    assert retention.read_evidence(tenant.token,aged.evidence['id']).reveal()==CONTENT.encode()
    request = retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Fresh reviewed consent after release')
    assert request['payload']['hold_version']==2


def test_parallel_hold_and_purge_reports_truthful_coverage(tenant,retention,aged,prepared):
    def purge():
        try:
            return retention.execute_purge(tenant.token,prepared['id'])['state']
        except AccessDenied:
            return 'held'
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(purge)
        hold = retention.place_hold(tenant.token,aged.case['id'],'Concurrent preservation request')
        state = future.result()
    if state=='held':
        assert aged.path.exists() and hold['coverage'][0]['content']=='verified_present'
    else:
        assert state=='completed' and not aged.path.exists()
        assert hold['coverage'][0]['content']!='verified_present' and hold['coverage'][0]['disposition']=='completed'


def test_audit_failure_before_prepared_intent_never_deletes(tenant,retention,aged,approved_purge):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable):
            retention.prepare_purge(tenant.token,approved_purge['id'])
    finally:
        audit_permission(tenant,True)
    assert aged.path.exists() and retention.get_purge(tenant.token,approved_purge['id'])['attempt'] is None


def test_deletion_then_receipt_failure_remains_visible_and_reconciles_without_unlink(tenant,retention,aged,prepared):
    with owner_connection(tenant.db) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.retention_events FROM gabriel_identity_app')
    try:
        with pytest.raises(IdentityUnavailable):
            retention.execute_purge(tenant.token,prepared['id'])
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.retention_events TO gabriel_identity_app')
    assert not aged.path.exists()
    assert retention.get_purge(tenant.token,prepared['request_id'])['attempt']['state']=='prepared'
    hold = retention.place_hold(tenant.token,aged.case['id'],'Hold after interrupted deletion')
    assert hold['coverage'][0]['content']!='verified_present'
    with pytest.raises(AccessDenied,match='purge_absence_requires_reconciliation'):
        retention.execute_purge(tenant.token,prepared['id'])
    assert retention.reconcile_purge(tenant.token,prepared['id'])['outcome']=='absence_confirmed'
    assert retention.governance(tenant.token,aged.case['id'])['holds'][0]['state']=='active'


def test_present_content_cannot_be_claimed_absent_and_missing_content_cannot_be_aborted(tenant,retention,aged,prepared):
    with pytest.raises(AccessDenied,match='purge_content_still_present'):
        retention.reconcile_purge(tenant.token,prepared['id'])
    aged.path.unlink()
    with pytest.raises(EvidenceError):
        retention.reconcile_purge(tenant.token,prepared['id'],abort=True)
    assert retention.reconcile_purge(tenant.token,prepared['id'])['outcome']=='absence_confirmed'


@pytest.mark.parametrize('damage',['ciphertext','symlink'])
def test_corrupt_or_symlink_content_is_never_unlinked(tenant,retention,aged,prepared,damage,tmp_path):
    if damage=='ciphertext':
        aged.path.chmod(0o600)
        sealed = bytearray(aged.path.read_bytes())
        sealed[-1] ^= 1
        aged.path.write_bytes(sealed)
    else:
        aged.path.unlink()
        outside = tmp_path/'outside-fixture'
        outside.write_text('Generated outside fixture')
        aged.path.symlink_to(outside)
    with pytest.raises(EvidenceError):
        retention.execute_purge(tenant.token,prepared['id'])
    assert aged.path.exists()


@pytest.mark.parametrize('marker',[False,True])
def test_wrong_store_cannot_confirm_absence(tenant,retention,aged,prepared,tmp_path,marker):
    other = tmp_path/'wrong-store'
    other.mkdir(mode=0o700)
    store = LocalEvidenceStore(other,retention.store.keys)
    if marker:
        store.identity(enroll=True)
    wrong = RetentionService(tenant.db.app,store)
    with pytest.raises((AccessDenied,EvidenceError)):
        wrong.reconcile_purge(tenant.token,prepared['id'])
    with pytest.raises((AccessDenied,EvidenceError)):
        wrong.execute_purge(tenant.token,prepared['id'])
    assert aged.path.exists()


@pytest.mark.parametrize('change',['policy','requester_logout','approver_logout','approval_expiry','request_expiry'])
def test_stale_policy_or_authority_prevents_unlink(tenant,retention,aged,prepared,change):
    token = tenant.token
    if change=='policy':
        retention.set_retention(tenant.token,1)
    elif change=='requester_logout':
        retention.logout(tenant.token)
        token = retention.login(tenant.org,'owner',tenant.password).token
    elif change=='approver_logout':
        retention.logout(aged.token)
    else:
        with owner_connection(tenant.db) as conn:
            table = 'purge_approvals' if change=='approval_expiry' else 'purge_requests'
            conn.execute(f"UPDATE gabriel_identity.{table} SET created_at=statement_timestamp()-interval '30 minutes',expires_at=statement_timestamp()-interval '15 minutes' WHERE organization_id=%s",(tenant.org,)) if change=='request_expiry' else conn.execute("UPDATE gabriel_identity.purge_approvals SET created_at=statement_timestamp()-interval '10 minutes',expires_at=statement_timestamp()-interval '6 minutes' WHERE organization_id=%s",(tenant.org,))
    with pytest.raises((AccessDenied,AuthenticationDenied)):
        retention.execute_purge(token,prepared['id'])
    assert aged.path.exists()


def test_expiry_during_final_crypto_read_is_checked_before_unlink(tenant,retention,aged,prepared,monkeypatch):
    original = retention.store.read
    calls = 0
    def expire(*args,**kwargs):
        nonlocal calls
        value = original(*args,**kwargs)
        calls += 1
        if calls==2:
            with owner_connection(tenant.db) as conn:
                conn.execute("UPDATE gabriel_identity.sessions SET created_at=statement_timestamp()-interval '2 hours',expires_at=statement_timestamp()-interval '1 hour' WHERE organization_id=%s AND user_id=%s",(tenant.org,aged.admin))
        return value
    with monkeypatch.context() as patch:
        patch.setattr(retention.store,'read',expire)
        with pytest.raises(AccessDenied,match='purge_actor_revoked'):
            retention.execute_purge(tenant.token,prepared['id'])
    assert aged.path.exists()


def test_unresolved_export_blocks_disposition(tenant,retention,aged):
    export = retention.prepare_export(tenant.token,aged.evidence['id'])
    with pytest.raises(AccessDenied,match='evidence_export_unresolved'):
        retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Unresolved export blocks purge')
    retention.finish_export(tenant.token,export.export_id,completed=False)
    assert retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'Reviewed after export reconciliation')['state']=='proposed'


def test_concurrent_proposal_and_preparation_are_idempotent(tenant,retention,aged):
    key = uuid4()
    with ThreadPoolExecutor(max_workers=3) as pool:
        requests = list(pool.map(lambda _:retention.propose_purge(tenant.token,aged.evidence['id'],key,'Concurrent purge fixture'),range(3)))
    assert len({r['id'] for r in requests})==1
    with pytest.raises(AccessDenied):
        retention.propose_purge(tenant.token,aged.evidence['id'],key,'Changed reason')
    request = requests[0]
    retention.approve_purge(aged.token,request['id'],request['digest'])
    with ThreadPoolExecutor(max_workers=3) as pool:
        attempts = list(pool.map(lambda _:retention.prepare_purge(tenant.token,request['id']),range(3)))
    assert len({a['id'] for a in attempts})==1
    with ThreadPoolExecutor(max_workers=3) as pool:
        def execute(_):
            try:
                return retention.execute_purge(tenant.token,attempts[0]['id'])['outcome']
            except AccessDenied:
                return 'not admitted'
        values = list(pool.map(execute,range(3)))
    assert values.count('removed')==1 and values.count('not admitted')==2


def test_cancel_prevents_preparation_and_prepared_requires_safe_abort(tenant,retention,aged,approved_purge):
    retention.cancel_purge(tenant.token,approved_purge['id'])
    with pytest.raises(AccessDenied):
        retention.prepare_purge(tenant.token,approved_purge['id'])
    new = retention.propose_purge(tenant.token,aged.evidence['id'],uuid4(),'New purge request')
    retention.approve_purge(aged.token,new['id'],new['digest'])
    attempt = retention.prepare_purge(tenant.token,new['id'])
    with pytest.raises(AccessDenied):
        retention.cancel_purge(tenant.token,new['id'])
    retention.reconcile_purge(tenant.token,attempt['id'],abort=True)
    assert aged.path.exists()


def test_cross_tenant_hold_and_purge_access_denied(tenant,retention,aged,approved_purge):
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Other retention fixture','owner',password)
    token = retention.login(org,'owner',password).token
    for call in (lambda:retention.governance(token,aged.case['id']),lambda:retention.place_hold(token,aged.case['id'],'Denied foreign hold'),
                 lambda:retention.get_purge(token,approved_purge['id']),lambda:retention.approve_purge(token,approved_purge['id'],approved_purge['digest'])):
        with pytest.raises(AccessDenied):
            call()


@pytest.mark.parametrize('role',['viewer','analyst'])
def test_roles_can_preserve_but_cannot_delete_or_release_holds(tenant,retention,aged,approved_purge,role):
    password = secrets.token_urlsafe(24)
    retention.create_member(tenant.token,'limited-retention',password,role)
    token = retention.login(tenant.org,'limited-retention',password).token
    assert retention.get_purge(token,approved_purge['id'])['id']==approved_purge['id']
    for call in (lambda:retention.set_retention(token,1),lambda:retention.prepare_purge(token,approved_purge['id']),
                 lambda:retention.approve_purge(token,approved_purge['id'],approved_purge['digest'])):
        with pytest.raises(AccessDenied):
            call()
    if role=='analyst':
        assert retention.place_hold(token,aged.case['id'],'Analyst preservation request')['state']=='active'
    else:
        with pytest.raises(AccessDenied):
            retention.place_hold(token,aged.case['id'],'Viewer cannot mutate hold')


def test_worker_cannot_manage_retention(tenant,retention,aged):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'retention worker fixture',['evidence.hash'])
    worker = service.issue_service(tenant.token,'bounded worker',task['id'],['evidence.hash'])
    with pytest.raises(AuthenticationDenied):
        retention.place_hold(worker.token,aged.case['id'],'Denied worker hold')
    with pytest.raises(AuthenticationDenied):
        retention.set_retention(worker.token,1)


def test_real_cli_hold_consent_primary_purge_and_reconciliation(tenant,retention,aged,tmp_path):
    config = tmp_path/'keys.json'
    ring = retention.store.keys
    config.write_text(json.dumps({'schema_version':1,'purpose':'evidence-v1','generation':ring.generation,
        'active':ring.active,'keys':{k:base64.b64encode(v).decode() for k,v in ring._keys.items()}}))
    config.chmod(0o444)
    human = tmp_path/'owner-session'
    human.write_text(tenant.token)
    admin = tmp_path/'admin-session'
    admin.write_text(aged.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(config),GABRIEL_EVIDENCE_ROOT=str(retention.store.root))
    def cli(*args,reviewer=False):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.case_cli',*args,'--token-file',str(admin if reviewer else human)],
            env=env,capture_output=True,text=True,timeout=10)
        assert not result.stderr and CONTENT not in result.stdout and tenant.token not in result.stdout and aged.token not in result.stdout
        assert tenant.db.app not in result.stdout and config.read_text() not in result.stdout
        return result.returncode,json.loads(result.stdout)
    assert cli('retention-get')[0]==0
    assert cli('retention-set','--days','1')[0]==0
    code,hold = cli('hold-place','--case-id',str(aged.case['id']),'--rationale','CLI preservation fixture')
    assert code==0
    assert cli('governance','--case-id',str(aged.case['id']))[0]==0
    assert cli('hold-release','--hold-id',hold['result']['id'],'--expected-digest',hold['result']['digest'],
        '--rationale','CLI reviewed release',reviewer=True)[0]==0
    code,request = cli('purge-propose','--evidence-id',str(aged.evidence['id']),'--request-id',str(uuid4()),'--rationale','CLI reviewed disposition')
    assert code==0
    action = request['result']['id']
    assert cli('purge-approve','--approval-id',action,'--expected-digest',request['result']['digest'],reviewer=True)[0]==0
    code,attempt = cli('purge-prepare','--approval-id',action)
    assert code==0
    assert cli('purge-get','--approval-id',action)[1]['result']['attempt']['state']=='prepared'
    assert cli('purge-execute','--attempt-id',attempt['result']['id'])[1]['result']['outcome']=='removed'
    assert not aged.path.exists()
    assert cli('purge-reconcile','--attempt-id',attempt['result']['id'])[0]==0


@pytest.mark.parametrize('table,assignment',[
    ('retention_policies','days=1'),('legal_holds',"reason='changed'"),('hold_releases',"reason='changed'"),
    ('purge_requests',"digest=repeat('0',64)"),('purge_approvals',"digest=repeat('0',64)"),
    ('purge_attempts','evidence_id=gen_random_uuid()'),('retention_events',"event='hold_placed'")])
def test_runtime_cannot_rewrite_or_erase_governance_bindings(tenant,table,assignment):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f'UPDATE gabriel_identity.{table} SET {assignment}')
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f'DELETE FROM gabriel_identity.{table}')
        conn.rollback()


@pytest.mark.parametrize('days',[0,3651,True,None])
def test_invalid_retention_durations_denied(tenant,retention,days):
    with pytest.raises(InvalidIdentityInput):
        retention.set_retention(tenant.token,days)


def test_v7_upgrade_preserves_cases_without_inventing_retention_or_holds(tenant,retention,case,evidence):
    with owner_connection(tenant.db) as conn:
        remove_v8(conn)
    migrate(tenant.db.owner)
    assert retention.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    assert retention.governance(tenant.token,case['id'])['holds']==[]
    with pytest.raises(AccessDenied,match='retention_policy_required'):
        retention.get_retention(tenant.token)


def test_interrupted_v8_migration_rolls_back_without_evidence_loss(tenant,retention,evidence,monkeypatch):
    original = Path.read_text
    with owner_connection(tenant.db) as conn:
        remove_v8(conn)
    def interrupted(path,*args,**kwargs):
        value = original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v8.sql' else value
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable):
                migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.legal_holds') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==7
        assert retention.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    finally:
        migrate(tenant.db.owner)
