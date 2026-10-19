"""Real SQL trust/freshness receipts, generated historical captures and actual closure effects."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.checkpoint_policy import CheckpointPolicyService
from gabriel.identity.checkpoints import canonical,fingerprint,new_keypair,public_fingerprint,seal,write_document
from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import (AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,
    migrate,provision_organization)
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,audit_permission,CONTENT
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.db_history import remove_v9

pytestmark = pytest.mark.integration


@pytest.fixture
def policy_service(tenant,cases):
    return CheckpointPolicyService(tenant.db.app,cases.store)


@pytest.fixture
def trusted(tenant,policy_service):
    private,public = new_keypair()
    pin = public_fingerprint(public)
    policy_service.trust_checkpoint_key(tenant.token,public,pin)
    policy_service.set_checkpoint_policy(tenant.token,pin,3600)
    return private,public,pin


def signed(service,token,case_id,private):
    envelope = seal(service.capture_checkpoint(token,case_id),private)
    return envelope,fingerprint(canonical(envelope))


@pytest.fixture
def accepted(tenant,policy_service,trusted,case,evidence):
    envelope,expected = signed(policy_service,tenant.token,case['id'],trusted[0])
    receipt = policy_service.accept_checkpoint(tenant.token,case['id'],envelope,expected)
    return envelope,expected,receipt


def approved_close(service,tenant,case):
    service.set_policy(tenant.token,distinct_approver=False)
    row = service.propose_close(tenant.token,case['id'],uuid4(),'Reviewed generated checkpoint-policy closure')
    service.submit(tenant.token,row['id'])
    service.approve(tenant.token,row['id'],row['digest'])
    return row


def age_fixture(tenant,private,envelope,seconds,receipt=None):
    """Construct historical signed fixtures with real SQL binding updates; never mock a clock."""
    snapshot = json.loads(json.dumps(envelope['body']['snapshot']))
    with owner_connection(tenant.db) as conn:
        instant = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']-timedelta(seconds=seconds)
        snapshot['captured_at']=iso(instant)
        conn.execute('UPDATE gabriel_identity.checkpoint_captures SET captured_at=%s,snapshot_digest=%s WHERE organization_id=%s AND case_id=%s AND nonce=%s',
            (instant,fingerprint(canonical(snapshot)),tenant.org,snapshot['case_id'],snapshot['nonce']))
        changed = seal(snapshot,private)
        expected = fingerprint(canonical(changed))
        if receipt:
            conn.execute('UPDATE gabriel_identity.checkpoint_receipts SET envelope=%s::jsonb,digest=%s WHERE organization_id=%s AND id=%s',
                (canonical(changed).decode(),expected,tenant.org,receipt['id']))
    return changed,expected


def test_no_implicit_policy_or_unpinned_key_enrollment(tenant,policy_service,case):
    private,public = new_keypair()
    with pytest.raises(InvalidIdentityInput): policy_service.trust_checkpoint_key(tenant.token,public,'0'*64)
    with pytest.raises(AccessDenied): policy_service.set_checkpoint_policy(tenant.token,public_fingerprint(public),3600)
    with pytest.raises(AccessDenied,match='checkpoint_policy_required'):
        policy_service.check_checkpoint_policy(tenant.token,case['id'],'0'*64)
    with pytest.raises(InvalidIdentityInput): policy_service.trust_checkpoint_key(tenant.token,private,public_fingerprint(public))


@pytest.mark.parametrize('age',[0,59,86401,True,None])
def test_invalid_freshness_windows_denied(tenant,policy_service,trusted,age):
    with pytest.raises(InvalidIdentityInput): policy_service.set_checkpoint_policy(tenant.token,trusted[2],age)


def test_accepted_receipt_is_idempotent_and_cannot_refresh_its_capture(tenant,policy_service,case,accepted):
    envelope,expected,receipt = accepted
    replay = policy_service.accept_checkpoint(tenant.token,case['id'],envelope,expected)
    assert replay==receipt
    result = policy_service.check_checkpoint_policy(tenant.token,case['id'],expected)
    assert result['full_current_evidence_coverage'] and result['receipt_id']==str(receipt['id'])
    assert result['content_integrity']=='not_checked' and result['source_authenticity']=='unverified'
    for wrong in (None,'0'*64):
        with pytest.raises(AccessDenied): policy_service.check_checkpoint_policy(tenant.token,case['id'],wrong)


def test_unregistered_and_future_claimed_capture_cannot_be_accepted(tenant,policy_service,trusted,case,evidence):
    envelope,_ = signed(policy_service,tenant.token,case['id'],trusted[0])
    for field,value in [('nonce',str(uuid4())),('captured_at','2099-01-01T00:00:00.000000+00:00')]:
        snapshot = dict(envelope['body']['snapshot'])
        snapshot[field]=value
        altered = seal(snapshot,trusted[0])
        with pytest.raises(AccessDenied,match='checkpoint_capture_not_registered'):
            policy_service.accept_checkpoint(tenant.token,case['id'],altered,fingerprint(canonical(altered)))


@pytest.mark.parametrize('seconds',[7200,-7200])
def test_stale_or_future_capture_is_denied_at_acceptance_and_current_check(tenant,policy_service,trusted,case,accepted,seconds):
    envelope,_,receipt = accepted
    aged,expected = age_fixture(tenant,trusted[0],envelope,seconds,receipt)
    with pytest.raises(AccessDenied,match='checkpoint_not_fresh'):
        policy_service.accept_checkpoint(tenant.token,case['id'],aged,expected)
    with pytest.raises(AccessDenied,match='checkpoint_not_fresh'):
        policy_service.check_checkpoint_policy(tenant.token,case['id'],expected)


def test_new_receipt_prevents_old_digest_and_out_of_order_acceptance(tenant,policy_service,trusted,case,accepted):
    first,old,_ = accepted
    waiting,waiting_digest = signed(policy_service,tenant.token,case['id'],trusted[0])
    latest,digest = signed(policy_service,tenant.token,case['id'],trusted[0])
    receipt = policy_service.accept_checkpoint(tenant.token,case['id'],latest,digest)
    assert receipt['revision']==2
    with pytest.raises(AccessDenied,match='checkpoint_current_receipt_required'):
        policy_service.check_checkpoint_policy(tenant.token,case['id'],old)
    for envelope,expected in [(first,old),(waiting,waiting_digest)]:
        with pytest.raises(AccessDenied,match='checkpoint_capture_not_newer'):
            policy_service.accept_checkpoint(tenant.token,case['id'],envelope,expected)


def test_policy_revision_invalidates_receipt_without_reaging_old_capture(tenant,policy_service,trusted,case,accepted):
    envelope,expected,_ = accepted
    policy_service.set_checkpoint_policy(tenant.token,trusted[2],7200)
    with pytest.raises(AccessDenied,match='checkpoint_current_receipt_required'):
        policy_service.check_checkpoint_policy(tenant.token,case['id'],expected)
    with pytest.raises(AccessDenied,match='checkpoint_receipt_context_changed'):
        policy_service.accept_checkpoint(tenant.token,case['id'],envelope,expected)
    fresh,digest = signed(policy_service,tenant.token,case['id'],trusted[0])
    assert policy_service.accept_checkpoint(tenant.token,case['id'],fresh,digest)['policy_revision']==2


def test_revocation_is_irreversible_and_new_key_requires_new_policy_and_capture(tenant,policy_service,trusted,case,accepted):
    _,expected,_ = accepted
    policy_service.revoke_checkpoint_key(tenant.token,trusted[2],'Retire generated signer key')
    with pytest.raises(AccessDenied): policy_service.check_checkpoint_policy(tenant.token,case['id'],expected)
    with pytest.raises(AccessDenied): policy_service.trust_checkpoint_key(tenant.token,trusted[1],trusted[2])
    private,public = new_keypair()
    pin = public_fingerprint(public)
    policy_service.trust_checkpoint_key(tenant.token,public,pin)
    policy_service.set_checkpoint_policy(tenant.token,pin,3600)
    envelope,digest = signed(policy_service,tenant.token,case['id'],private)
    policy_service.accept_checkpoint(tenant.token,case['id'],envelope,digest)
    assert policy_service.check_checkpoint_policy(tenant.token,case['id'],digest)['full_current_evidence_coverage']


def test_untrusted_signer_cannot_override_configured_policy_key(tenant,policy_service,trusted,case,evidence):
    private,_ = new_keypair()
    envelope,digest = signed(policy_service,tenant.token,case['id'],private)
    with pytest.raises(EvidenceError,match='checkpoint_trust_validation_failed'):
        policy_service.accept_checkpoint(tenant.token,case['id'],envelope,digest)


def test_current_coverage_requires_recapture_after_new_evidence(tenant,policy_service,trusted,case,accepted):
    envelope,expected,_ = accepted
    policy_service.acquire(tenant.token,case['id'],uuid4(),'Generated additional evidence','later fixture',approved=True)
    assert policy_service.verify_checkpoint(tenant.token,case['id'],envelope,trusted[1],expected)['custody_prefixes_match']
    with pytest.raises(EvidenceError,match='checkpoint_coverage_incomplete'):
        policy_service.check_checkpoint_policy(tenant.token,case['id'],expected)
    latest,digest = signed(policy_service,tenant.token,case['id'],trusted[0])
    policy_service.accept_checkpoint(tenant.token,case['id'],latest,digest)
    assert policy_service.check_checkpoint_policy(tenant.token,case['id'],digest)['full_current_evidence_coverage']


def test_case_close_requires_external_digest_and_preserves_exact_action_receipt(tenant,policy_service,case,accepted):
    _,expected,_ = accepted
    action = approved_close(policy_service,tenant,case)
    for wrong in (None,'0'*64):
        with pytest.raises(AccessDenied): policy_service.execute(tenant.token,action['id'],checkpoint_digest=wrong)
    assert policy_service.get_case(tenant.token,case['id'])['case']['state']=='open'
    result = policy_service.execute(tenant.token,action['id'],checkpoint_digest=expected)
    assert result['state']=='closed'
    assert policy_service.execute(tenant.token,action['id'],checkpoint_digest=expected)==result


def test_checkpoint_expiry_after_application_check_is_denied_by_database(tenant,policy_service,case,accepted,monkeypatch):
    from gabriel.identity import checkpoint_policy
    _,expected,receipt = accepted
    action = approved_close(policy_service,tenant,case)
    original = checkpoint_policy.fresh
    def expire(conn,capture,policy):
        value = original(conn,capture,policy)
        with owner_connection(tenant.db) as owner:
            owner.execute("UPDATE gabriel_identity.checkpoint_captures SET captured_at=clock_timestamp()-interval '2 hours' WHERE organization_id=%s AND case_id=%s AND nonce=%s",
                (tenant.org,case['id'],receipt['nonce']))
        return value
    with monkeypatch.context() as patch:
        patch.setattr(checkpoint_policy,'fresh',expire)
        with pytest.raises(IdentityUnavailable):
            policy_service.execute(tenant.token,action['id'],checkpoint_digest=expected)
    assert policy_service.get_case(tenant.token,case['id'])['case']['state']=='open'
    assert policy_service.get_action(tenant.token,action['id'])['execution'] is None


def test_older_runtime_cannot_bypass_database_checkpoint_guard(tenant,policy_service,case,accepted,monkeypatch):
    from gabriel.identity import checkpoint_policy
    action = approved_close(policy_service,tenant,case)
    with monkeypatch.context() as patch:
        patch.setattr(checkpoint_policy,'admit_close',lambda *a:None)
        with pytest.raises(IdentityUnavailable): policy_service.execute(tenant.token,action['id'])
    assert policy_service.get_case(tenant.token,case['id'])['case']['state']=='open'
    assert policy_service.get_action(tenant.token,action['id'])['execution'] is None


def test_audit_failure_rolls_back_acceptance_and_closure(tenant,policy_service,trusted,case,evidence):
    envelope,digest = signed(policy_service,tenant.token,case['id'],trusted[0])
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): policy_service.accept_checkpoint(tenant.token,case['id'],envelope,digest)
    finally: audit_permission(tenant,True)
    with pytest.raises(AccessDenied): policy_service.check_checkpoint_policy(tenant.token,case['id'],digest)
    policy_service.accept_checkpoint(tenant.token,case['id'],envelope,digest)
    action = approved_close(policy_service,tenant,case)
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): policy_service.execute(tenant.token,action['id'],checkpoint_digest=digest)
    finally: audit_permission(tenant,True)
    assert policy_service.get_case(tenant.token,case['id'])['case']['state']=='open'


def test_concurrent_acceptance_and_revocation_serialize(tenant,policy_service,trusted,case,evidence):
    envelope,digest = signed(policy_service,tenant.token,case['id'],trusted[0])
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda _:policy_service.accept_checkpoint(tenant.token,case['id'],envelope,digest),range(3)))
    assert len({r['id'] for r in rows})==1
    action = approved_close(policy_service,tenant,case)
    def execute():
        try: return policy_service.execute(tenant.token,action['id'],checkpoint_digest=digest)['state']
        except AccessDenied: return 'denied'
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(execute)
        policy_service.revoke_checkpoint_key(tenant.token,trusted[2],'Concurrent generated revocation')
        result = future.result()
    assert (result,policy_service.get_case(tenant.token,case['id'])['case']['state']) in {('closed','closed'),('denied','open')}
    with pytest.raises(AccessDenied): policy_service.check_checkpoint_policy(tenant.token,case['id'],digest)


@pytest.mark.parametrize('role',['viewer','analyst'])
def test_roles_cannot_change_trust_or_accept_receipts(tenant,policy_service,trusted,case,accepted,role):
    envelope,digest,_ = accepted
    password = secrets.token_urlsafe(24)
    policy_service.create_member(tenant.token,'checkpoint-limited',password,role)
    token = policy_service.login(tenant.org,'checkpoint-limited',password).token
    assert policy_service.check_checkpoint_policy(token,case['id'],digest)['full_current_evidence_coverage']
    for call in (lambda:policy_service.trust_checkpoint_key(token,trusted[1],trusted[2]),
        lambda:policy_service.set_checkpoint_policy(token,trusted[2],3600),
        lambda:policy_service.accept_checkpoint(token,case['id'],envelope,digest),
        lambda:policy_service.revoke_checkpoint_key(token,trusted[2],'Denied role revocation')):
        with pytest.raises(AccessDenied): call()
    policy_service.logout(token)
    with pytest.raises(AuthenticationDenied): policy_service.check_checkpoint_policy(token,case['id'],digest)


def test_cross_tenant_and_worker_boundaries(tenant,policy_service,trusted,case,accepted):
    from gabriel.identity.machine import ServiceIdentityService
    envelope,digest,_ = accepted
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Foreign policy fixture','owner',password)
    token = policy_service.login(org,'owner',password).token
    with pytest.raises(AccessDenied): policy_service.set_checkpoint_policy(token,trusted[2],3600)
    with pytest.raises(AccessDenied): policy_service.check_checkpoint_policy(token,case['id'],digest)
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'Checkpoint policy worker',['evidence.hash'])
    worker = service.issue_service(tenant.token,'policy worker',task['id'],['evidence.hash'])
    with pytest.raises(AuthenticationDenied): policy_service.accept_checkpoint(worker.token,case['id'],envelope,digest)


def test_durable_acceptance_survives_acceptor_logout(tenant,policy_service,case,accepted):
    _,digest,_ = accepted
    policy_service.logout(tenant.token)
    token = policy_service.login(tenant.org,'owner',tenant.password).token
    assert policy_service.check_checkpoint_policy(token,case['id'],digest)['full_current_evidence_coverage']


@pytest.mark.parametrize('table',['checkpoint_keys','checkpoint_key_revocations','checkpoint_policies','checkpoint_captures','checkpoint_receipts'])
def test_governance_rows_cannot_be_rewritten_or_erased_by_runtime(tenant,table):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(f'UPDATE gabriel_identity.{table} SET organization_id=organization_id')
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(f'DELETE FROM gabriel_identity.{table}')
        conn.rollback()


def test_v8_upgrade_preserves_evidence_without_invented_policy(tenant,policy_service,case,evidence):
    with owner_connection(tenant.db) as conn: remove_v9(conn)
    migrate(tenant.db.owner)
    assert policy_service.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    with pytest.raises(AccessDenied,match='checkpoint_policy_required'): policy_service.get_checkpoint_policy(tenant.token)
    assert policy_service.capture_checkpoint(tenant.token,case['id'])['case_id']==str(case['id'])


def test_interrupted_v9_migration_rolls_back_without_evidence_loss(tenant,policy_service,case,evidence,monkeypatch):
    original = Path.read_text
    with owner_connection(tenant.db) as conn: remove_v9(conn)
    def interrupted(path,*args,**kwargs):
        data = original(path,*args,**kwargs)
        return data+'\nSELECT 1/0;' if path.name=='schema_v9.sql' else data
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.checkpoint_keys') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==8
        assert policy_service.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    finally: migrate(tenant.db.owner)


def test_real_cli_trust_policy_accept_check_revoke_and_closure(tenant,policy_service,case,evidence,tmp_path):
    import base64
    private,public = new_keypair()
    pin = public_fingerprint(public)
    public_path,keys = tmp_path/'public.json',tmp_path/'evidence-keys.json'
    write_document(public_path,public)
    ring = policy_service.store.keys
    write_document(keys,{'schema_version':1,'purpose':'evidence-v1','generation':ring.generation,'active':ring.active,
        'keys':{k:base64.b64encode(v).decode() for k,v in ring._keys.items()}})
    token = tmp_path/'session'
    token.write_text(tenant.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(keys),GABRIEL_EVIDENCE_ROOT=str(policy_service.store.root))
    def cli(*args):
        run = subprocess.run([sys.executable,'-m','gabriel.identity.case_cli',*args,'--token-file',str(token)],env=env,text=True,capture_output=True,timeout=10)
        assert not run.stderr and CONTENT not in run.stdout and tenant.token not in run.stdout and tenant.db.app not in run.stdout
        return run.returncode,json.loads(run.stdout)
    assert cli('checkpoint-key-trust','--trusted-public-key',str(public_path),'--key-fingerprint',pin)[0]==0
    assert cli('checkpoint-policy-set','--key-fingerprint',pin,'--max-age-seconds','3600')[0]==0
    assert cli('checkpoint-policy-get')[0]==0
    envelope,digest = signed(policy_service,tenant.token,case['id'],private)
    file = tmp_path/'signed.json'
    write_document(file,envelope)
    assert cli('checkpoint-accept','--case-id',str(case['id']),'--checkpoint-file',str(file),'--expected-digest',digest)[0]==0
    assert cli('checkpoint-check','--case-id',str(case['id']),'--expected-digest',digest)[0]==0
    action = approved_close(policy_service,tenant,case)
    assert cli('action-execute','--approval-id',str(action['id']))[0]==1
    assert cli('action-execute','--approval-id',str(action['id']),'--checkpoint-digest',digest)[1]['result']['state']=='closed'
    assert cli('checkpoint-key-revoke','--key-fingerprint',pin,'--rationale','CLI generated revocation')[0]==0
    assert cli('checkpoint-check','--case-id',str(case['id']),'--expected-digest',digest)[0]==1
