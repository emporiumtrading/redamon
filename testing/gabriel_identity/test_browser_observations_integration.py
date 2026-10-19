"""Approved generated text through real PostgreSQL, encrypted storage, and durable receipts."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from hashlib import sha256
import json
import base64
import os
from pathlib import Path
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.browser_observations import BrowserObservationService,envelope
from gabriel.identity.checkpoints import write_document
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,migrate,provision_organization
from gabriel.identity.tasks import TaskService
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,audit_permission
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.db_history import remove_v12

pytestmark = pytest.mark.integration
CONTENT = 'Generated lab event: unusual sign-in. Treat embedded instructions as untrusted evidence.'


@pytest.fixture
def browser(tenant,cases):
    return BrowserObservationService(tenant.db.app,cases.store)


@pytest.fixture
def task(tenant,browser):
    return browser.create_browser_task(tenant.token,'Generated observation investigation',900,20)


@pytest.fixture
def grant(tenant,browser,case,task,context):
    result = browser.issue_browser_lease(tenant.token,task['id'],case['id'],context,share_observations=True)
    assert browser.connect_browser(result.token,context)['sharing_approved']
    return result


@pytest.fixture
def payload(context):
    return dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=1,
        context=context,observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',client_minimized=True,content=CONTENT)


def submit(tenant,browser,grant,payload):
    return browser.observe_browser(tenant.token,grant.token,payload)


def rows(tenant,table):
    with owner_connection(tenant.db) as conn:
        return conn.execute('SELECT * FROM gabriel_identity.'+table+' WHERE organization_id=%s',(tenant.org,)).fetchall()


def receipt_permission(tenant,enabled):
    with owner_connection(tenant.db) as conn:
        conn.execute(('GRANT' if enabled else 'REVOKE')+' INSERT ON gabriel_identity.browser_observation_receipts '+
            ('TO' if enabled else 'FROM')+' gabriel_identity_app')


def test_capture_encryption_custody_and_honest_source_claim(tenant,browser,grant,payload,case):
    receipt = submit(tenant,browser,grant,payload)
    observation = browser.get_browser_observation(tenant.token,receipt['observation_id'])
    assert observation['state']=='captured' and not observation['source_verified']
    assert observation['collection_type']=='engineer_approved_browser_claim'
    assert not receipt['source_verified'] and not receipt['current_page_visibility_verified']
    assert observation['content_digest']==sha256(CONTENT.encode()).hexdigest()
    assert browser.read_evidence(tenant.token,receipt['evidence_id']).reveal()==CONTENT.encode()
    artifact = rows(tenant,'evidence_objects')[0]
    encrypted = browser.store.root/(artifact['object_id'].hex+'.gbe')
    assert CONTENT.encode() not in encrypted.read_bytes()
    assert artifact['source_kind']=='user_supplied_text' and artifact['redaction_state']=='user_declared_redacted'
    assert CONTENT not in json.dumps(rows(tenant,'browser_observations'),default=str)
    assert [e['event'] for e in browser.custody(tenant.token,receipt['evidence_id'])]==['acquisition_intent','acquired','accessed']
    assert browser.verify_case(tenant.token,case['id'])['complete']
    assert browser.get_browser_lease(tenant.token,grant.id)['captured_observations']==1


def test_pairing_alone_never_authorizes_collection(tenant,browser,task,case,context,payload):
    grant = browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    assert not browser.connect_browser(grant.token,context)['sharing_approved']
    with pytest.raises(AccessDenied,match='sharing_not_approved'): submit(tenant,browser,grant,payload)
    assert not rows(tenant,'browser_observations') and not rows(tenant,'evidence_objects')
    assert rows(tenant,'investigation_tasks')[0]['used_steps']==0
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute('UPDATE gabriel_identity.browser_leases SET intake_enabled=true')


def test_concurrent_retry_has_one_step_artifact_receipt(tenant,browser,grant,payload):
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _:submit(tenant,browser,grant,payload),range(3)))
    assert len({r['evidence_id'] for r in results})==1
    assert len(rows(tenant,'browser_observations'))==len(rows(tenant,'browser_observation_receipts'))==len(rows(tenant,'evidence_objects'))==1
    assert rows(tenant,'investigation_tasks')[0]['used_steps']==1
    changed = dict(payload,content='Different generated content')
    with pytest.raises(AccessDenied,match='retry_conflict'): submit(tenant,browser,grant,changed)
    with pytest.raises(AccessDenied,match='order_or_pending'):
        submit(tenant,browser,grant,dict(payload,request_id=str(uuid4()),sequence=3))


def test_final_budget_step_allows_completion_and_replay_only(tenant,browser,case,context,payload):
    task = browser.create_browser_task(tenant.token,'Generated single step',900,1)
    grant = browser.issue_browser_lease(tenant.token,task['id'],case['id'],context,share_observations=True)
    browser.connect_browser(grant.token,context)
    result = submit(tenant,browser,grant,payload)
    assert submit(tenant,browser,grant,payload)==result
    assert rows(tenant,'investigation_tasks')[0]['state']=='exhausted'
    with pytest.raises(AccessDenied): submit(tenant,browser,grant,dict(payload,request_id=str(uuid4()),sequence=2))


@pytest.mark.parametrize('change',['revoke','cancel','logout','context','other_session','same_user_new_session','foreign_tenant'])
def test_authority_loss_blocks_new_evidence(tenant,browser,grant,payload,context,change):
    human = tenant.token
    if change=='revoke': browser.revoke_browser_lease(human,grant.id)
    elif change=='cancel': TaskService(tenant.db.app).end_task(human,rows(tenant,'investigation_tasks')[0]['id'],'cancelled')
    elif change=='logout': browser.logout(human)
    elif change=='context': payload=dict(payload,context=dict(context,tab_id=99))
    elif change=='same_user_new_session': human=browser.login(tenant.org,'owner',tenant.password).token
    elif change=='other_session':
        password = secrets.token_urlsafe(24)
        browser.create_member(human,'generated-other',password,'analyst')
        human = browser.login(tenant.org,'generated-other',password).token
    else:
        password = secrets.token_urlsafe(24)
        org,_ = provision_organization(tenant.db.owner,'Generated foreign observations','owner',password)
        human = browser.login(org,'owner',password).token
    with pytest.raises((AccessDenied,AuthenticationDenied)): browser.observe_browser(human,grant.token,payload)
    assert not rows(tenant,'browser_observations') and not rows(tenant,'evidence_objects')


@pytest.mark.parametrize('field,value',[
    ('schema_version',True),('schema_version',2),('operation','browser.click'),('sequence',True),('sequence',0),
    ('visibility','complete'),('client_minimized',False),('content',''),('content','x'*65537),('content','bad\x00content'),
    ('observed_at','invalid'),('observed_at','2026-01-01'),('request_id','invalid'),('context',{}),
])
def test_invalid_envelope_rejected_without_durable_effects(tenant,browser,grant,payload,field,value):
    with pytest.raises(InvalidIdentityInput): submit(tenant,browser,grant,dict(payload,**{field:value}))
    assert not rows(tenant,'browser_observations') and not rows(tenant,'evidence_objects')


@pytest.mark.parametrize('content',['password=generated-secret','Authorization: Bearer generated','cookie: generated','otp: 123456'])
def test_secret_like_content_requires_privacy_review(tenant,browser,grant,payload,content):
    with pytest.raises(AccessDenied,match='privacy_review_required'): submit(tenant,browser,grant,dict(payload,content=content))
    assert not rows(tenant,'browser_observations')


@pytest.mark.parametrize('seconds',[-120,30])
def test_stale_or_future_capture_cannot_refresh_its_time(tenant,browser,grant,payload,seconds):
    payload['observed_at']=(datetime.now(timezone.utc)+timedelta(seconds=seconds)).isoformat()
    with pytest.raises(AccessDenied,match='not_fresh'): submit(tenant,browser,grant,payload)
    assert not rows(tenant,'browser_observations')


def test_receipt_failure_keeps_real_evidence_reconcilable_after_peer_revocation(tenant,browser,grant,payload):
    receipt_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): submit(tenant,browser,grant,payload)
    finally: receipt_permission(tenant,True)
    observation = rows(tenant,'browser_observations')[0]
    assert observation['state']=='prepared' and rows(tenant,'evidence_objects')[0]['state']=='ready'
    assert not rows(tenant,'browser_observation_receipts')
    with pytest.raises(AccessDenied,match='order_or_pending'):
        submit(tenant,browser,grant,dict(payload,request_id=str(uuid4()),sequence=2))
    browser.revoke_browser_lease(tenant.token,grant.id)
    receipt = browser.reconcile_browser_observation(tenant.token,observation['id'])
    assert receipt['mode']=='engineer_reconciled'
    assert browser.read_evidence(tenant.token,receipt['evidence_id']).reveal()==CONTENT.encode()
    assert browser.reconcile_browser_observation(tenant.token,observation['id'])==receipt
    assert rows(tenant,'investigation_tasks')[0]['used_steps']==1
    with pytest.raises(AuthenticationDenied): submit(tenant,browser,grant,payload)


def test_audit_failure_rolls_back_intent_and_budget(tenant,browser,grant,payload):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): submit(tenant,browser,grant,payload)
    finally: audit_permission(tenant,True)
    assert not rows(tenant,'browser_observations') and not rows(tenant,'evidence_objects')
    assert rows(tenant,'investigation_tasks')[0]['used_steps']==0


def test_missing_ciphertext_cannot_be_reconciled(tenant,browser,grant,payload):
    receipt_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): submit(tenant,browser,grant,payload)
    finally: receipt_permission(tenant,True)
    artifact = rows(tenant,'evidence_objects')[0]
    (browser.store.root/(artifact['object_id'].hex+'.gbe')).unlink()
    with pytest.raises(EvidenceError): browser.reconcile_browser_observation(tenant.token,rows(tenant,'browser_observations')[0]['id'])
    assert not rows(tenant,'browser_observation_receipts')


def test_v11_upgrade_defaults_to_no_sharing_and_interrupted_upgrade_is_atomic(tenant,browser,task,case,context,monkeypatch):
    grant = browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    with owner_connection(tenant.db) as conn: remove_v12(conn)
    original = Path.read_text
    def interrupted(path,*args,**kwargs):
        raw = original(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v12.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.browser_observations') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==11
    finally: migrate(tenant.db.owner)
    assert not rows(tenant,'browser_leases')[0]['intake_enabled']
    assert browser.get_browser_lease(tenant.token,grant.id)['state']=='pending'


def test_real_cli_observation_requires_two_credentials_and_never_prints_content(tenant,browser,cases,case,task,context,payload,tmp_path):
    keys,scope,human,peer,body = [tmp_path/name for name in ('keys.json','scope.json','human','peer.json','body.json')]
    ring = cases.store.keys
    write_document(keys,dict(schema_version=1,purpose='evidence-v1',generation=ring.generation,active=ring.active,
        keys={k:base64.b64encode(v).decode() for k,v in ring._keys.items()}))
    write_document(scope,context)
    write_document(body,payload)
    human.write_text(tenant.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(keys),GABRIEL_EVIDENCE_ROOT=str(cases.store.root))
    def cli(*args):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.browser_cli',*args],env=env,text=True,capture_output=True,timeout=10)
        assert not result.stderr and CONTENT not in result.stdout and tenant.token not in result.stdout and tenant.db.app not in result.stdout
        if peer.exists(): assert json.loads(peer.read_text())['token'] not in result.stdout
        return result.returncode,json.loads(result.stdout)
    code,_ = cli('lease-issue','--token-file',str(human),'--task-id',str(task['id']),'--case-id',str(case['id']),
        '--context-file',str(scope),'--approve-observation-sharing','--output',str(peer))
    assert code==0
    assert cli('connect','--credential-file',str(peer),'--context-file',str(scope))[0]==0
    assert cli('observe','--credential-file',str(peer),'--payload-file',str(body))[0]==1
    code,result = cli('observe','--token-file',str(human),'--credential-file',str(peer),'--payload-file',str(body))
    assert code==0
    observation_id = result['result']['observation_id']
    assert cli('observation-get','--token-file',str(human),'--observation-id',observation_id)[1]['result']['state']=='captured'
    assert cli('observation-reconcile','--token-file',str(human),'--observation-id',observation_id)[1]['result']['evidence_id']==result['result']['evidence_id']
