"""Generated scopes and actual persisted browser pairing authority; no page collection simulated."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.browser_sessions import BrowserSessionService,approved_context,browser_digest
from gabriel.identity.checkpoints import write_document
from gabriel.identity.service import (AccessDenied,AuthenticationDenied,InvalidIdentityInput,IdentityUnavailable,
    migrate,provision_organization)
from gabriel.identity.tasks import TaskService
from testing.gabriel_identity.test_cases_integration import cases,case,audit_permission
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.db_history import remove_v11

pytestmark = pytest.mark.integration


@pytest.fixture
def browser(tenant,cases):
    return BrowserSessionService(tenant.db.app,cases.store)


@pytest.fixture
def context():
    return {'browser':'chrome','extension_version':'0.1.0','installation_id':str(uuid4()),'tab_id':7,
        'document_id':str(uuid4()),'page_url':'https://generated-console.invalid/security#events','account_label':'Generated lab account'}


@pytest.fixture
def task(tenant,browser):
    return browser.create_browser_task(tenant.token,'Generated browser investigation',900,20)


@pytest.fixture
def grant(tenant,browser,case,task,context):
    return browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)


def test_pairing_persists_hashed_scoped_credential_and_no_content_claim(tenant,browser,case,task,context,grant):
    assert grant.token not in repr(grant) and grant.token.startswith('gbp1_')
    with owner_connection(tenant.db) as conn:
        row = conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',(tenant.org,grant.id)).fetchone()
    assert row['token_digest']==browser_digest(grant.token) and grant.token not in json.dumps(row,default=str)
    assert row['state']=='pending' and task['resource']=='browser-observation-v1' and task['operations']==['browser.observe']
    with pytest.raises(AuthenticationDenied): browser.heartbeat_browser(grant.token,context)
    result = browser.connect_browser(grant.token,context)
    assert result['paired'] and result['page_content_received'] is False
    assert result['capabilities']==['session.heartbeat','session.disconnect']
    before = browser.get_browser_lease(tenant.token,grant.id)
    assert before['authorization_current'] and before['heartbeat_fresh']
    assert browser.connect_browser(grant.token,context)['expires_at']==grant.expires_at
    after = browser.get_browser_lease(tenant.token,grant.id)
    assert after['last_seen']==before['last_seen']
    assert 'token_digest' not in after and 'human_session_digest' not in after
    assert browser.heartbeat_browser(grant.token,context)['page_content_received'] is False
    assert str(task['id']) in [str(x) for x in browser.get_case(tenant.token,case['id'])['task_ids']]


@pytest.mark.parametrize('field,value',[
    ('browser','firefox'),('extension_version','0.2.0'),('tab_id',True),('tab_id',-1),('tab_id',2147483648),
    ('installation_id','not-a-uuid'),('document_id','../bad'),('account_label',''),('account_label','unsafe\nvalue'),
    ('page_url','http://generated-console.invalid/security'),('page_url','https://user:secret@generated-console.invalid/security'),
    ('page_url','https://generated-console.invalid/security?token=secret'),('page_url','https://generated-console.invalid/login'),
    ('page_url','https://generated-console.invalid/sso/callback'),('page_url','https://generated-console.invalid/security#token=secret'),
    ('page_url','https://generated-console.invalid/%0Dheader'),('page_url','https://GENERATED-console.invalid/security')])
def test_invalid_unsafe_or_unsupported_context_is_denied(context,field,value):
    context[field]=value
    with pytest.raises(InvalidIdentityInput): approved_context(context)


@pytest.mark.parametrize('suffix',[
    '/%6cogin','/%256cogin','/s%73o/callback','/security#token%3Dgenerated',
    '/security#token%253Dgenerated','/security%3Faccess_token=generated','/security%250Aheader',
    '/security%252525250Aheader','/security%5Cother','/security%C0%AF',
])
def test_encoded_sensitive_routes_and_fragment_secrets_cannot_bypass_scope_review(tenant,browser,case,task,context,suffix):
    context['page_url']='https://generated-console.invalid'+suffix
    with pytest.raises(InvalidIdentityInput): browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.browser_leases WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


def test_safe_encoded_unicode_route_keeps_exact_original_binding(tenant,browser,case,task,context):
    context['page_url']='https://generated-console.invalid/caf%C3%A9/events'
    grant = browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    assert browser.connect_browser(grant.token,context)['paired']
    changed=dict(context,page_url='https://generated-console.invalid/caf%c3%a9/events')
    with pytest.raises(AccessDenied): browser.heartbeat_browser(grant.token,changed)


@pytest.mark.parametrize('field,value',[
    ('browser','brave'),('installation_id',None),('tab_id',8),('document_id',None),
    ('page_url','https://generated-console.invalid/other'),('page_url','https://generated-console.invalid:8443/security#events'),
    ('page_url','https://other-console.invalid/security#events'),('page_url','https://generated-console.invalid/security#other'),
    ('account_label','Other generated account')])
def test_scope_drift_cannot_pair_or_heartbeat(tenant,browser,context,grant,field,value):
    changed = dict(context); changed[field]=str(uuid4()) if value is None else value
    with pytest.raises(AccessDenied): browser.connect_browser(grant.token,changed)
    assert browser.get_browser_lease(tenant.token,grant.id)['state']=='pending'
    browser.connect_browser(grant.token,context)
    before = browser.get_browser_lease(tenant.token,grant.id)['last_seen']
    with pytest.raises(AccessDenied): browser.heartbeat_browser(grant.token,changed)
    assert browser.get_browser_lease(tenant.token,grant.id)['last_seen']==before


def test_brave_scope_is_supported_as_distinct_typed_context(tenant,browser,case,task,context):
    context['browser']='brave'
    grant = browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    assert browser.connect_browser(grant.token,context)['paired']


def test_no_cross_audience_authority_and_local_task_cannot_pair(tenant,browser,case,context,grant):
    from gabriel.identity.machine import ServiceIdentityService
    service = ServiceIdentityService(tenant.db.app)
    local = service.create_task(tenant.token,'Generated local task',['evidence.hash'])
    worker = service.issue_service(tenant.token,'generated worker',local['id'],['evidence.hash'])
    with pytest.raises(AccessDenied): browser.issue_browser_lease(tenant.token,local['id'],case['id'],context)
    with pytest.raises(AuthenticationDenied): browser.create_case(grant.token,'Denied browser authority')
    for token in (tenant.token,worker.token,'gbp1_'+'a'*43,'',None):
        with pytest.raises(AuthenticationDenied): browser.connect_browser(token,context)
    with pytest.raises(AccessDenied): service.issue_service(tenant.token,'denied mixed scope',browser.get_browser_lease(tenant.token,grant.id)['task_id'],['evidence.hash'])


@pytest.mark.parametrize('change',['human_logout','role_change','task_cancel','lease_expiry','session_expiry','task_expiry'])
def test_authority_loss_denies_current_browser_session(tenant,browser,context,grant,change):
    browser.connect_browser(grant.token,context)
    row = browser.get_browser_lease(tenant.token,grant.id)
    if change=='human_logout': browser.logout(tenant.token)
    elif change=='task_cancel': TaskService(tenant.db.app).end_task(tenant.token,row['task_id'],'cancelled')
    else:
        with owner_connection(tenant.db) as conn:
            if change=='role_change':
                conn.execute("UPDATE gabriel_identity.memberships SET role='viewer' WHERE organization_id=%s AND user_id=%s",(tenant.org,tenant.owner))
            elif change=='lease_expiry':
                conn.execute("UPDATE gabriel_identity.browser_leases SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '6 minutes' WHERE organization_id=%s",(tenant.org,))
            elif change=='session_expiry':
                conn.execute("UPDATE gabriel_identity.sessions SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE organization_id=%s",(tenant.org,))
            else:
                conn.execute("UPDATE gabriel_identity.investigation_tasks SET created_at=statement_timestamp()-interval '2 hours',expires_at=statement_timestamp()-interval '90 minutes' WHERE organization_id=%s AND id=%s",(tenant.org,row['task_id']))
                assert conn.execute('SELECT expires_at<clock_timestamp() AS expired FROM gabriel_identity.investigation_tasks WHERE organization_id=%s AND id=%s',
                    (tenant.org,row['task_id'])).fetchone()['expired']
    with pytest.raises((AccessDenied,AuthenticationDenied)): browser.heartbeat_browser(grant.token,context)
    with pytest.raises((AccessDenied,AuthenticationDenied)): browser.connect_browser(grant.token,context)


@pytest.mark.parametrize('offset',[-60,60])
def test_heartbeat_gap_and_clock_rollback_require_fresh_pairing(tenant,browser,context,grant,offset):
    browser.connect_browser(grant.token,context)
    with owner_connection(tenant.db) as conn:
        # Construct a historical fixture; runtime credentials cannot disable this guard.
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DISABLE TRIGGER require_browser_lease_transition')
        conn.execute("UPDATE gabriel_identity.browser_leases SET created_at=clock_timestamp()-interval '2 minutes',last_seen=clock_timestamp()+%s*interval '1 second',expires_at=clock_timestamp()+interval '2 minutes' WHERE organization_id=%s",(offset,tenant.org))
        conn.execute('ALTER TABLE gabriel_identity.browser_leases ENABLE TRIGGER require_browser_lease_transition')
    assert not browser.get_browser_lease(tenant.token,grant.id)['heartbeat_fresh']
    with pytest.raises(AccessDenied,match='browser_heartbeat_gap_repair_required'): browser.heartbeat_browser(grant.token,context)
    with pytest.raises(AccessDenied): browser.connect_browser(grant.token,context)


def test_disconnect_and_engineer_revoke_are_terminal(tenant,browser,context,grant):
    browser.connect_browser(grant.token,context)
    browser.disconnect_browser(grant.token)
    assert browser.get_browser_lease(tenant.token,grant.id)['state']=='disconnected'
    browser.revoke_browser_lease(tenant.token,grant.id)
    for call in (lambda:browser.connect_browser(grant.token,context),lambda:browser.heartbeat_browser(grant.token,context)):
        with pytest.raises(AuthenticationDenied): call()
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE gabriel_identity.browser_leases SET state='active',last_seen=clock_timestamp() WHERE organization_id=%s AND id=%s",(tenant.org,grant.id))


def test_cross_tenant_viewer_and_foreign_analyst_cannot_revoke(tenant,browser,case,task,context,grant):
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Foreign generated browser tenant','owner',password)
    foreign = browser.login(org,'owner',password).token
    with pytest.raises(AccessDenied): browser.get_browser_lease(foreign,grant.id)
    with pytest.raises(AccessDenied): browser.revoke_browser_lease(foreign,grant.id)
    for role in ('viewer','analyst'):
        name = 'browser-'+role
        browser.create_member(tenant.token,name,password,role)
        token = browser.login(tenant.org,name,password).token
        with pytest.raises(AccessDenied): browser.revoke_browser_lease(token,grant.id)
        if role=='viewer':
            with pytest.raises(AccessDenied): browser.issue_browser_lease(token,task['id'],case['id'],context)


def test_audit_failure_rolls_back_pairing_and_heartbeat(tenant,browser,context,grant):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): browser.connect_browser(grant.token,context)
    finally: audit_permission(tenant,True)
    assert browser.get_browser_lease(tenant.token,grant.id)['state']=='pending'
    browser.connect_browser(grant.token,context)
    before = browser.get_browser_lease(tenant.token,grant.id)['last_seen']
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): browser.heartbeat_browser(grant.token,context)
    finally: audit_permission(tenant,True)
    assert browser.get_browser_lease(tenant.token,grant.id)['last_seen']==before


def test_concurrent_confirmation_preserves_one_lease_and_expiry(tenant,browser,context,grant):
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda _:browser.connect_browser(grant.token,context),range(3)))
    assert {r['lease_id'] for r in rows}=={str(grant.id)}
    assert {r['expires_at'] for r in rows}=={grant.expires_at}


def test_immutable_scope_and_tokens_cannot_be_rewritten(tenant,grant):
    with psycopg.connect(tenant.db.app) as conn:
        for assignment in ("page_url='https://outside.invalid/'","token_digest=repeat('0',64)",'tab_id=999'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute('UPDATE gabriel_identity.browser_leases SET '+assignment)
            conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute('DELETE FROM gabriel_identity.browser_leases')


def test_v10_upgrade_and_interrupted_v11_preserve_cases(tenant,browser,case,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v11(conn)
    original = Path.read_text
    def interrupted(path,*args,**kwargs):
        raw = original(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v11.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        assert browser.get_case(tenant.token,case['id'])['case']['id']==case['id']
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.browser_leases') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==10
    finally: migrate(tenant.db.owner)


def test_real_cli_pairs_without_exposing_browser_or_human_secrets(tenant,browser,cases,case,task,context,tmp_path):
    import base64
    ring = cases.store.keys
    keys,scope,human,credential = tmp_path/'keys.json',tmp_path/'scope.json',tmp_path/'session',tmp_path/'pair.json'
    write_document(keys,{'schema_version':1,'purpose':'evidence-v1','generation':ring.generation,'active':ring.active,
        'keys':{k:base64.b64encode(v).decode() for k,v in ring._keys.items()}})
    write_document(scope,context)
    human.write_text(tenant.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(keys),GABRIEL_EVIDENCE_ROOT=str(cases.store.root))
    def cli(*args):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.browser_cli',*args],env=env,text=True,capture_output=True,timeout=10)
        assert not result.stderr and tenant.token not in result.stdout and tenant.db.app not in result.stdout
        if credential.exists(): assert json.loads(credential.read_text())['token'] not in result.stdout
        return result.returncode,json.loads(result.stdout)
    assert cli('task-create','--name','Generated CLI browser task','--token-file',str(human))[0]==0
    code,result = cli('lease-issue','--token-file',str(human),'--case-id',str(case['id']),'--task-id',str(task['id']),
        '--context-file',str(scope),'--output',str(credential))
    assert code==0 and credential.stat().st_mode & 0o777==0o600
    lease_id = result['result']['lease_id']
    for command in ('connect','heartbeat'):
        assert cli(command,'--credential-file',str(credential),'--context-file',str(scope))[0]==0
    assert cli('lease-get','--token-file',str(human),'--lease-id',lease_id)[1]['result']['authorization_current']
    assert cli('disconnect','--credential-file',str(credential))[0]==0
    assert cli('lease-revoke','--token-file',str(human),'--lease-id',lease_id)[0]==0
