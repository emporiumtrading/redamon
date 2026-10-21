"""Generated navigation claims against PostgreSQL; no real console or browser execution."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.browser_navigation import BrowserNavigationService,CONTRACTS,context_of
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,migrate
from gabriel.identity.tasks import TaskService
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,audit_permission
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_observations_integration import payload,rows
from testing.gabriel_identity.db_history import remove_v21

pytestmark=pytest.mark.integration
DESTINATION='https://generated-console.invalid/security#traffic'
VERSION='generated-read-only-v1'


@pytest.fixture
def browser(tenant,cases):
    return BrowserNavigationService(tenant.db.app,cases.store)


@pytest.fixture
def grant(tenant,browser,case,context):
    task=browser.create_browser_task(tenant.token,'Generated navigation protocol',900,20)
    lease=browser.issue_browser_lease(tenant.token,task['id'],case['id'],context,share_observations=True)
    browser.connect_browser(lease.token,context)
    return lease


@pytest.fixture
def navigation(tenant,browser,grant,context,monkeypatch):
    monkeypatch.setitem(CONTRACTS,VERSION,{'/security#traffic','/security#events'})
    return browser.grant_navigation(tenant.token,grant.token,uuid4(),VERSION,[DESTINATION,context['page_url']],max_moves=2)


def prepare(tenant,browser,grant,destination=DESTINATION):
    return browser.prepare_navigation(tenant.token,grant.token,uuid4(),destination)


def complete(tenant,browser,grant,intent,context):
    target=dict(context,page_url=intent['destination_url'],document_id=str(uuid4()))
    return browser.complete_navigation(tenant.token,grant.token,intent['id'],target)


def test_default_contracts_deny_every_production_destination(tenant,browser,grant):
    assert not CONTRACTS
    with pytest.raises(AccessDenied,match='contract_not_admitted'):
        browser.grant_navigation(tenant.token,grant.token,uuid4(),VERSION,[DESTINATION])
    assert not rows(tenant,'browser_navigation_grants')


def test_only_original_human_session_can_grant_or_prepare(tenant,browser,grant,navigation):
    other=browser.login(tenant.org,'owner',tenant.password).token
    with pytest.raises(AccessDenied,match='original_operator'):
        browser.prepare_navigation(other,grant.token,uuid4(),DESTINATION)
    with pytest.raises(AccessDenied,match='original_operator'):
        browser.grant_navigation(other,grant.token,uuid4(),VERSION,[DESTINATION])
    assert not rows(tenant,'browser_navigation_intents')


@pytest.mark.parametrize('destination',[
    'https://outside.invalid/security#traffic',
    'https://generated-console.invalid/configuration',
    'https://generated-console.invalid/login'])
def test_contract_cannot_expand_to_other_origin_or_unknown_route(tenant,browser,grant,navigation,destination):
    with pytest.raises(AccessDenied): prepare(tenant,browser,grant,destination)
    assert not rows(tenant,'browser_navigation_intents')


def test_prepare_blocks_capture_until_atomic_context_commit(tenant,browser,grant,navigation,context,payload):
    intent=prepare(tenant,browser,grant)
    assert intent['state']=='prepared' and not intent['dispatch_performed'] and not intent['source_verified']
    with pytest.raises(AccessDenied,match='navigation_outcome_unresolved'):
        browser.observe_browser(tenant.token,grant.token,payload)
    result=complete(tenant,browser,grant,intent,context)
    assert result['current'] and not result['replayed'] and not result['source_verified']
    assert len(rows(tenant,'browser_navigation_receipts'))==len(rows(tenant,'browser_navigation_commits'))==1
    with pytest.raises(AccessDenied): browser.heartbeat_browser(grant.token,context)
    assert browser.heartbeat_browser(grant.token,result['context'])['page_content_received'] is False
    receipt=browser.observe_browser(tenant.token,grant.token,dict(payload,context=result['context']))
    assert receipt['evidence_id'] and not receipt['source_verified']
    with owner_connection(tenant.db) as conn:
        lease=conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',
                           (tenant.org,grant.id)).fetchone()
    assert context_of(lease)==result['context'] and lease['expires_at']==grant.expires_at


def test_concurrent_prepare_and_completion_replay_cannot_rewind(tenant,browser,grant,navigation,context):
    request=uuid4()
    with ThreadPoolExecutor(max_workers=3) as pool:
        intents=list(pool.map(lambda _:browser.prepare_navigation(tenant.token,grant.token,request,DESTINATION),range(3)))
    assert len({x['id'] for x in intents})==1
    target=dict(context,page_url=DESTINATION,document_id=str(uuid4()))
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda _:browser.complete_navigation(tenant.token,grant.token,intents[0]['id'],target),range(3)))
    assert sum(not x['replayed'] for x in results)==1
    second=prepare(tenant,browser,grant,context['page_url'])
    final=complete(tenant,browser,grant,second,target)
    old=browser.complete_navigation(tenant.token,grant.token,intents[0]['id'],target)
    assert old['replayed'] and not old['current']
    assert browser.heartbeat_browser(grant.token,final['context'])
    with pytest.raises(AccessDenied,match='move_limit'): prepare(tenant,browser,grant)
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute('SELECT gabriel_identity.apply_browser_navigation(%s,%s)',(tenant.org,intents[0]['id']))
    assert len(rows(tenant,'browser_navigation_commits'))==2


@pytest.mark.parametrize('field,value',[
    ('account_label','Other generated account'),('tab_id',99),('browser','brave'),
    ('installation_id',None),('page_url','https://outside.invalid/security#traffic')])
def test_completion_cannot_change_granted_identity(tenant,browser,grant,navigation,context,field,value):
    intent=prepare(tenant,browser,grant)
    target=dict(context,page_url=DESTINATION,document_id=str(uuid4()))
    target[field]=str(uuid4()) if value is None else value
    with pytest.raises(AccessDenied,match='scope_mismatch'):
        browser.complete_navigation(tenant.token,grant.token,intent['id'],target)
    assert not rows(tenant,'browser_navigation_receipts') and not rows(tenant,'browser_navigation_commits')


def test_unresolved_or_expired_move_requires_stop_not_automatic_retry(tenant,browser,grant,navigation,context,payload):
    intent=prepare(tenant,browser,grant)
    with pytest.raises(AccessDenied,match='outcome_unresolved'): prepare(tenant,browser,grant)
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.browser_navigation_intents SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '90 seconds' WHERE organization_id=%s",(tenant.org,))
    with pytest.raises(AccessDenied,match='not_current'): complete(tenant,browser,grant,intent,context)
    with pytest.raises(AccessDenied,match='outcome_unresolved'): prepare(tenant,browser,grant)
    with pytest.raises(AccessDenied,match='navigation_outcome_unresolved'):
        browser.observe_browser(tenant.token,grant.token,payload)
    assert browser.stop_navigation(tenant.token,grant.token)['stopped']
    with pytest.raises(AuthenticationDenied): browser.heartbeat_browser(grant.token,context)


def test_audit_failure_rolls_back_receipt_and_scope_change(tenant,browser,grant,navigation,context):
    intent=prepare(tenant,browser,grant)
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): complete(tenant,browser,grant,intent,context)
    finally: audit_permission(tenant,True)
    assert not rows(tenant,'browser_navigation_receipts') and not rows(tenant,'browser_navigation_commits')
    assert browser.heartbeat_browser(grant.token,context)
    assert complete(tenant,browser,grant,intent,context)['current']


@pytest.mark.parametrize('loss',['logout','cancel','contract_revoked'])
def test_current_authority_required_to_complete(tenant,browser,grant,navigation,context,monkeypatch,loss):
    intent=prepare(tenant,browser,grant)
    if loss=='logout': browser.logout(tenant.token)
    elif loss=='contract_revoked': monkeypatch.delitem(CONTRACTS,VERSION)
    else:
        lease=rows(tenant,'browser_leases')[0]
        TaskService(tenant.db.app).end_task(tenant.token,lease['task_id'],'cancelled')
    with pytest.raises((AccessDenied,AuthenticationDenied)): complete(tenant,browser,grant,intent,context)
    assert not rows(tenant,'browser_navigation_commits')
    if loss=='contract_revoked':
        assert browser.stop_navigation(tenant.token,grant.token)['stopped']
        with pytest.raises(AuthenticationDenied): browser.heartbeat_browser(grant.token,context)


def test_application_cannot_rewrite_scope_or_forge_commit(tenant,browser,grant,navigation):
    intent=prepare(tenant,browser,grant)
    statements=[
        ('UPDATE gabriel_identity.browser_leases SET page_url=%s',(DESTINATION,)),
        ('INSERT INTO gabriel_identity.browser_navigation_commits (organization_id,intent_id) VALUES (%s,%s)',(tenant.org,intent['id'])),
        ('DELETE FROM gabriel_identity.browser_navigation_grants',()),
        ('UPDATE gabriel_identity.browser_navigation_intents SET destination_url=%s',(DESTINATION,))]
    for sql,values in statements:
        with psycopg.connect(tenant.db.app) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(sql,values)


def test_v21_migration_is_atomic_and_preserves_existing_lease(tenant,browser,grant,context,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v21(conn)
    read=Path.read_text
    def interrupted(path,*args,**kwargs):
        raw=read(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v21.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        assert browser.heartbeat_browser(grant.token,context)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.browser_navigation_grants') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==20
    finally: migrate(tenant.db.owner)
