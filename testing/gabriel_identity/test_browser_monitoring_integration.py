"""Real authority, lifetime and multi-tab isolation; no production provider dispatch."""
from io import BytesIO
import json
import os
import secrets
from types import SimpleNamespace
import psycopg
from psycopg.conninfo import make_conninfo
from psycopg import sql
from gabriel.identity.cli import read_secret
from gabriel.identity.service import migrate
from uuid import uuid4

import pytest

from gabriel.identity.browser_gateway import BrowserGateway,BrowserGatewayGroup,ticket_digest
from gabriel.identity.browser_navigation import BrowserNavigationService,OPERATOR_PAGES
from gabriel.identity.service import AccessDenied,AuthenticationDenied,InvalidIdentityInput
from testing.gabriel_identity.test_identity_integration import tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context

pytestmark=pytest.mark.integration


@pytest.fixture(scope='module')
def database():
    app_path,owner_path=os.environ.get('GABRIEL_IDENTITY_DSN_FILE'),os.environ.get('GABRIEL_MIGRATION_DSN_FILE')
    if not app_path or not owner_path:pytest.skip('isolated PostgreSQL credentials required')
    owner=read_secret(owner_path);app=read_secret(app_path);name='gabriel_monitor_'+secrets.token_hex(8)
    with psycopg.connect(owner,autocommit=True) as conn:conn.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    scoped=SimpleNamespace(owner=make_conninfo(owner,dbname=name),app=make_conninfo(app,dbname=name))
    try:
        migrate(scoped.owner)
        yield scoped
    finally:
        with psycopg.connect(owner,autocommit=True) as conn:conn.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))


def enrollment(tenant,cases,case,context,tab=1,**kwargs):
    browser=BrowserNavigationService(tenant.db.app,cases.store)
    task=browser.create_browser_task(tenant.token,'Generated scheduled review',3600,100)
    scope=dict(context,extension_version='0.4.0',tab_id=tab)
    lease=browser.issue_browser_lease(tenant.token,task['id'],case['id'],scope,share_observations=True,**kwargs)
    ticket='gbc1_'+'a'*42+('a' if tab==1 else 'b')
    config=dict(endpoint='https://localhost:8443',extension_origin='chrome-extension://'+'a'*32,
        context=scope,ticket_digest=ticket_digest(ticket),lease_id=str(lease.id))
    gateway=BrowserGateway(browser,tenant.token,lease.token,config)
    return browser,lease,scope,gateway,ticket


def call(group,operation,body,token=None):
    raw=json.dumps(body).encode();status=[]
    env={'wsgi.url_scheme':'https','HTTP_HOST':'localhost:8443','HTTP_ORIGIN':'chrome-extension://'+'a'*32,
        'REQUEST_METHOD':'POST','PATH_INFO':'/v1/browser/'+operation,'CONTENT_TYPE':'application/json',
        'CONTENT_LENGTH':str(len(raw)),'wsgi.input':BytesIO(raw)}
    if token:env['HTTP_AUTHORIZATION']='Bearer '+token
    result=b''.join(group(env,lambda code,headers:status.append(code)))
    return status[0],json.loads(result)


def test_scheduled_lifetime_requires_explicit_server_sharing_consent(tenant,cases,case,context):
    with pytest.raises(InvalidIdentityInput):enrollment(tenant,cases,case,context,ttl_seconds=3600)
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,ttl_seconds=3600,monitoring_approved=True)
    paired=browser.connect_browser(lease.token,scope)
    assert paired['scheduled_review_enabled']
    with owner_connection(tenant.db) as conn:
        row=conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',(tenant.org,lease.id)).fetchone()
    assert 300<(row['expires_at']-row['created_at']).total_seconds()<=3600
    with pytest.raises(InvalidIdentityInput):
        browser.issue_browser_lease(tenant.token,row['task_id'],case['id'],scope,3600,monitoring_approved=True)


def test_group_routes_tickets_and_credentials_without_cross_tab_authority(tenant,cases,case,context):
    one=enrollment(tenant,cases,case,context,tab=1)
    two=enrollment(tenant,cases,case,context,tab=2)
    group=BrowserGatewayGroup([one[3],two[3]])
    assert call(group,'claim',{'ticket':two[4],'context':one[2]})[0]=='403 Forbidden'
    for browser,lease,scope,gateway,ticket in [one,two]:
        status,result=call(group,'claim',{'ticket':ticket,'context':scope})
        assert status=='200 OK' and result['result']['token']==lease.token
    assert call(group,'heartbeat',{'context':two[2]},one[1].token)[0]=='403 Forbidden'
    assert call(group,'heartbeat',{'context':two[2]},two[1].token)[0]=='200 OK'
    assert call(group,'disconnect',{},one[1].token)[0]=='200 OK'
    assert call(group,'heartbeat',{'context':two[2]},two[1].token)[0]=='200 OK'
    assert two[0].get_browser_lease(tenant.token,two[1].id)['state']=='active'


@pytest.mark.parametrize('path',['/logout','/delete','/configuration','/settings','/reset','/apply','/block'])
def test_operator_route_grant_rejects_action_pages(tenant,cases,case,context,path):
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context)
    browser.connect_browser(lease.token,scope)
    from urllib.parse import urlsplit
    origin=urlsplit(scope['page_url'])
    with pytest.raises(AccessDenied):browser.grant_navigation(tenant.token,lease.token,uuid4(),OPERATOR_PAGES,[origin.scheme+'://'+origin.netloc+path])


def test_exact_operator_routes_remain_origin_bound_and_stop_is_terminal(tenant,cases,case,context):
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,ttl_seconds=3600,monitoring_approved=True)
    browser.connect_browser(lease.token,scope)
    from urllib.parse import urlsplit
    origin=urlsplit(scope['page_url']);destination=origin.scheme+'://'+origin.netloc+'/alerts'
    grant=browser.grant_navigation(tenant.token,lease.token,uuid4(),OPERATOR_PAGES,[destination],max_moves=100)
    assert grant['max_moves']==100
    assert browser.navigation_plan(tenant.token,lease.token,scope)['monitoring_approved']
    with pytest.raises(AccessDenied):browser.prepare_navigation(tenant.token,lease.token,uuid4(),'https://outside.invalid/alerts')
    browser.disconnect_browser(lease.token)
    with pytest.raises(AuthenticationDenied):browser.navigation_plan(tenant.token,lease.token,scope)


def test_text_review_is_receipt_bound_idempotent_and_preserves_source_quotes(tenant,cases,case,context):
    from gabriel.identity.model_protocol import decode
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,monitoring_approved=True)
    browser.connect_browser(lease.token,scope)
    payload=dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=1,context=scope,
        observed_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
        visibility='partial',client_minimized=True,content='Generated lab account\nFailed login for generated-user\n')
    captured=browser.observe_browser(tenant.token,lease.token,payload)
    one=browser.review_browser_text(tenant.token,lease.token,scope,captured['observation_id'])
    two=browser.review_browser_text(tenant.token,lease.token,scope,captured['observation_id'])
    assert one==two and one['candidate_count']==1 and not one['incident_confirmed']
    value=decode(browser.read_evidence(tenant.token,one['review_evidence_id']).reveal().decode())
    assert value['evidence_id']==str(captured['evidence_id'])
    assert all(payload['content'][r['start']:r['end']]==r['quote'] for r in value['findings'])
    browser.disconnect_browser(lease.token)
    with pytest.raises(AuthenticationDenied):browser.review_browser_text(tenant.token,lease.token,scope,captured['observation_id'])


def test_source_health_display_fields_do_not_expand_specialist_contract(tenant,cases,case,context):
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context)
    result=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    sample=next(r['sample'] for r in result['packet']['references'] if r['kind']=='browser_lease_sample')
    assert 'scheduled_permission' not in sample and 'captured_observations' not in sample


def test_discovery_is_explicit_and_binds_discovered_query_routes_to_original_origin(tenant,cases,case,context):
    from gabriel.identity.browser_navigation import DISCOVERED_PAGES
    from gabriel.identity.browser_sessions import approved_context
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,monitoring_approved=True,discovery_approved=True)
    status,result=call(gateway,'claim',{'ticket':ticket,'context':scope})
    assert status=='200 OK'
    plan=browser.navigation_plan(tenant.token,lease.token,scope)
    assert plan['contract_version']==DISCOVERED_PAGES and plan['destinations']==[scope['page_url']]
    from urllib.parse import urlsplit
    original=urlsplit(scope['page_url']);url=original.scheme+'://'+original.netloc+'/unknown-alerts?view=recent'
    assert approved_context(dict(scope,page_url=url))['page_url']==url
    intent=browser.prepare_navigation(tenant.token,lease.token,uuid4(),url)
    assert intent['destination_url']==url
    moved=dict(scope,page_url=url,document_id=str(uuid4()))
    completed=browser.complete_navigation(tenant.token,lease.token,intent['id'],moved)
    assert completed['current'] and browser.heartbeat_browser(lease.token,moved)
    from datetime import datetime,timezone
    captured=browser.observe_browser(tenant.token,lease.token,dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),
        sequence=1,context=moved,observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',client_minimized=True,
        content='Generated lab account\nFailed login for generated-user'))
    assert captured['evidence_id']
    assert browser.review_browser_text(tenant.token,lease.token,moved,captured['observation_id'])['candidate_count']==1
    for denied in [url+'&token=generated',url+'&action=delete','https://outside.invalid/alerts']:
        with pytest.raises((AccessDenied,AuthenticationDenied,InvalidIdentityInput)):
            browser.prepare_navigation(tenant.token,lease.token,uuid4(),denied)


def test_unrecognized_header_encoding_is_denied_by_group_without_raising(tenant,cases,case,context):
    one=enrollment(tenant,cases,case,context)
    status,result=call(BrowserGatewayGroup([one[3]]),'heartbeat',{'context':one[2]},'generated-invalid-ünicode')
    assert status=='403 Forbidden' and result['status']=='denied'


def test_generic_filters_allow_encoded_spaces_but_not_nested_action_routes(context):
    from gabriel.identity.browser_sessions import approved_context
    from gabriel.identity.browser_navigation import readonly_page
    context=dict(context,extension_version='0.4.0',page_url='https://generated-console.invalid/alerts?q=failed%20login')
    assert approved_context(context)['page_url'].endswith('failed%20login')
    with pytest.raises(AccessDenied):readonly_page('https://generated-console.invalid/%252564elete')


def test_database_discovery_receipts_reject_other_origins_and_enforce_page_budget(tenant,cases,case,context):
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,monitoring_approved=True,discovery_approved=True)
    assert call(gateway,'claim',{'ticket':ticket,'context':scope})[0]=='200 OK'
    plan=browser.navigation_plan(tenant.token,lease.token,scope)
    from urllib.parse import urlsplit
    url=urlsplit(scope['page_url']);origin=url.scheme+'://'+url.netloc
    statement='''INSERT INTO gabriel_identity.browser_discovered_destinations
        (organization_id,grant_id,destination_url,source_url,created_by) VALUES (%s,%s,%s,%s,%s)'''
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(statement,(tenant.org,plan['id'],'https://outside.invalid/alerts',scope['page_url'],tenant.owner))
    with psycopg.connect(tenant.db.app) as conn:
        for i in range(19):conn.execute(statement,(tenant.org,plan['id'],origin+'/read-'+str(i),scope['page_url'],tenant.owner))
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):conn.execute(statement,(tenant.org,plan['id'],origin+'/read-20',scope['page_url'],tenant.owner))
    for statement in ['DELETE FROM gabriel_identity.browser_discovered_destinations','UPDATE gabriel_identity.browser_discovered_destinations SET source_url=source_url']:
        with psycopg.connect(tenant.db.app) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):conn.execute(statement)
