"""Finite WSGI navigation routes with real PostgreSQL authority and generated contracts."""
import io
import json
from uuid import uuid4

import pytest

from gabriel.identity.browser_gateway import BrowserGateway
from gabriel.identity.browser_navigation import BrowserNavigationService,CONTRACTS
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_observations_integration import task,payload,rows
from testing.gabriel_identity.test_browser_gateway_integration import bootstrap,ORIGIN

pytestmark=pytest.mark.integration
DESTINATION='https://generated-console.invalid/security#traffic'
VERSION='generated-gateway-navigation-v1'


@pytest.fixture
def browser(tenant,cases):
    return BrowserNavigationService(tenant.db.app,cases.store)


def request(app,operation,body,*,token=None,origin=ORIGIN):
    data=json.dumps(body).encode();status=[]
    environ={'wsgi.url_scheme':'https','HTTP_HOST':app.target.removeprefix('https://'),
        'HTTP_ORIGIN':origin,'PATH_INFO':'/v1/browser/'+operation,'REQUEST_METHOD':'POST',
        'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(data)),'wsgi.input':io.BytesIO(data)}
    if token is not None: environ['HTTP_AUTHORIZATION']='Bearer '+token
    response=b''.join(app(environ,lambda result,headers:status.append(result)))
    return status[0],json.loads(response)


@pytest.fixture
def gateway(tenant,browser,bootstrap,context):
    app=BrowserGateway(browser,tenant.token,bootstrap['peer'],bootstrap['configuration'])
    status,_=request(app,'claim',dict(ticket=bootstrap['ticket'],context=context))
    assert status=='200 OK'
    return app


@pytest.fixture
def navigation(tenant,browser,bootstrap,gateway,context,monkeypatch):
    monkeypatch.setitem(CONTRACTS,VERSION,{'/security#events','/security#traffic'})
    return browser.grant_navigation(tenant.token,bootstrap['peer'],uuid4(),VERSION,[DESTINATION,context['page_url']])


def prepare(gateway,bootstrap,context):
    status,result=request(gateway,'navigation-prepare',dict(context=context,request_id=str(uuid4()),destination_url=DESTINATION),token=bootstrap['peer'])
    assert status=='200 OK'
    return result['result']


def test_gateway_tracks_only_receipted_context_and_rejects_stale_capture(tenant,browser,gateway,bootstrap,navigation,context,payload):
    intent=prepare(gateway,bootstrap,context)
    assert not intent['dispatch_performed']
    assert request(gateway,'observe',payload,token=bootstrap['peer'])[0]=='403 Forbidden'
    target=dict(context,page_url=DESTINATION,document_id=str(uuid4()))
    status,result=request(gateway,'navigation-complete',dict(intent_id=intent['id'],context=target),token=bootstrap['peer'])
    assert status=='200 OK' and result['result']['current'] and gateway.context==target
    assert tenant.token not in json.dumps(result) and bootstrap['peer'] not in json.dumps(result)
    assert request(gateway,'heartbeat',dict(context=context),token=bootstrap['peer'])[0]=='403 Forbidden'
    assert request(gateway,'observe',dict(payload,context=target),token=bootstrap['peer'])[0]=='200 OK'
    replay=request(gateway,'navigation-complete',dict(intent_id=intent['id'],context=target),token=bootstrap['peer'])
    assert replay[0]=='200 OK' and replay[1]['result']['replayed']
    assert len(rows(tenant,'browser_navigation_commits'))==1


def test_gateway_never_accepts_grant_or_unpaired_navigation(gateway,bootstrap,context):
    assert not CONTRACTS
    body=dict(context=context,request_id=str(uuid4()),destination_url=DESTINATION)
    assert request(gateway,'navigation-grant',body,token=bootstrap['peer'])[0]=='403 Forbidden'
    assert request(gateway,'navigation-prepare',body,token=bootstrap['peer'])[0]=='403 Forbidden'
    assert request(gateway,'navigation-prepare',body)[0]=='403 Forbidden'
    assert request(gateway,'navigation-prepare',body,token=bootstrap['peer'],origin='https://generated-untrusted.invalid')[0]=='403 Forbidden'


def test_configuration_anchor_and_latest_receipt_required(tenant,browser,gateway,bootstrap,navigation,context):
    intent=prepare(gateway,bootstrap,context)
    target=dict(context,page_url=DESTINATION,document_id=str(uuid4()))
    browser.complete_navigation(tenant.token,bootstrap['peer'],intent['id'],target)
    # A file's asserted context cannot become a new anchor for an existing grant.
    changed=dict(bootstrap['configuration'],context=dict(context,account_label='Different generated account'))
    foreign=BrowserGateway(browser,tenant.token,bootstrap['peer'],changed)
    foreign._claimed=True
    assert request(foreign,'heartbeat',dict(context=target),token=bootstrap['peer'])[0]=='403 Forbidden'
    assert request(gateway,'heartbeat',dict(context=target),token=bootstrap['peer'])[0]=='200 OK'
    with owner_connection(tenant.db) as conn:
        conn.execute('DELETE FROM gabriel_identity.browser_navigation_commits WHERE organization_id=%s',(tenant.org,))
    assert request(gateway,'heartbeat',dict(context=target),token=bootstrap['peer'])[0]=='403 Forbidden'
    assert request(gateway,'disconnect',{},token=bootstrap['peer'])[0]=='200 OK'


def test_disconnect_survives_contract_withdrawal(tenant,browser,gateway,bootstrap,navigation,context,monkeypatch):
    intent=prepare(gateway,bootstrap,context)
    target=dict(context,page_url=DESTINATION,document_id=str(uuid4()))
    assert request(gateway,'navigation-complete',dict(intent_id=intent['id'],context=target),token=bootstrap['peer'])[0]=='200 OK'
    monkeypatch.delitem(CONTRACTS,VERSION)
    assert request(gateway,'status',dict(context=target),token=bootstrap['peer'])[0]=='403 Forbidden'
    assert request(gateway,'disconnect',{},token=bootstrap['peer'])[0]=='200 OK'
    assert request(gateway,'heartbeat',dict(context=target),token=bootstrap['peer'])[0]=='403 Forbidden'
