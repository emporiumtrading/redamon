"""Real native TLS, PostgreSQL, encrypted bytes and single-use browser claims."""
from concurrent.futures import ThreadPoolExecutor
import base64
import http.client
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import time

import pytest

from gabriel.identity.browser_gateway import BrowserGateway,endpoint,extension_origin,load_gateway,prepare
from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.service import AccessDenied,IdentityUnavailable
from gabriel.identity.tasks import TaskService
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,audit_permission
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_observations_integration import browser,task,payload,CONTENT
from testing.gabriel_identity.tls_lab import certificates

pytestmark=pytest.mark.integration
ORIGIN='chrome-extension://'+'a'*32


@pytest.fixture
def bootstrap(tenant,browser,task,case,context,tmp_path,monkeypatch):
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0))
        port=reserved.getsockname()[1]
    directory=tmp_path/'gateway'
    result=prepare(browser,tenant.token,task['id'],case['id'],context,'https://localhost:'+str(port),ORIGIN,directory,share_observations=True)
    ring=browser.store.keys
    keys=tmp_path/'keys.json'
    write_document(keys,dict(schema_version=1,purpose='evidence-v1',generation=ring.generation,active=ring.active,
        keys={k:base64.b64encode(v).decode() for k,v in ring._keys.items()}))
    monkeypatch.setenv('GABRIEL_EVIDENCE_KEYRING_FILE',str(keys))
    monkeypatch.setenv('GABRIEL_EVIDENCE_ROOT',str(browser.store.root))
    return dict(directory=directory,configuration=read_document(directory/'gateway.json'),result=result,
        ticket=read_document(directory/'claim.json',private=True)['ticket'],peer=read_document(directory/'peer.json',private=True)['token'],
        port=port,tls=certificates(tmp_path))


def call(boot,operation,body,token=None,*,origin=ORIGIN,host=None,raw=None,trust=True):
    context=ssl.create_default_context(cafile=str(boot['tls']['ca.pem'])) if trust else ssl.create_default_context()
    client=http.client.HTTPSConnection('localhost',boot['port'],context=context,timeout=8)
    headers={'Content-Type':'application/json','Origin':origin}
    if host: headers['Host']=host
    if token: headers['Authorization']='Bearer '+token
    try:
        client.request('POST','/v1/browser/'+operation,body=json.dumps(body).encode() if raw is None else raw,headers=headers)
        response=client.getresponse()
        return response.status,json.loads(response.read()),dict(response.getheaders())
    finally: client.close()


@pytest.fixture
def server(bootstrap):
    boot=bootstrap
    process=subprocess.Popen([sys.executable,'-m','gabriel.identity.gateway_cli','serve','--configuration',str(boot['directory']/'gateway.json'),
        '--certificate',str(boot['tls']['server.pem']),'--key',str(boot['tls']['server.key']),'--bind','127.0.0.1:'+str(boot['port'])],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            if process.poll() is not None: raise AssertionError('gateway exited before readiness')
            try:
                call(boot,'heartbeat',{})
                break
            except (OSError,http.client.HTTPException): time.sleep(0.05)
        else: raise AssertionError('native TLS gateway did not become ready')
        yield boot
    finally:
        process.terminate()
        out,err=process.communicate(timeout=10)
        assert boot['peer'] not in out+err and boot['ticket'] not in out+err and CONTENT not in out+err


def claim(boot,context):
    return call(boot,'claim',{'ticket':boot['ticket'],'context':context})


def test_real_tls_claim_observation_and_revocation(tenant,browser,context,payload,server):
    code,response,headers=claim(server,context)
    assert code==200 and headers['Access-Control-Allow-Origin']==ORIGIN and headers['Cache-Control']=='no-store'
    peer=response['result']['token']
    assert peer==server['peer'] and tenant.token not in json.dumps(response)
    assert claim(server,context)[0]==403
    code,response,_=call(server,'observe',payload,peer)
    assert code==200 and response['result']['source_verified'] is False
    assert browser.read_evidence(tenant.token,response['result']['evidence_id']).reveal()==CONTENT.encode()
    assert call(server,'receipts',{'context':context},peer)[1]['result']['observations'][0]['state']=='captured'
    assert call(server,'disconnect',{},peer)[0]==200
    assert call(server,'observe',payload,peer)[0]==403


def test_tls_rejects_untrusted_certificate(server,context):
    with pytest.raises(ssl.SSLCertVerificationError):
        call(server,'claim',{'ticket':server['ticket'],'context':context},trust=False)


def test_concurrent_claim_consumes_exactly_once(server,context):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:claim(server,context),range(2)))
    assert sorted(r[0] for r in results)==[200,403]


@pytest.mark.parametrize('change',['origin','host','scope','ticket','duplicate_json','unknown_operation'])
def test_tls_boundary_denials_do_not_consume_valid_claim(server,context,change):
    body={'ticket':server['ticket'],'context':context}
    kwargs={}
    operation='claim'
    if change=='origin': kwargs['origin']='https://hostile-generated.invalid'
    elif change=='host': kwargs['host']='outside-generated.invalid'
    elif change=='scope': body['context']=dict(context,tab_id=900)
    elif change=='ticket': body['ticket']='gbc1_'+'x'*43
    elif change=='unknown_operation': operation='login'
    else: kwargs['raw']=b'{"ticket":"bad","ticket":"duplicate","context":{}}'
    code,response,headers=call(server,operation,body,**kwargs)
    assert code==403 and response['status']=='denied' and 'token' not in response
    if change=='origin': assert 'Access-Control-Allow-Origin' not in headers
    assert claim(server,context)[0]==200


def test_original_session_loss_denies_network_observation(tenant,browser,server,context,payload):
    assert claim(server,context)[0]==200
    browser.logout(tenant.token)
    assert call(server,'observe',payload,server['peer'])[0]==403
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.browser_observations WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


def test_task_cancel_denies_network_observation(tenant,browser,task,server,context,payload):
    assert claim(server,context)[0]==200
    TaskService(tenant.db.app).end_task(tenant.token,task['id'],'cancelled')
    assert call(server,'observe',payload,server['peer'])[0]==403


def test_audit_failure_cannot_export_peer_or_consume_ticket(tenant,server,context):
    audit_permission(tenant,False)
    try:
        code,response,_=claim(server,context)
        assert code==503 and server['peer'] not in json.dumps(response)
    finally: audit_permission(tenant,True)
    assert claim(server,context)[0]==200


def test_bootstrap_cannot_be_reused_after_gateway_restart(server):
    with pytest.raises(FileExistsError): load_gateway(server['directory']/'gateway.json')


def test_expired_claim_and_changed_original_session(tenant,browser,bootstrap):
    app=load_gateway(bootstrap['directory']/'gateway.json')
    app._started=time.monotonic()-61
    with pytest.raises(AccessDenied): app.dispatch('claim',{'ticket':bootstrap['ticket'],'context':app.context},None)
    app._human=browser.login(tenant.org,'owner',tenant.password).token
    with pytest.raises(AccessDenied): app._bound(pending=True)


@pytest.mark.parametrize('url',['http://localhost','https://user:secret@localhost','https://localhost/path','https://localhost?token=secret',
    'https://localhost#secret','https://LOCALHOST','https://localhost/%25250a','https://localhost:bad'])
def test_endpoint_validation(url):
    with pytest.raises(ValueError): endpoint(url)
