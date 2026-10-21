"""Actual HTTPS workbench forms, live identity, PostgreSQL and encrypted evidence."""
from concurrent.futures import ThreadPoolExecutor
import base64
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode
from uuid import uuid4

import pytest

from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.service import provision_organization
from gabriel.identity.workbench import COOKIE,load_workbench,prepare_workbench
from gabriel.identity.model_budget import ModelBudgetService
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,CONTENT,audit_permission
from testing.gabriel_identity.tls_lab import certificates

pytestmark=pytest.mark.integration


@pytest.fixture
def boot(tenant,cases,tmp_path,monkeypatch,request):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    directory=tmp_path/'workbench'
    target='https://localhost:'+str(port)
    token=tenant.token
    if getattr(request,'param','owner')=='viewer':
        password=secrets.token_urlsafe(24)
        cases.create_member(token,'workbench-viewer',password,'viewer')
        token=cases.login(tenant.org,'workbench-viewer',password).token
    prepare_workbench(cases,token,target,directory)
    keys=tmp_path/'keys.json'
    ring=cases.store.keys
    write_document(keys,dict(schema_version=1,purpose='evidence-v1',generation=ring.generation,active=ring.active,
        keys={k:base64.b64encode(v).decode() for k,v in ring._keys.items()}))
    monkeypatch.setenv('GABRIEL_EVIDENCE_KEYRING_FILE',str(keys))
    monkeypatch.setenv('GABRIEL_EVIDENCE_ROOT',str(cases.store.root))
    from testing.gabriel_identity.test_vault_integration import fresh_ring
    provider_ring=fresh_ring()
    provider_keys=tmp_path/'provider-keyring.json'
    write_document(provider_keys,dict(schema_version=1,generation=provider_ring.generation,active=provider_ring.active,
        keys={k:base64.b64encode(v).decode() for k,v in provider_ring._keys.items()}))
    monkeypatch.setenv('GABRIEL_PROVIDER_KEYRING_FILE',str(provider_keys))
    return dict(directory=directory,port=port,target=target,ticket=read_document(directory/'claim.json',private=True)['ticket'],tls=certificates(tmp_path))


def call(boot,path,fields=None,*,cookie=None,origin=None,headers=None,method=None,raw=None,trust=True):
    context=ssl.create_default_context(cafile=str(boot['tls']['ca.pem'])) if trust else ssl.create_default_context()
    client=http.client.HTTPSConnection('localhost',boot['port'],context=context,timeout=8)
    method=method or ('POST' if fields is not None else 'GET')
    request_headers=dict(headers or {})
    if fields is not None:
        request_headers.setdefault('Content-Type','application/x-www-form-urlencoded')
        request_headers.setdefault('Origin',origin or boot['target'])
    if cookie: request_headers['Cookie']=cookie
    try:
        client.request(method,path,body=raw if raw is not None else urlencode(fields) if fields is not None else None,headers=request_headers)
        response=client.getresponse()
        return response.status,response.read().decode(),dict(response.getheaders())
    finally: client.close()


@pytest.fixture
def server(boot):
    process=subprocess.Popen([sys.executable,'-m','gabriel.identity.workbench_cli','serve','--configuration',str(boot['directory']/'workbench.json'),
        '--certificate',str(boot['tls']['server.pem']),'--key',str(boot['tls']['server.key']),'--bind','127.0.0.1:'+str(boot['port'])],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        end=time.monotonic()+12
        while time.monotonic()<end:
            if process.poll() is not None: raise AssertionError('workbench exited before readiness')
            try:
                if call(boot,'/claim')[0]==200: break
            except OSError: pass
            time.sleep(0.05)
        else: raise AssertionError('workbench TLS readiness failed')
        yield boot
    finally:
        process.terminate()
        out,err=process.communicate(timeout=10)
        assert boot['ticket'] not in out+err and CONTENT not in out+err


def csrf(html): return re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"',html)[1]


def connect(server):
    code,html,_=call(server,'/claim')
    assert code==200
    token=csrf(html)
    code,_,headers=call(server,'/claim',dict(csrf=token,ticket=server['ticket']))
    assert code==303
    return headers['Set-Cookie'].split(';',1)[0],token,headers


def test_customer_provider_screen_stores_nvidia_privately_and_requires_csrf(tenant,server):
    cookie,token,_=connect(server)
    code,html,_=call(server,'/providers',cookie=cookie)
    assert code==200 and 'Your AI keys' in html and '$18 account credit' in html
    assert 'type="password" name="api_key"' in html and 'no shared API key' in html
    value='generated-workbench-key-'+secrets.token_urlsafe(32)
    fields=dict(csrf='wrong',provider='nvidia',api_key=value)
    assert call(server,'/providers/save',fields,cookie=cookie)[0]==403
    fields['csrf']=token
    code,body,headers=call(server,'/providers/save',fields,cookie=cookie)
    assert code==303 and headers['Location']=='/providers' and value not in body+repr(headers)
    code,html,_=call(server,'/providers',cookie=cookie)
    assert code==200 and 'validation pending' in html and value not in html
    with owner_connection(tenant.db) as conn:
        row=conn.execute("SELECT * FROM gabriel_identity.provider_secrets WHERE organization_id=%s AND provider='nvidia'",(tenant.org,)).fetchone()
    assert row and value.encode() not in bytes(row['ciphertext'])
    assert call(server,'/providers/revoke',dict(csrf=token,provider='nvidia'),cookie=cookie)[0]==303
    assert 'revoked' in call(server,'/providers',cookie=cookie)[1]


def test_twelve_role_selector_persists_typed_review_and_shows_uncertainty(tenant,cases,case,evidence,server):
    from testing.gabriel_identity.test_specialist_analysis_integration import intake
    _,holder=intake(tenant,cases,case,evidence)
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/specialists'
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'Specialist assessments' in html
    from gabriel.identity.specialist_contracts import ROLES
    assert all('value="'+role+'"' in html for role in ROLES)
    fields=dict(csrf=token,request_id=str(uuid4()),role='alert_triage',input_evidence_id=str(holder['id']))
    code,_,headers=call(server,path,fields,cookie=cookie)
    assert code==303
    code,html,_=call(server,headers['Location'],cookie=cookie)
    assert code==200 and 'urgent review' in html and 'Attacker status: unknown' in html
    assert 'Hypotheses for review' in html and 'Alternative explanation' in html and 'Uncertainty' in html
    runs=cases.list_specialist_runs(tenant.token,case['id'])['runs']
    assert len(runs)==1 and runs[0]['role']=='alert_triage'


@pytest.mark.parametrize('boot',['viewer'],indirect=True)
def test_provider_forms_are_hidden_and_denied_for_viewer(server):
    cookie,token,_=connect(server)
    assert 'Your AI keys' not in call(server,'/cases',cookie=cookie)[1]
    assert call(server,'/providers',cookie=cookie)[0]==403
    assert call(server,'/providers/save',dict(csrf=token,provider='nvidia',api_key='generated-key'),cookie=cookie)[0]==403


def test_spending_screen_changes_real_limits_and_pauses_reservations(tenant,server):
    cookie,token,_=connect(server)
    code,html,_=call(server,'/spending',cookie=cookie)
    assert code==200 and 'AI spending' in html and '$18.000000' in html and 'Models are not active' in html
    assert tenant.token not in html and server['ticket'] not in html
    fields=dict(csrf=token,month='17.50',day='0.25',investigation='0.025',enabled='no')
    code,_,headers=call(server,'/spending/limits',fields,cookie=cookie)
    assert code==303 and headers['Location']=='/spending'
    limits=ModelBudgetService(tenant.db.app).status(tenant.token)['limits']
    assert limits==dict(enabled=False,month_microusd=17500000,day_microusd=250000,investigation_microusd=25000)
    assert 'New reservations paused' in call(server,'/spending',cookie=cookie)[1]


def test_local_plan_forms_persist_steps_replay_receipts_and_stop(tenant,cases,case,evidence,server):
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/coordinator'
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'Create local plan' in html and 'does not assess an attack' in html
    request=str(uuid4())
    code,_,headers=call(server,path+'/new',dict(csrf=token,request_id=request),cookie=cookie)
    assert code==303
    detail=headers['Location']
    run_id=detail.rsplit('/',1)[1]
    code,_,again=call(server,path+'/new',dict(csrf=token,request_id=request),cookie=cookie)
    assert code==303 and again['Location']==detail
    assert len(cases.list_coordinator_runs(tenant.token,case['id'])['runs'])==1
    assert cases.get_coordinator(tenant.token,run_id)['completed_steps']==0
    for _ in range(2):
        assert call(server,detail+'/next',dict(csrf=token,sequence='1'),cookie=cookie)[0]==303
    state=cases.get_coordinator(tenant.token,run_id)
    assert state['completed_steps']==1 and state['steps'][1]['claimed_at'] is None
    html=call(server,detail,cookie=cookie)[1]
    assert 'Receipt checksum' in html and str(evidence['id']) in html and CONTENT not in html
    assert call(server,detail+'/next',dict(csrf=token,sequence='2'),cookie=cookie)[0]==303
    html=call(server,detail,cookie=cookie)[1]
    assert 'Local checks complete' in html and 'Review telemetry assessment' in html and 'Run next local step' not in html
    assert call(server,detail+'/stop',dict(csrf=token),cookie=cookie)[0]==303
    assert cases.get_coordinator(tenant.token,run_id)['status']=='stopped'
    assert 'Stop this plan' not in call(server,detail,cookie=cookie)[1]
    assert call(server,detail+'/next',dict(csrf=token,sequence='2'),cookie=cookie)[0]==403


@pytest.mark.parametrize('attack',['no_cookie','csrf','origin','extra','sequence','get'])
def test_local_plan_actions_reject_invalid_boundary_without_claim(tenant,cases,case,server,attack):
    run=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/coordinator/'+run['id']+'/next'
    fields=dict(csrf=token,sequence='1')
    kwargs=dict(cookie=cookie)
    if attack=='no_cookie': kwargs={}
    elif attack=='csrf': fields['csrf']='wrong'
    elif attack=='origin': kwargs['origin']='https://unapproved.invalid'
    elif attack=='extra': fields['operation']='external_action'
    elif attack=='sequence': fields['sequence']='3'
    elif attack=='get': fields=None
    assert call(server,path,fields,**kwargs)[0]==403
    assert cases.get_coordinator(tenant.token,run['id'])['steps'][0]['claimed_at'] is None


def test_local_plan_wrong_case_and_foreign_tenant_cannot_mutate(tenant,cases,case,server):
    run=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    other=cases.create_case(tenant.token,'Generated wrong path case')
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated foreign plan','owner',password)
    foreign=cases.login(org,'owner',password).token
    foreign_case=cases.create_case(foreign,'Generated foreign plan case')
    foreign_run=cases.begin_coordinator(foreign,foreign_case['id'],uuid4())
    cookie,token,_=connect(server)
    for case_id,run_id in [(str(other['id']),run['id']),(str(case['id']),foreign_run['id'])]:
        path='/cases/'+case_id+'/coordinator/'+run_id
        assert call(server,path,cookie=cookie)[0]==403
        assert call(server,path+'/stop',dict(csrf=token),cookie=cookie)[0]==403
    assert cases.get_coordinator(tenant.token,run['id'])['status']=='pending_local_steps'
    assert cases.get_coordinator(foreign,foreign_run['id'])['status']=='pending_local_steps'


@pytest.mark.parametrize('boot',['viewer'],indirect=True)
def test_viewer_plan_history_has_no_controls_and_cannot_mutate(tenant,cases,case,server):
    run=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/coordinator'
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and run['id'] in html and 'Create local plan' not in html
    detail=path+'/'+run['id']
    html=call(server,detail,cookie=cookie)[1]
    assert 'Run next local step' not in html and 'Stop this plan' not in html
    assert call(server,path+'/new',dict(csrf=token,request_id=str(uuid4())),cookie=cookie)[0]==403
    assert call(server,detail+'/next',dict(csrf=token,sequence='1'),cookie=cookie)[0]==403
    assert call(server,detail+'/stop',dict(csrf=token),cookie=cookie)[0]==403
    assert cases.get_coordinator(tenant.token,run['id'])['completed_steps']==0


def test_changed_evidence_returns_recovery_guidance_without_completion(tenant,cases,case,server):
    run=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    cases.acquire(tenant.token,case['id'],uuid4(),'Generated later evidence','Generated fixture',approved=True)
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/coordinator/'+run['id']
    code,html,_=call(server,path+'/next',dict(csrf=token,sequence='1'),cookie=cookie)
    assert code==409 and 'evidence set changed' in html and 'create a new plan' in html
    assert cases.get_coordinator(tenant.token,run['id'])['completed_steps']==0


@pytest.mark.parametrize('change',['revoked','closed','expired'])
def test_plan_controls_recheck_current_session_case_and_expiry(tenant,cases,case,evidence,server,change):
    run=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    cookie,token,_=connect(server)
    if change=='revoked': cases.logout(tenant.token)
    elif change=='closed':
        from gabriel.identity.actions import ActionService
        actions=ActionService(tenant.db.app,cases.store)
        actions.set_policy(tenant.token,distinct_approver=False)
        action=actions.propose_close(tenant.token,case['id'],uuid4(),'Generated reviewed closure for access test')
        actions.submit(tenant.token,action['id'])
        actions.approve(tenant.token,action['id'],action['digest'])
        cases.close_case(tenant.token,case['id'],approval_id=action['id'])
        assert cases.get_case(tenant.token,case['id'])['case']['state']=='closed'
    else:
        with owner_connection(tenant.db) as conn:
            conn.execute("UPDATE gabriel_identity.coordinator_runs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE id=%s",(run['id'],))
    path='/cases/'+str(case['id'])+'/coordinator/'+run['id']
    assert call(server,path+'/next',dict(csrf=token,sequence='1'),cookie=cookie)[0]==403
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.coordinator_claims WHERE run_id=%s',(run['id'],)).fetchone()['n']==0


@pytest.mark.parametrize('amount',['20','NaN','1e0','-1','0','0.0000001'])
def test_spending_form_refuses_invalid_or_excess_limit_without_change(tenant,server,amount):
    cookie,token,_=connect(server)
    fields=dict(csrf=token,month=amount,day='0.50',investigation='0.05',enabled='yes')
    assert call(server,'/spending/limits',fields,cookie=cookie)[0]==403
    assert ModelBudgetService(tenant.db.app).status(tenant.token)['limits']['month_microusd']==18000000


@pytest.mark.parametrize('boot',['viewer'],indirect=True)
def test_viewer_can_read_spending_but_cannot_change_it(tenant,server):
    cookie,token,_=connect(server)
    code,html,_=call(server,'/spending',cookie=cookie)
    assert code==200 and 'Save spending controls' not in html
    assert call(server,'/spending/limits',dict(csrf=token,month='1',day='0.1',investigation='0.01',enabled='no'),cookie=cookie)[0]==403
    assert ModelBudgetService(tenant.db.app).status(tenant.token)['limits']['enabled']


def test_spending_form_requires_current_cookie_csrf_and_exact_origin(tenant,server):
    cookie,token,_=connect(server)
    fields=dict(csrf=token,month='1',day='0.1',investigation='0.01',enabled='no')
    assert call(server,'/spending/limits',fields)[0]==403
    assert call(server,'/spending/limits',{**fields,'csrf':'wrong'},cookie=cookie)[0]==403
    assert call(server,'/spending/limits',fields,cookie=cookie,origin='https://unapproved.invalid')[0]==403
    assert ModelBudgetService(tenant.db.app).status(tenant.token)['limits']['enabled']


def test_https_case_report_custody_and_explicit_content_view(tenant,cases,case,evidence,server):
    cookie,token,headers=connect(server)
    assert all(value in headers['Set-Cookie'] for value in ('Secure','HttpOnly','SameSite=Strict','Path=/'))
    code,html,headers=call(server,'/cases',cookie=cookie)
    assert code==200 and str(tenant.org) in html and case['title'] in html
    assert headers['Cache-Control']=='no-store' and "default-src 'none'" in headers['Content-Security-Policy']
    assert tenant.token not in html and server['ticket'] not in html and CONTENT not in html
    path='/cases/'+str(case['id'])
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'unverified_supplied' in html and 'not performed' in html and CONTENT not in html
    code,report,headers=call(server,path+'/report',cookie=cookie)
    assert code==200 and headers['Content-Type']=='application/json'
    assert json.loads(report)['snapshot']['evidence'][0]['id']==str(evidence['id'])
    assert CONTENT not in report
    path+='/evidence/'+str(evidence['id'])
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'acquired' in html and CONTENT not in html
    assert call(server,path+'/content',cookie=cookie)[0]==403
    code,html,_=call(server,path+'/content',dict(csrf=token),cookie=cookie)
    assert code==200 and CONTENT in html
    assert cases.custody(tenant.token,evidence['id'])[-1]['event']=='accessed'
    code,html,_=call(server,'/audit',cookie=cookie)
    assert code==200 and 'evidence.accessed' in html and CONTENT not in html and tenant.token not in html
    code,html,_=call(server,'/sources',cookie=cookie)
    assert code==200 and 'No browser sessions recorded' in html
    assert call(server,'/disconnect',dict(csrf=token),cookie=cookie)[0]==200
    assert call(server,'/cases',cookie=cookie)[0]==403


@pytest.mark.parametrize('boot',['owner','viewer'],indirect=True)
def test_provenance_screen_and_download_use_actual_case_metadata(tenant,cases,case,evidence,server):
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])
    code,html,_=call(server,path+'/relationships',cookie=cookie)
    assert code==200 and 'Case provenance' in html and 'contains evidence' in html
    assert CONTENT not in html and tenant.token not in html
    code,body,headers=call(server,path+'/graph',cookie=cookie)
    graph=json.loads(body)['projection']
    assert code==200 and headers['Content-Type']=='application/json'
    assert {node['record_id'] for node in graph['nodes']}=={str(case['id']),str(evidence['id'])}
    assert graph['assessment']=='not_performed' and CONTENT not in body
    assert call(server,path+'/graph',dict(csrf=token),cookie=cookie)[0]==403
    password=secrets.token_urlsafe(24)
    organization,_=provision_organization(tenant.db.owner,'Generated foreign graph owner','owner',password)
    other=cases.login(organization,'owner',password).token
    other_case=cases.create_case(other,'Generated foreign graph case')
    for view in ('relationships','graph'):
        assert call(server,'/cases/'+str(other_case['id'])+'/'+view,cookie=cookie)[0]==403


def test_case_form_persists_one_case_under_concurrent_replay(tenant,cases,server):
    cookie,token,_=connect(server)
    code,html,_=call(server,'/cases/new',cookie=cookie)
    assert code==200
    nonce=re.search(r'name="nonce" value="([A-Za-z0-9_-]+)"',html)[1]
    fields=dict(csrf=token,nonce=nonce,title='Generated <script>alert(1)</script> case')
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:call(server,'/cases',fields,cookie=cookie),range(2)))
    assert sorted(row[0] for row in results)==[303,403]
    rows=cases.list_cases(tenant.token)
    assert len(rows)==1 and rows[0]['title']==fields['title']
    code,html,_=call(server,'/cases/'+str(rows[0]['id']),cookie=cookie)
    assert code==200 and '<script>alert(1)</script>' not in html and '&lt;script&gt;' in html


def test_telemetry_specialist_forms_persist_history_with_csrf_and_role_checks(tenant,cases,case,server):
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/specialists'
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'No specialist assessments recorded' in html
    request=re.search(r'name="request_id" value="([0-9a-f-]+)"',html)[1]
    fields=dict(csrf=token,request_id=request,role='telemetry_health')
    assert call(server,path,dict(fields,csrf='bad'),cookie=cookie)[0]==403
    assert not cases.list_specialist_runs(tenant.token,case['id'])['runs']
    code,_,headers=call(server,path,fields,cookie=cookie)
    assert code==303
    code,html,_=call(server,headers['Location'],cookie=cookie)
    assert code==200 and 'Attacker status: unknown' in html and 'No model was called' in html
    assert CONTENT not in html and tenant.token not in html
    assert call(server,path,fields,cookie=cookie)[0]==303
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1
    assert call(server,path,dict(fields,request_id=str(uuid4()),role='threat_hunting'),cookie=cookie)[0]==403


def test_memory_forms_require_review_and_forget_does_not_erase_source(tenant,cases,case,evidence,server):
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/memory'
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'No memory references recorded' in html and 'source evidence' in html
    request=re.search(r'name="request_id" value="([0-9a-f-]+)"',html)[1]
    fields=dict(csrf=token,request_id=request,evidence_id=str(evidence['id']),kind='fact',scope='case',topic='generated.web-memory',supersedes='')
    assert call(server,path+'/propose',dict(fields,csrf='bad'),cookie=cookie)[0]==403
    assert call(server,path+'/propose',fields,cookie=cookie)[0]==303
    record=cases.list_memory(tenant.token,case['id'])['records'][0]
    assert record['status']=='proposed' and not cases.retrieve_memory(tenant.token,case['id'])
    review=dict(csrf=token,memory_id=record['id'],decision='approved',expected_digest=record['source_digest'])
    assert call(server,path+'/review',review,cookie=cookie)[0]==403
    assert call(server,path+'/review',dict(review,acknowledged='yes'),cookie=cookie)[0]==303
    assert cases.retrieve_memory(tenant.token,case['id'])[0].metadata['id']==record['id']
    assert call(server,path+'/forget',dict(csrf=token,memory_id=record['id']),cookie=cookie)[0]==303
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    assert call(server,path+'/reset',dict(csrf=token,epoch='0'),cookie=cookie)[0]==303


@pytest.mark.parametrize('attack',['missing_csrf','wrong_origin','null_origin','duplicate_field','forwarding','wrong_host','query','cross_site','duplicate_cookie','get_body','json','unknown_route'])
def test_boundary_denials_do_not_create_case(tenant,cases,server,attack):
    cookie,token,_=connect(server)
    _,form,_=call(server,'/cases/new',cookie=cookie)
    nonce=re.search(r'name="nonce" value="([A-Za-z0-9_-]+)"',form)[1]
    path='/cases'
    fields=dict(csrf=token,nonce=nonce,title='Denied generated case')
    kwargs=dict(cookie=cookie)
    if attack=='missing_csrf': fields.pop('csrf')
    elif attack=='wrong_origin': kwargs['origin']='https://generated-hostile.invalid'
    elif attack=='null_origin': kwargs['origin']='null'
    elif attack=='duplicate_field': kwargs['raw']=urlencode(fields)+'&csrf='+token
    elif attack=='forwarding': kwargs['headers']={'X-Forwarded-Proto':'https'}
    elif attack=='wrong_host': kwargs['headers']={'Host':'generated-hostile.invalid'}
    elif attack=='query': path+='?ticket=blocked'
    elif attack=='cross_site': kwargs['headers']={'Sec-Fetch-Site':'cross-site'}
    elif attack=='duplicate_cookie': kwargs['cookie']=cookie+'; '+cookie
    elif attack=='get_body': kwargs.update(method='GET',raw='body')
    elif attack=='json': kwargs['headers']={'Content-Type':'application/json'}
    else: path='/admin/execute'
    assert call(server,path,fields,**kwargs)[0]==403
    assert not cases.list_cases(tenant.token)


def test_wrong_ticket_and_claim_replay(tenant,server):
    _,html,_=call(server,'/claim')
    token=csrf(html)
    assert call(server,'/claim',dict(csrf=token,ticket='gwt1_'+'a'*43))[0]==403
    cookie,_,_=connect(server)
    assert call(server,'/claim',dict(csrf=token,ticket=server['ticket']))[0]==403
    assert call(server,'/cases',cookie=cookie)[0]==200


def test_original_logout_denies_existing_cookie(tenant,cases,case,server):
    cookie,_,_=connect(server)
    cases.logout(tenant.token)
    code,html,_=call(server,'/cases/'+str(case['id']),cookie=cookie)
    assert code==403 and case['title'] not in html


def test_foreign_case_is_denied(tenant,cases,server):
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated foreign workbench','owner',password)
    foreign=cases.login(org,'owner',password).token
    case=cases.create_case(foreign,'Generated foreign case')
    cookie,_,_=connect(server)
    code,html,_=call(server,'/cases/'+str(case['id']),cookie=cookie)
    assert code==403 and case['title'] not in html


def test_audit_failure_cannot_issue_cookie(tenant,server):
    _,html,_=call(server,'/claim')
    audit_permission(tenant,False)
    try:
        code,_,headers=call(server,'/claim',dict(csrf=csrf(html),ticket=server['ticket']))
        assert code==503 and 'Set-Cookie' not in headers
    finally: audit_permission(tenant,True)
    assert connect(server)[0].startswith(COOKIE+'=')


def test_restart_cannot_resurrect_bootstrap(server):
    with pytest.raises(FileExistsError): load_workbench(server['directory']/'workbench.json')


def test_tls_requires_trust(server):
    with pytest.raises(ssl.SSLCertVerificationError): call(server,'/claim',trust=False)


@pytest.mark.parametrize('boot',['viewer'],indirect=True)
def test_viewer_can_read_metadata_but_not_create_or_reveal_content(tenant,cases,case,evidence,server):
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/evidence/'+str(evidence['id'])
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'View evidence content' not in html
    assert call(server,path+'/content',dict(csrf=token),cookie=cookie)[0]==403
    assert call(server,'/cases/new',cookie=cookie)[0]==403
    assert call(server,'/audit',cookie=cookie)[0]==403
    assert call(server,'/sources',cookie=cookie)[0]==200
    assert len(cases.list_cases(tenant.token))==1


def test_evidence_html_is_escaped(tenant,cases,case,server):
    content='<img src=x onerror=alert(1)> Generated hostile artifact'
    from uuid import uuid4
    artifact=cases.acquire(tenant.token,case['id'],uuid4(),content,'Generated HTML fixture',approved=True)
    cookie,token,_=connect(server)
    path='/cases/'+str(case['id'])+'/evidence/'+str(artifact['id'])+'/content'
    code,html,_=call(server,path,dict(csrf=token),cookie=cookie)
    assert code==200 and content not in html and '&lt;img src=x onerror=alert(1)&gt;' in html


def test_operator_cli_prepares_exclusive_private_files(tenant,boot,tmp_path):
    token=tmp_path/'operator-session'
    token.write_text(tenant.token)
    token.chmod(0o600)
    directory=tmp_path/'cli-workbench'
    command=[sys.executable,'-m','gabriel.identity.workbench_cli','prepare','--token-file',str(token),'--endpoint',boot['target'],'--directory',str(directory)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=10)
    assert result.returncode==0 and tenant.token not in result.stdout+result.stderr
    original=(directory/'claim.json').read_bytes()
    assert directory.stat().st_mode&0o777==0o700
    assert (directory/'human.json').stat().st_mode&0o777==0o600
    assert subprocess.run(command,capture_output=True,timeout=10).returncode==1
    assert (directory/'claim.json').read_bytes()==original
