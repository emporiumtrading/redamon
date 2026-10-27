"""Real tenant/crypto/agent-loop tests; simulated responses never qualify a model."""
from copy import deepcopy
import json
import secrets
from uuid import uuid4

import pytest

from gabriel.identity import model_routes,model_worker,personal_providers,specialist_agents as agents
from gabriel.identity.model_protocol import ProbeError
from gabriel.identity.service import AccessDenied,AuthenticationDenied
from gabriel.identity.vault import ProviderVault,ProviderKeyRing
from testing.gabriel_identity.test_browser_monitoring_integration import database
from testing.gabriel_identity.test_identity_integration import tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence
from testing.gabriel_identity.test_vault_integration import fresh_ring
from testing.gabriel_identity.test_specialist_analysis_integration import intake
from testing.gabriel_identity.test_specialist_analysis import CASES

pytestmark=pytest.mark.integration


@pytest.fixture
def setup(tenant,cases,monkeypatch):
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'generated-agent-analyst',password,'analyst')
    token=cases.login(tenant.org,'generated-agent-analyst',password).token
    vault=ProviderVault(tenant.db.app,fresh_ring())
    personal=personal_providers.PersonalProviders(vault)
    secret='generated-personal-'+secrets.token_urlsafe(30)
    posts=[]
    class Client:
        unknown=False;callback=None;bad_tool=False;always_tool=False;chosen_tool='review_rules'
        credentials=[]
        def __init__(self,credential):type(self).credentials.append(credential.reveal())
        def request(self,method,path,payload=None):
            if path=='/api/v1/key':return dict(data=dict(is_management_key=False,is_provisioning_key=False,
                limit=18,limit_reset='monthly',usage_daily=0,usage_monthly=0,limit_remaining=18))
            if path=='/api/v1/credits':return dict(data=dict(total_credits=20,total_usage=0))
            if path=='/api/v1/endpoints/zdr':return dict(data=[dict(model_id=agents.DEFAULT_MODEL,
                provider_name='Cerebras',tag='cerebras/fp16',status=0,
                supported_parameters=['temperature','response_format','max_tokens','reasoning'],
                pricing=dict(prompt='0.0000003',completion='0.000003',request=0))])
            assert method=='POST' and path=='/api/v1/chat/completions'
            posts.append(payload)
            if type(self).callback:type(self).callback()
            if type(self).unknown:raise ProbeError('provider_transport_unresolved')
            packet=json.loads(payload['messages'][1]['content'])
            action=['external-execute'] if type(self).bad_tool else [type(self).chosen_tool] if type(self).chosen_tool not in {t['tool'] for t in packet['tool_results']} or type(self).always_tool else []
            decision=dict(disposition='abstain',claims=[dict(id='claim-1',statement='Generated role-scoped evidence requires review.',references=[packet['observations'][0]['id']])],
                alternatives=['An approved administrative explanation remains possible.'],contradictions=['No independent source corroboration supplied.'],
                uncertainty=['Source semantics remain unverified.'],reported_gaps=['source-unverified'],requested_actions=action)
            return dict(id='fixture-agent',model=agents.DEFAULT_MODEL,provider='Cerebras',
                choices=[dict(finish_reason='stop',message=dict(content=json.dumps(decision)))],usage=dict(prompt_tokens=1000,completion_tokens=200,cost=.0002))
    monkeypatch.setattr(model_worker,'OpenRouterTransport',Client)
    monkeypatch.setattr(personal_providers,'OpenRouterTransport',Client)
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset(agents.digest(agents.configuration(role)) for role in agents.ROLES))
    personal.configure(token,'openrouter',secret)
    return dict(token=token,vault=vault,personal=personal,secret=secret,posts=posts,client=Client)


def start(setup,cases,case,holder,role='alert_triage',request=None,**kwargs):
    return agents.start(cases,setup['vault'],setup['token'],case['id'],request or uuid4(),role,holder['id'],approved=True,**kwargs)


@pytest.mark.parametrize('role,kind,data,expected,urgency',CASES)
def test_every_specialist_reasons_uses_local_tool_and_persists_answer(tenant,cases,case,evidence,setup,role,kind,data,expected,urgency):
    doc,holder=intake(tenant,cases,case,evidence,kind,data)
    request=uuid4();result=start(setup,cases,case,holder,role,request)
    assert result['state']=='completed_requires_review' and result['model_used']
    assert len(result['steps'])==2 and len(setup['posts'])==2
    assert agents.readiness(role)['model_enabled']
    first,second=[json.loads(p['messages'][1]['content']) for p in setup['posts']]
    assert first['role']==role
    rules=next(t for t in second['tool_results'] if t['tool']=='review_rules')
    assert expected in rules['result']['observations'][0]
    if kind=='exposure':assert first['tool_results'][0]['tool']=='assess_exposure'
    wire=json.dumps(setup['posts'])
    for private in [setup['secret'],str(case['id']),str(evidence['id']),doc['facts'][0]['id'],doc['facts'][0]['entity_id']]:assert private not in wire
    answer=json.loads(cases.read_evidence(setup['token'],result['steps'][-1]['answer_evidence_id']).reveal())
    assert answer['local_manifest']['job_id']==result['job_id']
    replay=start(setup,cases,case,holder,role,request)
    assert all(s['historical'] for s in replay['steps']) and len(setup['posts'])==2
    from gabriel.identity.model_budget import ModelBudgetService
    usage=ModelBudgetService(cases._dsn).status(setup['token'])['usage']
    assert usage['held_slots']==0 and usage['day_used']==12608


def test_personal_keys_are_user_scoped_and_no_fallback_exists(tenant,cases,case,evidence,setup,monkeypatch):
    assert setup['personal'].status(tenant.token)==[]
    with pytest.raises(AccessDenied):setup['personal'].resolve(tenant.token)
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'second-agent-analyst',password,'analyst')
    other=cases.login(tenant.org,'second-agent-analyst',password).token
    assert setup['personal'].status(other)==[]
    monkeypatch.setenv('OPENROUTER_API_KEY',setup['secret'])
    with pytest.raises(AccessDenied):setup['personal'].resolve(other)
    with owner_connection(tenant.db) as conn:
        row=conn.execute('SELECT * FROM gabriel_identity.personal_provider_secrets WHERE organization_id=%s',(tenant.org,)).fetchone()
        assert setup['secret'].encode() not in bytes(row['ciphertext'])
    assert setup['personal'].resolve(setup['token'])[0].reveal()==setup['secret']


def test_analyst_cannot_use_organization_key_or_manage_global_budget(tenant,cases,case,evidence,setup):
    _,holder=intake(tenant,cases,case,evidence)
    with pytest.raises(AccessDenied,match='organization_provider_admin'):start(setup,cases,case,holder,key_scope='organization')
    from gabriel.identity.model_budget import ModelBudgetService
    with pytest.raises(AccessDenied):ModelBudgetService(cases._dsn).configure(setup['token'],enabled=True)
    assert not setup['posts']


def test_missing_consent_and_unqualified_config_never_dispatch(tenant,cases,case,evidence,setup,monkeypatch):
    _,holder=intake(tenant,cases,case,evidence)
    with pytest.raises(AccessDenied,match='consent_required'):
        agents.start(cases,setup['vault'],setup['token'],case['id'],uuid4(),'alert_triage',holder['id'])
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset())
    with pytest.raises(AccessDenied,match='not_production_admitted'):start(setup,cases,case,holder)
    assert not setup['posts'] and not agents.readiness('alert_triage')['model_enabled']


def test_unknown_outcome_is_not_repeated(tenant,cases,case,evidence,setup):
    _,holder=intake(tenant,cases,case,evidence);request=uuid4();setup['client'].unknown=True
    with pytest.raises(ProbeError):start(setup,cases,case,holder,request=request)
    with pytest.raises(AccessDenied,match='unresolved_no_resend'):start(setup,cases,case,holder,request=request)
    assert len(setup['posts'])==1


@pytest.mark.parametrize('change',['key_revoke','logout','stop'])
def test_live_revocation_suppresses_returned_answer(tenant,cases,case,evidence,setup,change):
    _,holder=intake(tenant,cases,case,evidence)
    def revoke():
        if change=='key_revoke':setup['personal'].revoke(setup['token'])
        elif change=='logout':cases.logout(setup['token'])
        else:
            jobs=agents.history(cases,setup['token'],case['id']);agents.stop(cases,setup['token'],jobs[0]['id'])
    setup['client'].callback=revoke
    with pytest.raises((AccessDenied,AuthenticationDenied)):start(setup,cases,case,holder)
    assert len(setup['posts'])==1


def test_unapproved_tool_never_executes_and_repeated_read_stops_loop(tenant,cases,case,evidence,setup):
    _,holder=intake(tenant,cases,case,evidence);setup['client'].bad_tool=True
    with pytest.raises(ProbeError,match='tool_not_admitted'):start(setup,cases,case,holder)
    setup['client'].bad_tool=False;setup['client'].always_tool=True
    result=start(setup,cases,case,holder)
    assert result['state']=='bounded_loop_stopped_requires_review' and len(result['steps'])==2
    assert len(setup['posts'])==3


def test_autonomous_orchestration_cannot_bypass_required_hermes(tenant,cases,case,evidence,setup,monkeypatch):
    from gabriel.identity import hermes_bridge
    monkeypatch.setattr(hermes_bridge,'health',lambda:dict(status='ready'))
    _,holder=intake(tenant,cases,case,evidence,kind='identity',data=dict(event='mfa_disabled',authorized='no'))
    with pytest.raises(AccessDenied,match='hermes_preflight_blocked'):
        agents.orchestrate(cases,setup['vault'],setup['token'],case['id'],uuid4(),holder['id'],approved=True)
    assert not setup['posts']


def test_provider_rotation_rewraps_personal_secrets(tenant,cases,setup):
    old=setup['vault']._ring
    ring=ProviderKeyRing('new_personal_key',{**dict(old._keys),'new_personal_key':secrets.token_bytes(32)},old.generation+1)
    vault=ProviderVault(cases._dsn,ring)
    assert vault.rotate(tenant.token)['rewrapped']==1
    assert personal_providers.PersonalProviders(vault).resolve(setup['token'])[0].reveal()==setup['secret']


def test_another_member_cannot_resume_or_stop_a_personal_agent(tenant,cases,case,evidence,setup):
    _,holder=intake(tenant,cases,case,evidence)
    result=start(setup,cases,case,holder)
    with pytest.raises(AccessDenied,match='not_owned'):agents.resume(cases,setup['vault'],tenant.token,result['job_id'])
    with pytest.raises(AccessDenied,match='not_owned'):agents.stop(cases,tenant.token,result['job_id'])
    assert len(setup['posts'])==2


def test_workbench_stop_is_not_blocked_by_agent_provider_io(tenant,cases,case,evidence,setup,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from io import BytesIO
    from threading import Event
    from urllib.parse import urlencode
    from gabriel.identity.workbench import Workbench,COOKIE,ticket_hash
    app=Workbench(cases,setup['token'],dict(endpoint='https://localhost:8444',ticket_digest=ticket_hash('gwt1_'+'a'*43)),provider_vault=setup['vault'])
    app._cookie='generated-agent-ui-cookie';app._claimed=True
    active=Event();release=Event()
    def slow(*args,**kwargs):
        active.set();assert release.wait(5)
        return dict(state='generated_completed',steps=[])
    def stop(*args,**kwargs):release.set();return dict(stopped=True)
    monkeypatch.setattr(agents,'start',slow);monkeypatch.setattr(agents,'stop',stop)
    _,holder=intake(tenant,cases,case,evidence)
    def post(path,fields):
        raw=urlencode(dict(csrf=app._csrf,**fields)).encode();observed=[]
        env=dict(REQUEST_METHOD='POST',PATH_INFO=path,CONTENT_TYPE='application/x-www-form-urlencoded',
            CONTENT_LENGTH=str(len(raw)),HTTP_HOST='localhost:8444',HTTP_ORIGIN='https://localhost:8444',
            HTTP_COOKIE=COOKIE+'='+app._cookie,**{'wsgi.url_scheme':'https','wsgi.input':BytesIO(raw)})
        app(env,lambda status,headers:observed.append(status))
        return observed[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        running=pool.submit(post,'/cases/'+str(case['id'])+'/agents',dict(request_id=str(uuid4()),role='alert_triage',input_evidence_id=str(holder['id']),model=agents.DEFAULT_MODEL,key_scope='personal',approved='yes'))
        try:
            assert active.wait(3)
            stopped=pool.submit(post,'/cases/'+str(case['id'])+'/agents/'+str(uuid4())+'/stop',{})
            assert stopped.result(timeout=2)=='200 OK'
        finally:release.set()
        assert running.result(timeout=3)=='200 OK'


def test_memory_read_tool_without_supported_history_exports_no_contents(tenant,cases,case,evidence,setup):
    _,holder=intake(tenant,cases,case,evidence,kind='recovery',data=dict(check='restore',result='fail',baseline='current'))
    setup['client'].chosen_tool='review_memory'
    result=start(setup,cases,case,holder,role='recovery_learning')
    assert result['state']=='completed_requires_review'
    context=json.loads(setup['posts'][1]['messages'][1]['content'])['tool_results'][0]
    assert context['tool']=='review_memory' and context['result']['state']=='no_supported_references'
    assert context['result']['historical_assertions']==[] and not context['result']['contents_exported']
    assert not context['result']['free_text_exported'] and not context['result']['model_training_performed']


def test_personal_ciphertext_is_cryptographically_bound_to_its_owner(tenant,cases,setup):
    from gabriel.identity.vault import SecretUnavailable
    with owner_connection(tenant.db) as conn:
        conn.execute('UPDATE gabriel_identity.personal_provider_secrets SET user_id=%s WHERE organization_id=%s',(tenant.owner,tenant.org))
    with pytest.raises(SecretUnavailable):setup['personal'].resolve(tenant.token)


@pytest.mark.parametrize('column',['nonce','ciphertext'])
def test_active_personal_key_requires_complete_encrypted_material(tenant,setup,column):
    import psycopg
    from psycopg import sql
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(sql.SQL('UPDATE gabriel_identity.personal_provider_secrets SET {}=NULL WHERE organization_id=%s').format(sql.Identifier(column)),(tenant.org,))
