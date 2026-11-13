"""Real Hermes SDK/service, PostgreSQL, keys and specialist loops; no paid calls."""
import json
import os
from uuid import uuid4

import pytest

from gabriel.identity import hermes_bridge as bridge,hermes_supervisor as hermes,model_routes,model_worker
from gabriel.identity.service import AccessDenied,AuthenticationDenied,connection
from testing.gabriel_identity.test_identity_integration import tenant,owner_connection
from testing.gabriel_identity.test_browser_monitoring_integration import database
from testing.gabriel_identity.test_cases_integration import cases,case,evidence
from testing.gabriel_identity.test_specialist_analysis_integration import intake
from testing.gabriel_identity.test_specialist_agents_integration import setup

pytestmark=pytest.mark.integration


@pytest.fixture(autouse=True)
def native_runtime():
    try:assert bridge.health()['status']=='ready'
    except (AccessDenied,AssertionError):
        if os.environ.get('GABRIEL_REQUIRE_HERMES')=='1':pytest.fail('required_native_hermes_service_missing')
        pytest.skip('private native Hermes service required')


@pytest.fixture
def supervision(setup,monkeypatch):
    base=setup['client']
    class Client(base):
        selected=['incident_scoping','identity_access'];hermes_callback=None
        def request(self,method,path,payload=None):
            packet=json.loads(payload['messages'][1]['content']) if method=='POST' else {}
            if 'stage' not in packet:return super().request(method,path,payload)
            setup['posts'].append(payload)
            if type(self).hermes_callback:type(self).hermes_callback()
            row=dict(disposition='abstain',claims=[dict(id='claim-1',statement='The supplied identity assertion requires independent review.',references=['o1'])],
                alternatives=['Authorized administrative activity is possible.'],contradictions=['No independent corroboration supplied.'],
                uncertainty=['Partial source assertions remain unverified.'],reported_gaps=['source-unverified'],
                requested_actions=list(type(self).selected) if packet['stage']=='plan' else [])
            return dict(id='fixture-hermes-'+packet['stage'],model=hermes.DEFAULT_MODEL,provider='Cerebras',
                choices=[dict(finish_reason='stop',message=dict(content=json.dumps(row)))],usage=dict(prompt_tokens=1000,completion_tokens=200,cost=.0002))
    monkeypatch.setattr(model_worker,'OpenRouterTransport',Client)
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',model_routes.PRODUCTION_CONFIGURATIONS|frozenset(hermes.digest(hermes.configuration(s)) for s in ('plan','report')))
    setup['hermes_client']=Client
    return setup


def begin(cases,case,holder,supervision,request=None):
    return hermes.start(cases,supervision['vault'],supervision['token'],case['id'],request or uuid4(),holder['id'],approved=True)


def test_native_runtime_preserves_exact_request_and_response_without_credentials():
    messages=[dict(role='system',content='Return only the supplied generated JSON.'),dict(role='user',content='Generated offline fixture.')]
    assert bridge.prepare(hermes.DEFAULT_MODEL,messages)==messages
    result=bridge.turn(hermes.DEFAULT_MODEL,messages,'{"selected_roles":[]}')
    assert result['native_turns']==1 and result['answer']=='{"selected_roles":[]}'
    assert set(result)=={'version','upstream','messages','answer','native_turns'}


def test_preflight_rejects_unqualified_supervisor_before_any_inference(tenant,cases,case,evidence,setup):
    _,holder=intake(tenant,cases,case,evidence)
    status=hermes.preflight(cases,setup['vault'],setup['token'],case['id'],holder['id'])
    assert not status['ready'] and status['required'] and status['model_calls']==0
    assert next(c for c in status['checks'] if c['check']=='exact_supervisor_and_specialist_qualification')['status']=='blocked'
    with pytest.raises(AccessDenied,match='preflight_blocked'):hermes.start(cases,setup['vault'],setup['token'],case['id'],uuid4(),holder['id'],approved=True)
    assert not setup['posts']


def test_hermes_plans_delegates_two_independent_agents_reports_and_replays(tenant,cases,case,evidence,supervision):
    doc,holder=intake(tenant,cases,case,evidence,'identity',dict(event='mfa_disabled',authorized='no'))
    request=uuid4();result=begin(cases,case,holder,supervision,request)
    assert result['state']=='hermes_completed_requires_review' and result['required']
    assert result['delegated_roles']==['incident_scoping','identity_access'] and len(result['agents'])==2
    assert len(supervision['posts'])==6 and all(x['result']['state']=='completed_requires_review' for x in result['agents'])
    packets=[json.loads(p['messages'][1]['content']) for p in supervision['posts']]
    assert packets[0]['stage']=='plan' and packets[-1]['stage']=='report'
    assert [p['role'] for p in packets if 'role' in p]==['incident_scoping','incident_scoping','identity_access','identity_access']
    assert [x['role'] for x in packets[-1]['specialist_progress']]==result['delegated_roles']
    assert all(x['state']=='completed_requires_review' and x['assessment']==dict(disposition='abstain',references=['o1'],provenance='unreviewed_model_assessment',independent_corroboration=False) for x in packets[-1]['specialist_progress'])
    wire=json.dumps(supervision['posts'])
    for private in [supervision['secret'],str(case['id']),str(evidence['id']),doc['facts'][0]['id']]:assert private not in wire
    with connection(cases._dsn) as conn:
        p=cases._human(conn,supervision['token'])
        jobs=conn.execute('SELECT supervisor_run_id FROM gabriel_identity.specialist_agent_jobs WHERE organization_id=%s',(p.organization_id,)).fetchall()
        assert len(jobs)==2 and {str(j['supervisor_run_id']) for j in jobs}=={result['run_id']}
        reservations=conn.execute('SELECT DISTINCT investigation_id FROM gabriel_identity.model_reservations WHERE organization_id=%s',(p.organization_id,)).fetchall()
        assert len(reservations)==1
    replay=begin(cases,case,holder,supervision,request)
    assert replay['state']=='hermes_completed_requires_review'
    for key in ('run_id','state','delegated_roles','plan_answer_evidence_id','report_answer_evidence_id'):
        assert replay[key]==result[key]
    assert len(replay['agents'])==len(result['agents'])==2
    for original,repeated in zip(result['agents'],replay['agents']):
        assert repeated['result']['job_id']==original['result']['job_id']
        assert [s['answer_evidence_id'] for s in repeated['result']['steps']]==[s['answer_evidence_id'] for s in original['result']['steps']]
        assert all(s['historical'] for s in repeated['result']['steps'])
    assert len(supervision['posts'])==6
    for key in ['plan_answer_evidence_id','report_answer_evidence_id']:
        assert json.loads(cases.read_evidence(supervision['token'],result[key]).reveal())['result']['decision']['disposition']=='abstain'


def test_shared_call_cap_stops_extra_specialist_work_and_reports_partial_state(tenant,cases,case,evidence,supervision):
    _,holder=intake(tenant,cases,case,evidence,'identity',dict(event='mfa_disabled',authorized='no'))
    supervision['hermes_client'].selected=['incident_scoping','threat_hunting','identity_access']
    result=begin(cases,case,holder,supervision)
    assert result['state']=='hermes_bounded_investigation_requires_review'
    assert result['report_answer_evidence_id'] is None and len(supervision['posts'])==6
    assert result['agents'][-1]['result']['state']=='budget_or_call_limit_reached'


@pytest.mark.parametrize('change',['key_revoke','logout','stop'])
def test_revocation_during_hermes_inference_suppresses_result_and_child_dispatch(tenant,cases,case,evidence,supervision,change):
    _,holder=intake(tenant,cases,case,evidence,'identity',dict(event='mfa_disabled',authorized='no'))
    def revoke():
        if change=='key_revoke':supervision['personal'].revoke(supervision['token'])
        elif change=='logout':cases.logout(supervision['token'])
        else:hermes.stop(cases,supervision['token'],hermes.history(cases,supervision['token'],case['id'])[0]['id'])
    supervision['hermes_client'].hermes_callback=revoke
    with pytest.raises((AccessDenied,AuthenticationDenied)):begin(cases,case,holder,supervision)
    assert len(supervision['posts'])==1
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_agent_jobs WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


def test_stopped_supervisor_blocks_manual_child_resume(tenant,cases,case,evidence,supervision):
    from gabriel.identity import specialist_agents as agents
    _,holder=intake(tenant,cases,case,evidence,'identity',dict(event='mfa_disabled',authorized='no'))
    result=begin(cases,case,holder,supervision)
    hermes.stop(cases,supervision['token'],result['run_id'])
    with pytest.raises(AccessDenied,match='coordinator_not_active'):
        agents.resume(cases,supervision['vault'],supervision['token'],result['agents'][0]['result']['job_id'])
    assert len(supervision['posts'])==6


def test_unowned_selected_tab_cannot_be_substituted_for_a_fresh_read(tenant,cases,case,evidence,supervision):
    _,holder=intake(tenant,cases,case,evidence)
    with pytest.raises(AccessDenied,match='selected_tab_not_owned'):
        hermes.preflight(cases,supervision['vault'],supervision['token'],case['id'],holder['id'],lease_ids=[uuid4()])
    assert not supervision['posts']


@pytest.fixture(autouse=True)
def scoped_process_dsn(database,tmp_path,monkeypatch):
    path=tmp_path/'hermes-workbench.dsn'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out:out.write(database.app)
    monkeypatch.setenv('GABRIEL_IDENTITY_DSN_FILE',str(path))


from testing.gabriel_identity.test_workbench_integration import boot,server,connect,call,csrf


@pytest.mark.parametrize('boot',['owner','analyst'],indirect=True)
def test_actual_https_supervisor_page_and_preflight_require_csrf_and_expose_blockers(tenant,cases,case,evidence,server):
    _,holder=intake(tenant,cases,case,evidence)
    cookie,_,_=connect(server)
    path='/cases/'+str(case['id'])+'/hermes'
    code,html,_=call(server,path,cookie=cookie)
    assert code==200 and 'Hermes investigation supervisor' in html and 'Check readiness' in html and 'qualification pending' in html
    fields=dict(csrf=csrf(html),request_id=str(uuid4()),input_evidence_id=str(holder['id']),model=hermes.DEFAULT_MODEL,
        specialist_model=hermes.DEFAULT_MODEL,key_scope='personal',selected_leases='local',operation='preflight')
    code,html,_=call(server,path,fields,cookie=cookie)
    assert code==200 and 'Investigation is blocked' in html and 'No inference was performed' in html
    fields['csrf']='incorrect'
    assert call(server,path,fields,cookie=cookie)[0]==403


def tab_sources(tenant,cases,case,supervision,*,count=2,visibility='visible_text_only',capture=True):
    from datetime import datetime,timezone
    from hashlib import sha256
    from gabriel.identity.browser_navigation import BrowserNavigationService
    from testing.gabriel_identity.test_specialist_analysis import document
    browser=BrowserNavigationService(tenant.db.app,cases.store)
    task=browser.create_browser_task(supervision['token'],'Generated Hermes selected tabs',900,20)
    facts=[];leases=[];contexts=[]
    for tab in range(count):
        scope=dict(browser='chrome',extension_version='0.4.0',installation_id=str(uuid4()),tab_id=tab+1,
            document_id=str(uuid4()),page_url='https://generated-console.invalid/security',account_label='Generated Hermes lab')
        lease=browser.issue_browser_lease(supervision['token'],task['id'],case['id'],scope,share_observations=True)
        browser.connect_browser(lease.token,scope)
        leases.append(lease);contexts.append(scope)
        if capture:
            text='Generated dashboard sign-in assertion '+str(tab+1)
            reply=browser.observe_browser(supervision['token'],lease.token,dict(schema_version=1,operation='browser.observe',
                request_id=str(uuid4()),sequence=1,context=scope,observed_at=datetime.now(timezone.utc).isoformat(),
                visibility=visibility,client_minimized=True,content=text))
            source=document('identity',dict(event='mfa_disabled',authorized='no'))
            fact=source['facts'][0];fact.update(evidence_id=str(reply['evidence_id']),evidence_digest=sha256(text.encode()).hexdigest())
            facts.append(fact)
    if not capture:return browser,leases,contexts,None
    source['case_id']=str(case['id']);source['as_of']=datetime.now(timezone.utc).isoformat().replace('+00:00','Z');source['facts']=facts
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(source),'Generated browser-bound typed facts',approved=True)
    return browser,leases,contexts,holder


def test_two_selected_tabs_require_real_current_captures_and_matching_typed_sources(tenant,cases,case,supervision):
    browser,leases,contexts,holder=tab_sources(tenant,cases,case,supervision)
    ids=[str(l.id) for l in leases]
    result=hermes.preflight(cases,supervision['vault'],supervision['token'],case['id'],holder['id'],lease_ids=ids)
    assert result['ready'] and result['selected_leases']==ids and result['scope']=='selected_tabs_and_bound_typed_facts'
    assert not supervision['posts']
    browser.revoke_browser_lease(supervision['token'],leases[1].id)
    with pytest.raises(AccessDenied,match='selected_tab_not_current'):
        hermes.preflight(cases,supervision['vault'],supervision['token'],case['id'],holder['id'],lease_ids=ids)


@pytest.mark.parametrize('visibility',['partial','missing'])
def test_heartbeat_or_partial_capture_never_passes_tab_preflight(tenant,cases,case,evidence,supervision,visibility):
    _,fallback=intake(tenant,cases,case,evidence)
    browser,leases,contexts,holder=tab_sources(tenant,cases,case,supervision,count=1,visibility='partial',capture=visibility!='missing')
    with pytest.raises(AccessDenied,match='fresh_tab_read_required|fresh_dashboard_facts_required'):
        hermes.preflight(cases,supervision['vault'],supervision['token'],case['id'],(holder or fallback)['id'],lease_ids=[str(leases[0].id)])
    assert not supervision['posts']
