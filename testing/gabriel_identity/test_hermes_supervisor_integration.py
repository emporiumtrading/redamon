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
    assert packets[-1]['specialist_progress']==[dict(role=r,state='completed_requires_review') for r in result['delegated_roles']]
    wire=json.dumps(supervision['posts'])
    for private in [supervision['secret'],str(case['id']),str(evidence['id']),doc['facts'][0]['id']]:assert private not in wire
    with connection(cases._dsn) as conn:
        p=cases._human(conn,supervision['token'])
        jobs=conn.execute('SELECT supervisor_run_id FROM gabriel_identity.specialist_agent_jobs WHERE organization_id=%s',(p.organization_id,)).fetchall()
        assert len(jobs)==2 and {str(j['supervisor_run_id']) for j in jobs}=={result['run_id']}
        reservations=conn.execute('SELECT DISTINCT investigation_id FROM gabriel_identity.model_reservations WHERE organization_id=%s',(p.organization_id,)).fetchall()
        assert len(reservations)==1
    assert begin(cases,case,holder,supervision,request)['state']=='hermes_completed_requires_review'
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
