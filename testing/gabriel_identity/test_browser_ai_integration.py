"""Actual PostgreSQL/browser gateway/worker custody with hermetic provider transport."""
from datetime import datetime,timezone
import json
from uuid import uuid4

import pytest

from gabriel.identity import browser_ai,model_routes
from gabriel.identity.browser_gateway import BrowserGateway,prepare
from gabriel.identity.service import AccessDenied,AuthenticationDenied
from gabriel.identity.vault import ProviderKeyRing
from gabriel.identity.model_protocol import ProbeError
from gabriel.identity.model_evaluation import digest
from testing.gabriel_identity.test_browser_monitoring_integration import database,enrollment
from testing.gabriel_identity.test_identity_integration import tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_model_worker_integration import setup as legacy_setup,MODEL

pytestmark=pytest.mark.integration


@pytest.fixture
def ai(tenant,cases,case,context,legacy_setup,monkeypatch):
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset({digest(browser_ai.configuration(MODEL))}))
    monkeypatch.setattr(ProviderKeyRing,'from_file',classmethod(lambda cls,path:legacy_setup['vault']._ring))
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,monitoring_approved=True)
    configured=dict(endpoint=gateway.target,extension_origin=gateway.origin,context=scope,
        ticket_digest=gateway._ticket,lease_id=str(lease.id),ai_model=MODEL)
    gateway=BrowserGateway(browser,tenant.token,lease.token,configured)
    paired=gateway.dispatch('claim',dict(ticket=ticket,context=scope),None)
    assert paired['ai_review_enabled']
    return dict(browser=browser,lease=lease,scope=scope,gateway=gateway,fixture=legacy_setup)


def capture(ai,tenant,sequence=1,content='Generated lab account\nFailed login for PRIVATE_GENERATED_USER at https://generated-console.invalid'):
    row=ai['browser'].observe_browser(tenant.token,ai['lease'].token,dict(schema_version=1,operation='browser.observe',
        request_id=str(uuid4()),sequence=sequence,context=ai['scope'],observed_at=datetime.now(timezone.utc).isoformat(),
        visibility='partial',client_minimized=True,content=content))
    return dict(row,evidence_id=str(row['evidence_id']),observation_id=str(row['observation_id']))


def dispatch(ai,observation):
    return ai['gateway'].dispatch('ai-review',dict(context=ai['scope'],observation_id=observation['observation_id']),
        'Bearer '+ai['lease'].token)


def test_browser_capture_dispatches_minimized_signals_and_persists_source_linked_answer(tenant,ai):
    observed=capture(ai,tenant)
    answer=dispatch(ai,observed)
    assert answer['model_used'] and answer['state']=='model_answer_requires_review'
    assert answer['disposition']=='urgent_inconclusive' and answer['review_status']=='unreviewed'
    assert not answer['quality_qualified'] and not answer['incident_confirmed']
    calls=ai['fixture']['calls'];assert len(calls)==1
    body=json.dumps(calls[0])
    for private in ['PRIVATE_GENERATED_USER','generated-console.invalid','Generated lab account',observed['evidence_id'],str(tenant.org)]:
        assert private not in body
    packet=json.loads(calls[0]['messages'][1]['content'])
    assert packet['signals']==[dict(id='o1',signal='authentication',passage_count=1)]
    assert packet['time_basis']=='server_capture_receipt_not_event_time' and not packet['actions_authorized']
    raw=ai['browser'].read_evidence(tenant.token,answer['answer_evidence_id']).reveal()
    payload=json.loads(raw)
    assert payload['local_manifest']['lineage']['o1']['evidence_id']==observed['evidence_id']
    assert payload['local_manifest']['lineage']['o1']['evidence_digest']==ai['browser'].read_evidence(tenant.token,observed['evidence_id']).metadata['digest']
    replay=dispatch(ai,observed)
    assert replay['historical'] and replay['answer_evidence_id']==answer['answer_evidence_id'] and len(calls)==1
    status=ai['fixture']['worker'].budget.status(tenant.token)
    assert status['usage']['held_slots']==0 and status['usage']['day_used']==6304
    with owner_connection(tenant.db) as conn:
        row=conn.execute('SELECT * FROM gabriel_identity.model_settlements WHERE reservation_id=%s',(answer['reservation_id'],)).fetchone()
        assert row['outcome']=='completed_upper_bound' and row['actual_microusd']==6304


def test_unknown_provider_outcome_is_never_retried_and_keeps_its_reservation(tenant,ai):
    observed=capture(ai,tenant);ai['fixture']['client'].unknown=True
    with pytest.raises(ProbeError):dispatch(ai,observed)
    with pytest.raises(AccessDenied,match='outcome_unresolved_no_resend'):dispatch(ai,observed)
    assert len(ai['fixture']['calls'])==1
    assert ai['fixture']['worker'].budget.status(tenant.token)['usage']['held_slots']==1


def test_stop_is_not_blocked_by_provider_request_and_suppresses_the_answer(tenant,ai):
    observed=capture(ai,tenant)
    ai['fixture']['client'].callback=lambda:ai['gateway'].dispatch('disconnect',{},'Bearer '+ai['lease'].token)
    with pytest.raises((AccessDenied,AuthenticationDenied)):dispatch(ai,observed)
    assert len(ai['fixture']['calls'])==1
    assert ai['browser'].get_browser_lease(tenant.token,ai['lease'].id)['state']=='disconnected'
    assert ai['fixture']['worker'].budget.status(tenant.token)['usage']['held_slots']==1
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_answer_receipts WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


def test_unadmitted_configuration_and_paused_budget_deny_before_generation(tenant,ai,monkeypatch):
    observed=capture(ai,tenant)
    with monkeypatch.context() as patch:
        patch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset())
        with pytest.raises(AccessDenied,match='not_production_admitted'):dispatch(ai,observed)
    ai['fixture']['worker'].budget.configure(tenant.token,enabled=False)
    with pytest.raises(AccessDenied,match='paused'):dispatch(ai,observed)
    assert not ai['fixture']['calls']


def test_gateway_requires_independent_server_approval_for_ai(tenant,cases,case,context):
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context,monitoring_approved=True)
    paired=gateway.dispatch('claim',dict(ticket=ticket,context=scope),None)
    assert not paired['ai_review_enabled']
    with pytest.raises(AccessDenied,match='not_approved'):
        gateway.dispatch('ai-review',dict(context=scope,observation_id=str(uuid4())),'Bearer '+lease.token)


def test_no_supported_signals_abstains_without_generation(tenant,ai):
    observed=capture(ai,tenant,content='Generated lab account\nNo visible failed login events')
    answer=dispatch(ai,observed)
    assert answer['state']=='abstained_no_supported_signals' and not answer['model_used']
    assert not ai['fixture']['calls'] and ai['fixture']['worker'].budget.status(tenant.token)['usage']['held_slots']==0


def test_foreign_context_or_capture_does_not_grant_ai_authority(tenant,ai,cases,case,context):
    observed=capture(ai,tenant)
    with pytest.raises(AccessDenied):
        ai['gateway'].dispatch('ai-review',dict(context=dict(ai['scope'],account_label='Other account'),
            observation_id=observed['observation_id']),'Bearer '+ai['lease'].token)
    browser,lease,scope,_,_=enrollment(tenant,cases,case,context,tab=2,monitoring_approved=True)
    browser.connect_browser(lease.token,scope)
    with pytest.raises(AccessDenied,match='capture_scope_mismatch'):
        browser_ai.process(browser,ai['fixture']['vault'],tenant.token,lease.token,scope,observed['observation_id'],MODEL)
    assert not ai['fixture']['calls']


def test_successive_completed_reviews_count_full_ceilings_without_occupying_unknown_slots(tenant,ai):
    for sequence in range(1,4):
        observed=capture(ai,tenant,sequence=sequence)
        assert dispatch(ai,observed)['model_used']
    assert len(ai['fixture']['calls'])==3
    status=ai['fixture']['worker'].budget.status(tenant.token)
    assert status['usage']['held_slots']==0 and status['usage']['day_used']==3*6304


def test_preparation_rejects_unqualified_model_without_creating_an_installation(tenant,cases,case,context,tmp_path):
    from gabriel.identity.browser_navigation import BrowserNavigationService
    service=BrowserNavigationService(tenant.db.app,cases.store)
    target=tmp_path/'unadmitted'
    with pytest.raises(AccessDenied,match='not_production_admitted'):
        prepare(service,tenant.token,str(uuid4()),case['id'],context,'https://localhost:8443','chrome-extension://'+'a'*32,
            target,share_observations=True,monitor_seconds=300,ai_model=MODEL)
    assert not target.exists()
