"""Real database/crypto worker boundaries with hermetic transport, never provider evidence."""
import json
import secrets
from uuid import uuid4

import pytest

from gabriel.identity import model_routes,model_worker
from gabriel.identity.model_evaluation import digest
from gabriel.identity.model_worker import ModelWorker,configuration
from gabriel.identity.provider_probe import ProbeError
from gabriel.identity.service import AccessDenied,IdentityUnavailable
from gabriel.identity.vault import ProviderVault
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,audit_permission,row_and_file
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_vault_integration import fresh_ring
from testing.gabriel_identity.test_model_lab import catalog,key_data

pytestmark=pytest.mark.integration
MODEL='openai/gpt-4.1-mini'


@pytest.fixture
def setup(tenant,cases,case,evidence,monkeypatch):
    vault=ProviderVault(tenant.db.app,fresh_ring())
    secret='generated-worker-'+secrets.token_urlsafe(30)
    vault.put(tenant.token,'openrouter',secret)
    record=dict(record_id=str(uuid4()),evidence_id=str(evidence['id']),evidence_digest=evidence['digest'],
        event_time='2026-10-20T12:00:00Z',kind='authentication',outcome='failure',
        actor='GENERATED_PRIVATE_PRINCIPAL',asset='GENERATED_PRIVATE_ASSET',address=None,count=2)
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(dict(version='normalized-telemetry-v1',records=[record])),
                         'Generated normalized fixture',approved=True)
    plan=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    cases.advance_coordinator(tenant.token,plan['id']); cases.advance_coordinator(tenant.token,plan['id'])
    worker=ModelWorker(cases,vault)
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset({digest(configuration(MODEL))}))
    calls=[]
    class Client:
        callback=None
        unknown=False
        def __init__(self,credential): assert credential.reveal()==secret
        def request(self,method,path,payload=None):
            if path=='/api/v1/endpoints/zdr': return catalog()
            if path=='/api/v1/key': return dict(data=key_data())
            assert method=='POST'
            raw=json.dumps(payload)
            assert all(value not in raw for value in [secret,'GENERATED_PRIVATE_PRINCIPAL','GENERATED_PRIVATE_ASSET',str(tenant.org),str(case['id']),str(evidence['id'])])
            calls.append(payload)
            if type(self).callback: type(self).callback()
            if type(self).unknown: raise ProbeError('provider_transport_unresolved')
            answer=dict(disposition='urgent_inconclusive',claims=[dict(id='claim-1',statement='Generated partial observation.',references=['o1'])],
                alternatives=['An authorized activity remains possible.'],contradictions=['No independent corroboration supplied.'],
                uncertainty=['Source visibility is unverified.'],reported_gaps=['missing-context'],requested_actions=[])
            return dict(id='fixture-generation',model=MODEL,provider='Azure',choices=[dict(finish_reason='stop',message=dict(content=json.dumps(answer)))],
                        usage=dict(prompt_tokens=299,completion_tokens=227,cost=0.0002))
    monkeypatch.setattr(model_worker,'OpenRouterTransport',Client)
    return dict(worker=worker,vault=vault,secret=secret,holder=holder,plan=plan,calls=calls,client=Client)


def reserve(tenant,setup):
    return setup['worker'].reserve(tenant.token,setup['plan']['id'],setup['holder']['id'],uuid4(),MODEL)


def dispatch(tenant,setup,reservation):
    return setup['worker'].dispatch(tenant.token,setup['plan']['id'],setup['holder']['id'],reservation['reservation_id'])


def test_default_admission_denies_before_vault_or_budget(tenant,setup,monkeypatch):
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset())
    with pytest.raises(AccessDenied,match='not_production_admitted'): reserve(tenant,setup)
    assert setup['worker'].budget.status(tenant.token)['usage']['held_slots']==0
    assert not setup['calls']


def test_admitted_test_fixture_dispatch_is_private_and_remains_reserved(tenant,setup):
    request=uuid4(); worker=setup['worker']
    row=worker.reserve(tenant.token,setup['plan']['id'],setup['holder']['id'],request,MODEL)
    assert worker.reserve(tenant.token,setup['plan']['id'],setup['holder']['id'],request,MODEL)==row
    assert row['reserved_microusd']==6304
    report=dispatch(tenant,setup,row)
    assert 'GENERATED_PRIVATE_PRINCIPAL' not in repr(report) and setup['secret'] not in repr(report)
    private=json.loads(report.reveal())
    assert private['result']['decision']['disposition']=='urgent_inconclusive'
    assert private['local_manifest']['identity_map']
    assert report.metadata['cost_reconciliation_required'] and not report.metadata['result_persisted']
    assert not report.metadata['production_admission'] and not report.metadata['quality_qualified']
    assert worker.budget.status(tenant.token)['usage']['held_slots']==1
    with pytest.raises(AccessDenied,match='already_claimed_no_resend'): dispatch(tenant,setup,row)
    assert len(setup['calls'])==1


def test_unknown_outcome_survives_fresh_worker_without_resend(tenant,setup,cases):
    row=reserve(tenant,setup); setup['client'].unknown=True
    with pytest.raises(ProbeError): dispatch(tenant,setup,row)
    setup['worker']=ModelWorker(cases,setup['vault'])
    with pytest.raises(AccessDenied,match='already_claimed_no_resend'): dispatch(tenant,setup,row)
    assert len(setup['calls'])==1
    assert setup['worker'].budget.status(tenant.token)['usage']['held_slots']==1


@pytest.mark.parametrize('change',['stop','new_evidence','budget_pause','input_digest'])
def test_dispatch_rechecks_scope_and_budget_before_sending(tenant,setup,cases,case,change):
    row=reserve(tenant,setup)
    if change=='stop': cases.stop_coordinator(tenant.token,setup['plan']['id'])
    elif change=='new_evidence': cases.acquire(tenant.token,case['id'],uuid4(),'Generated later evidence','Generated fixture',approved=True)
    elif change=='budget_pause': setup['worker'].budget.configure(tenant.token,enabled=False)
    else:
        with owner_connection(tenant.db) as conn:
            conn.execute('UPDATE gabriel_identity.model_reservations SET input_digest=%s WHERE id=%s',('0'*64,row['reservation_id']))
    with pytest.raises(AccessDenied): dispatch(tenant,setup,row)
    assert not setup['calls']
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_dispatch_claims WHERE reservation_id=%s',(row['reservation_id'],)).fetchone()['n']==0


def test_stop_during_provider_call_suppresses_returned_result_and_holds_cost(tenant,setup,cases):
    row=reserve(tenant,setup)
    setup['client'].callback=lambda:cases.stop_coordinator(tenant.token,setup['plan']['id'])
    with pytest.raises(AccessDenied): dispatch(tenant,setup,row)
    assert len(setup['calls'])==1
    assert setup['worker'].budget.status(tenant.token)['usage']['held_slots']==1


def test_wrong_case_input_cannot_be_egressed(tenant,setup,cases):
    other=cases.create_case(tenant.token,'Generated other worker case')
    holder=cases.acquire(tenant.token,other['id'],uuid4(),'Generated unrelated input','Generated fixture',approved=True)
    with pytest.raises(AccessDenied,match='input_not_in_plan'):
        setup['worker'].reserve(tenant.token,setup['plan']['id'],holder['id'],uuid4(),MODEL)
    assert not setup['calls']


def test_input_read_requires_auditable_admission(tenant,setup):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): reserve(tenant,setup)
    finally: audit_permission(tenant,True)
    assert not setup['calls'] and setup['worker'].budget.status(tenant.token)['usage']['held_slots']==0


def test_referenced_source_ciphertext_must_still_verify_before_dispatch(tenant,setup,cases,evidence):
    row=reserve(tenant,setup)
    _,path=row_and_file(tenant,cases,evidence)
    path.chmod(0o600)
    path.write_bytes(b'generated-corrupt-ciphertext')
    from gabriel.identity.evidence_store import EvidenceError
    with pytest.raises(EvidenceError): dispatch(tenant,setup,row)
    assert not setup['calls']
