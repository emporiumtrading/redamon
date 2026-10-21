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
    assert report.metadata['cost_reconciliation_required'] and report.metadata['result_persisted']
    assert not report.metadata['production_admission'] and not report.metadata['quality_qualified']
    assert worker.budget.status(tenant.token)['usage']['held_slots']==1
    with pytest.raises(AccessDenied,match='already_claimed_no_resend'): dispatch(tenant,setup,row)
    assert len(setup['calls'])==1
    restored=ModelWorker(cases=worker.cases,vault=setup['vault']).get_answer(tenant.token,row['reservation_id'])
    assert restored.reveal()==report.reveal() and restored.metadata['historical']


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


def answer_receipt_permission(tenant,enabled):
    with owner_connection(tenant.db) as conn:
        conn.execute(('GRANT INSERT ON' if enabled else 'REVOKE INSERT ON')+
            ' gabriel_identity.model_answer_receipts '+('TO' if enabled else 'FROM')+' gabriel_identity_app')


def test_receipt_commit_failure_recovers_without_new_provider_or_vault_access(tenant,setup,monkeypatch):
    row=reserve(tenant,setup)
    answer_receipt_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): dispatch(tenant,setup,row)
    finally: answer_receipt_permission(tenant,True)
    assert len(setup['calls'])==1
    def forbidden(*args,**kwargs): raise AssertionError('recovery attempted credential/provider access')
    monkeypatch.setattr(setup['vault'],'resolve_for_backend',forbidden)
    recovered=setup['worker'].recover_answer(tenant.token,row['reservation_id'])
    assert recovered.metadata['result_persisted'] and recovered.metadata['review_status']=='unreviewed'
    replay=setup['worker'].recover_answer(tenant.token,row['reservation_id'])
    assert replay.reveal()==recovered.reveal() and len(setup['calls'])==1
    assert setup['worker'].budget.status(tenant.token)['usage']['held_slots']==1


def test_ciphertext_written_before_database_rollback_is_recoverable(tenant,setup,cases,monkeypatch):
    row=reserve(tenant,setup); original=cases._custody
    def interrupted(conn,p,value,event):
        if event=='acquired': raise RuntimeError('generated interruption after encryption')
        return original(conn,p,value,event)
    monkeypatch.setattr(cases,'_custody',interrupted)
    with pytest.raises(RuntimeError,match='generated interruption'): dispatch(tenant,setup,row)
    monkeypatch.setattr(cases,'_custody',original)
    answer=setup['worker'].recover_answer(tenant.token,row['reservation_id'])
    assert answer.metadata['result_persisted'] and len(setup['calls'])==1
    _,path=row_and_file(tenant,cases,dict(id=answer.metadata['answer_evidence_id']))
    raw=path.read_bytes()
    assert b'GENERATED_PRIVATE_PRINCIPAL' not in raw and setup['secret'].encode() not in raw


def test_missing_ciphertext_cannot_be_recovered_by_resending(tenant,setup,cases,monkeypatch):
    row=reserve(tenant,setup); original=cases.store.write
    def interrupted(*args,**kwargs): raise RuntimeError('generated interruption before encryption')
    monkeypatch.setattr(cases.store,'write',interrupted)
    with pytest.raises(RuntimeError): dispatch(tenant,setup,row)
    monkeypatch.setattr(cases.store,'write',original)
    from gabriel.identity.evidence_store import EvidenceError
    with pytest.raises(EvidenceError): setup['worker'].recover_answer(tenant.token,row['reservation_id'])
    with pytest.raises(AccessDenied,match='already_claimed_no_resend'): dispatch(tenant,setup,row)
    assert len(setup['calls'])==1


@pytest.mark.parametrize('change',['stop','new_source','pause'])
def test_incomplete_receipt_recovery_rechecks_live_scope(tenant,setup,cases,case,change):
    row=reserve(tenant,setup);answer_receipt_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): dispatch(tenant,setup,row)
    finally: answer_receipt_permission(tenant,True)
    if change=='stop': cases.stop_coordinator(tenant.token,setup['plan']['id'])
    elif change=='new_source': cases.acquire(tenant.token,case['id'],uuid4(),'Generated source after model answer','Generated fixture',approved=True)
    else: setup['worker'].budget.configure(tenant.token,enabled=False)
    with pytest.raises(AccessDenied): setup['worker'].recover_answer(tenant.token,row['reservation_id'])
    assert len(setup['calls'])==1
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_answer_receipts WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


def test_completed_answer_is_historical_after_stop_and_does_not_need_model_admission(tenant,setup,cases,monkeypatch):
    row=reserve(tenant,setup);answer=dispatch(tenant,setup,row)
    cases.stop_coordinator(tenant.token,setup['plan']['id'])
    monkeypatch.setattr(model_routes,'PRODUCTION_CONFIGURATIONS',frozenset())
    replay=setup['worker'].get_answer(tenant.token,row['reservation_id'])
    assert replay.reveal()==answer.reveal() and replay.metadata['historical']
    assert len(setup['calls'])==1 and not replay.metadata['production_admission']


def test_answer_ciphertext_and_original_sources_must_verify_on_read(tenant,setup,cases,evidence):
    row=reserve(tenant,setup);dispatch(tenant,setup,row)
    _,path=row_and_file(tenant,cases,evidence);path.chmod(0o600);path.write_bytes(b'generated-corruption')
    from gabriel.identity.evidence_store import EvidenceError
    with pytest.raises(EvidenceError): setup['worker'].get_answer(tenant.token,row['reservation_id'])
    assert len(setup['calls'])==1


def test_answer_read_requires_transactional_audit(tenant,setup):
    row=reserve(tenant,setup);dispatch(tenant,setup,row);audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): setup['worker'].get_answer(tenant.token,row['reservation_id'])
    finally: audit_permission(tenant,True)


def test_unreviewed_model_answer_cannot_be_reused_as_source_evidence(tenant,setup,cases,case):
    row=reserve(tenant,setup);answer=dispatch(tenant,setup,row)
    answer_id=answer.metadata['answer_evidence_id']
    data=json.loads(cases.read_evidence(tenant.token,setup['holder']['id']).reveal())
    data['records'][0]['evidence_id']=answer_id
    data['records'][0]['evidence_digest']=cases.read_evidence(tenant.token,answer_id).metadata['digest']
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(data),'Generated attempted answer reuse',approved=True)
    plan=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    cases.advance_coordinator(tenant.token,plan['id']);cases.advance_coordinator(tenant.token,plan['id'])
    with pytest.raises(AccessDenied,match='unreviewed_model_answer_is_not_source_evidence'):
        setup['worker'].reserve(tenant.token,plan['id'],holder['id'],uuid4(),MODEL)
    assert len(setup['calls'])==1


def test_answer_receipts_are_append_only_and_case_bound(tenant,setup):
    from gabriel.identity.service import connection
    row=reserve(tenant,setup);dispatch(tenant,setup,row)
    for table in ['model_answer_intents','model_answer_receipts']:
        with pytest.raises(IdentityUnavailable):
            with connection(tenant.db.app) as conn:
                conn.execute('DELETE FROM gabriel_identity.'+table)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_answer_receipts WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==1


def test_answer_is_not_accessible_from_another_tenant(tenant,setup,cases):
    from gabriel.identity.service import provision_organization
    row=reserve(tenant,setup);dispatch(tenant,setup,row)
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated foreign answer reader','owner',password)
    token=cases.login(org,'owner',password).token
    with pytest.raises(AccessDenied): setup['worker'].get_answer(token,row['reservation_id'])
    with pytest.raises(AccessDenied): setup['worker'].recover_answer(token,row['reservation_id'])


def test_answer_schema_upgrade_failure_is_atomic(tenant,monkeypatch):
    from pathlib import Path
    from gabriel.identity.service import migrate
    from testing.gabriel_identity.db_history import remove_v18
    with owner_connection(tenant.db) as conn: remove_v18(conn)
    original=Path.read_text
    def interrupted(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v18.sql' else value
    monkeypatch.setattr(Path,'read_text',interrupted)
    with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT to_regclass('gabriel_identity.model_answer_intents') AS t").fetchone()['t'] is None
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==17
    monkeypatch.setattr(Path,'read_text',original);migrate(tenant.db.owner)


def test_model_origin_requires_a_backend_staging_intent(tenant,cases,case):
    with pytest.raises(AccessDenied,match='model_answer_intent_required'):
        cases.acquire(tenant.token,case['id'],uuid4(),'Generated fabricated model origin','Generated fixture',
                      approved=True,_model_generated=True)


def test_concurrent_recovery_publishes_one_receipt_without_resending(tenant,setup):
    from concurrent.futures import ThreadPoolExecutor
    row=reserve(tenant,setup);answer_receipt_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): dispatch(tenant,setup,row)
    finally: answer_receipt_permission(tenant,True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        values=list(pool.map(lambda _:setup['worker'].recover_answer(tenant.token,row['reservation_id']),range(3)))
    assert len({value.reveal() for value in values})==1 and len(setup['calls'])==1
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_answer_receipts WHERE organization_id=%s',
                            (tenant.org,)).fetchone()['n']==1
