"""Durable twelve-role local plans against disposable PostgreSQL and encrypted evidence."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from gabriel.identity import coordinator,specialist_analysis_runs
from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,IdentityUnavailable,InvalidIdentityInput,migrate
from gabriel.identity.specialist_contracts import ROLES
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,row_and_file
from testing.gabriel_identity.test_specialist_analysis_integration import intake
from testing.gabriel_identity.db_history import remove_v25

pytestmark=pytest.mark.integration


@pytest.fixture
def typed(tenant,cases,case,evidence):
    return intake(tenant,cases,case,evidence)[1]


@pytest.fixture
def plan(tenant,cases,case,typed):
    return cases.begin_coordinator(tenant.token,case['id'],uuid4(),input_evidence_id=typed['id'])


def test_all_twelve_complete_with_fixed_input_and_no_model_authority(tenant,cases,case,typed,plan):
    assert plan['max_steps']==12 and plan['input_evidence_id']==str(typed['id'])
    assert [row['operation'] for row in plan['steps']]==list(ROLES)
    done=cases.complete_coordinator(tenant.token,plan['id'])
    assert done['completed_steps']==12 and done['status']=='local_plan_complete'
    assert not done['model_enabled'] and not done['external_actions_enabled']
    assert cases.complete_coordinator(tenant.token,plan['id'])==done
    for step in done['steps']:
        run=cases.get_specialist_run(tenant.token,case['id'],step['result']['specialist_id'])
        assert run['role']==step['operation'] and run['packet']['input_evidence_id']==str(typed['id'])
        assert run['result_digest']==step['result']['specialist_result_digest']
        assert run['result']['execution']['model_cost_usd']=='0' and run['result']['confidence']=='unqualified'
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==12


def test_concurrent_drains_and_fresh_service_converge_without_duplicate_reviews(tenant,cases,case,plan):
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _:cases.complete_coordinator(tenant.token,plan['id']),range(3)))
    fresh=CaseService(tenant.db.app,cases.store)
    assert fresh.complete_coordinator(tenant.token,plan['id'])['completed_steps']==12
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==12


def test_receipt_failure_replays_original_role_then_resumes_remaining_roles(tenant,cases,case,plan,monkeypatch):
    original=coordinator._audit
    def interrupted(conn,event,*args):
        if event=='coordinator.local_step_completed': raise IdentityUnavailable('generated_receipt_failure')
        return original(conn,event,*args)
    with monkeypatch.context() as patch:
        patch.setattr(coordinator,'_audit',interrupted)
        with pytest.raises(IdentityUnavailable): cases.complete_coordinator(tenant.token,plan['id'])
    assert cases.get_coordinator(tenant.token,plan['id'])['completed_steps']==0
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1
    assert cases.complete_coordinator(tenant.token,plan['id'])['completed_steps']==12
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==12


def test_stop_before_specialist_writer_denies_both_result_and_completion(tenant,cases,case,plan,monkeypatch):
    original=specialist_analysis_runs.run
    def stop_before(*args,**kwargs):
        cases.stop_coordinator(tenant.token,plan['id'])
        return original(*args,**kwargs)
    monkeypatch.setattr(specialist_analysis_runs,'run',stop_before)
    with pytest.raises(AccessDenied,match='not_active'): cases.complete_coordinator(tenant.token,plan['id'])
    assert not cases.list_specialist_runs(tenant.token,case['id'])['runs']
    assert cases.get_coordinator(tenant.token,plan['id'])['status']=='stopped'


def test_stop_between_roles_preserves_history_and_prevents_remaining_work(tenant,cases,case,plan,monkeypatch):
    original=coordinator.advance
    def stop_after(*args,**kwargs):
        value=original(*args,**kwargs)
        cases.stop_coordinator(tenant.token,plan['id'])
        return value
    monkeypatch.setattr(coordinator,'advance',stop_after)
    result=cases.complete_coordinator(tenant.token,plan['id'])
    assert result['status']=='stopped' and result['completed_steps']==1
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1


@pytest.mark.parametrize('mode',['added_source','corrupt_source'])
def test_changed_or_corrupt_source_blocks_remaining_roles(tenant,cases,case,evidence,plan,mode):
    assert cases.advance_coordinator(tenant.token,plan['id'])['completed_steps']==1
    if mode=='added_source':
        cases.acquire(tenant.token,case['id'],uuid4(),'Generated new source','Generated fixture',approved=True)
    else:
        _,path=row_and_file(tenant,cases,evidence);path.chmod(0o600);path.write_bytes(b'generated-corrupt-source')
    with pytest.raises((AccessDenied,EvidenceError)): cases.complete_coordinator(tenant.token,plan['id'])
    assert cases.get_coordinator(tenant.token,plan['id'])['completed_steps']==1
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1


def test_input_replay_conflict_and_legacy_sequence_limit(tenant,cases,case,evidence,typed):
    request=uuid4()
    first=cases.begin_coordinator(tenant.token,case['id'],request,input_evidence_id=typed['id'])
    assert cases.begin_coordinator(tenant.token,case['id'],request,input_evidence_id=typed['id'])==first
    with pytest.raises(AccessDenied,match='conflict'): cases.begin_coordinator(tenant.token,case['id'],request)
    with pytest.raises(InvalidIdentityInput): cases.begin_coordinator(tenant.token,case['id'],uuid4(),input_evidence_id=typed['id'],max_steps=2)
    legacy=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    with pytest.raises(InvalidIdentityInput): cases.advance_coordinator(tenant.token,legacy['id'],expected_sequence=3)
    assert cases.advance_coordinator(tenant.token,first['id'],expected_sequence=12)['completed_steps']==0


def test_invalid_or_foreign_input_cannot_create_plan(tenant,cases,case,evidence):
    with pytest.raises(InvalidIdentityInput): cases.begin_coordinator(tenant.token,case['id'],uuid4(),input_evidence_id=evidence['id'])
    other=cases.create_case(tenant.token,'Generated foreign input case')
    with pytest.raises(AccessDenied): cases.begin_coordinator(tenant.token,other['id'],uuid4(),input_evidence_id=evidence['id'])
    assert not cases.list_coordinator_runs(tenant.token,case['id'])['runs']


def test_schema_upgrade_rollback_preserves_legacy_plan(tenant,cases,case,monkeypatch):
    legacy=cases.begin_coordinator(tenant.token,case['id'],uuid4())
    with owner_connection(tenant.db) as conn: remove_v25(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v25.sql' else value
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_text',broken)
        with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==24
        assert not conn.execute("SELECT 1 FROM information_schema.columns WHERE table_schema='gabriel_identity' AND table_name='coordinator_runs' AND column_name='input_evidence_id'").fetchone()
    migrate(tenant.db.owner)
    assert cases.get_coordinator(tenant.token,legacy['id'])['completed_steps']==0
