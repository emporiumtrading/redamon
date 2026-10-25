"""Real persisted local coordination; no model responses or external-effect fixtures."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity import coordinator
from gabriel.identity.cases import CaseService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,migrate,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,audit_permission
from testing.gabriel_identity.db_history import remove_v17

pytestmark=pytest.mark.integration


@pytest.fixture
def plan(tenant,cases,case,evidence):
    return cases.begin_coordinator(tenant.token,case['id'],uuid4())


def test_plan_and_fixed_local_steps_survive_fresh_service(tenant,cases,case,evidence,plan):
    assert plan['status']=='pending_local_steps' and plan['max_steps']==2
    assert [s['operation'] for s in plan['steps']]==['evidence_inventory','telemetry_health']
    fresh=CaseService(tenant.db.app,cases.store)
    assert fresh.get_coordinator(tenant.token,plan['id'])['source_digest']==plan['source_digest']
    first=fresh.advance_coordinator(tenant.token,plan['id'])
    assert first['completed_steps']==1
    assert first['steps'][0]['result']['sources']==[dict(evidence_id=str(evidence['id']),digest=evidence['digest'])]
    done=fresh.advance_coordinator(tenant.token,plan['id'])
    assert done['status']=='local_plan_complete' and done['completed_steps']==2
    assert not done['model_enabled'] and not done['external_actions_enabled']
    assert done['incident_assessment']=='not_performed'
    assert fresh.advance_coordinator(tenant.token,plan['id'])==done
    linked=fresh.get_specialist_run(tenant.token,case['id'],done['steps'][1]['result']['specialist_id'])
    assert linked['result_digest']==done['steps'][1]['result']['specialist_result_digest']
    assert linked['result']['execution']['model'] is None


def test_duplicate_begin_and_conflicting_limits(tenant,cases,case,evidence):
    request=uuid4()
    first=cases.begin_coordinator(tenant.token,case['id'],request,max_steps=1)
    assert cases.begin_coordinator(tenant.token,case['id'],request,max_steps=1)==first
    with pytest.raises(AccessDenied,match='conflict'):
        cases.begin_coordinator(tenant.token,case['id'],request,max_steps=2)
    assert cases.advance_coordinator(tenant.token,first['id'])['status']=='local_plan_complete'


def test_expected_step_replay_never_advances_the_following_step(tenant,cases,plan):
    first=cases.advance_coordinator(tenant.token,plan['id'],expected_sequence=1)
    assert first['completed_steps']==1
    assert cases.advance_coordinator(tenant.token,plan['id'],expected_sequence=1)==first
    assert cases.get_coordinator(tenant.token,plan['id'])['steps'][1]['claimed_at'] is None
    with pytest.raises(InvalidIdentityInput):
        cases.advance_coordinator(tenant.token,plan['id'],expected_sequence=True)
    assert cases.advance_coordinator(tenant.token,plan['id'],expected_sequence=2)['completed_steps']==2


def test_history_is_bounded_case_scoped_and_omits_receipt_bodies(tenant,cases,case,plan):
    other=cases.create_case(tenant.token,'Generated separate coordinator case')
    cases.begin_coordinator(tenant.token,other['id'],uuid4())
    for _ in range(32): cases.begin_coordinator(tenant.token,case['id'],uuid4())
    history=cases.list_coordinator_runs(tenant.token,case['id'])
    assert len(history['runs'])==32 and history['truncated']
    assert all(row['case_id']==str(case['id']) and 'steps' not in row for row in history['runs'])
    assert all(not row['current_source_authority_checked'] for row in history['runs'])
    password=secrets.token_urlsafe(24)
    foreign_org,_=provision_organization(tenant.db.owner,'Generated foreign coordinator history','owner',password)
    token=cases.login(foreign_org,'owner',password).token
    with pytest.raises(AccessDenied): cases.list_coordinator_runs(token,case['id'])


def test_concurrent_requests_never_exceed_plan_or_duplicate_specialist(tenant,cases,plan,case):
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _:cases.advance_coordinator(tenant.token,plan['id']),range(4)))
    while cases.get_coordinator(tenant.token,plan['id'])['completed_steps']<2:
        cases.advance_coordinator(tenant.token,plan['id'])
    with owner_connection(tenant.db) as conn:
        for table in ('coordinator_results','coordinator_claims'):
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.'+table+' WHERE run_id=%s',(plan['id'],)).fetchone()['n']==2
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE case_id=%s',(case['id'],)).fetchone()['n']==1


def test_stop_before_and_during_operation_does_not_create_completion(tenant,cases,plan,monkeypatch):
    original=coordinator.execute_local
    def stop_during(*args):
        result=original(*args)
        cases.stop_coordinator(tenant.token,plan['id'])
        return result
    monkeypatch.setattr(coordinator,'execute_local',stop_during)
    with pytest.raises(AccessDenied,match='not_active'):
        cases.advance_coordinator(tenant.token,plan['id'])
    stopped=cases.get_coordinator(tenant.token,plan['id'])
    assert stopped['status']=='stopped' and stopped['completed_steps']==0
    assert stopped['steps'][0]['claimed_at'] is not None
    with pytest.raises(AccessDenied): cases.advance_coordinator(tenant.token,plan['id'])
    assert cases.stop_coordinator(tenant.token,plan['id'])['status']=='stopped'


def test_new_source_invalidates_before_claim(tenant,cases,case,plan):
    cases.acquire(tenant.token,case['id'],uuid4(),'Generated later evidence','Generated fixture',approved=True)
    with pytest.raises(AccessDenied,match='scope_changed'):
        cases.advance_coordinator(tenant.token,plan['id'])
    assert cases.get_coordinator(tenant.token,plan['id'])['steps'][0]['claimed_at'] is None


def test_changed_source_during_operation_leaves_durable_unfinished_claim(tenant,cases,case,plan,monkeypatch):
    original=coordinator.execute_local
    def changed(*args):
        result=original(*args)
        cases.acquire(tenant.token,case['id'],uuid4(),'Generated intervening evidence','Generated fixture',approved=True)
        return result
    monkeypatch.setattr(coordinator,'execute_local',changed)
    with pytest.raises(AccessDenied,match='scope_changed'):
        cases.advance_coordinator(tenant.token,plan['id'])
    assert cases.get_coordinator(tenant.token,plan['id'])['completed_steps']==0


def test_unknown_model_or_action_operation_cannot_be_scheduled(tenant,cases,case):
    for maximum in (0,3,True,1.5):
        with pytest.raises(InvalidIdentityInput):
            cases.begin_coordinator(tenant.token,case['id'],uuid4(),max_steps=maximum)
    for ttl in (59,901,True):
        with pytest.raises(InvalidIdentityInput):
            cases.begin_coordinator(tenant.token,case['id'],uuid4(),ttl_seconds=ttl)


def test_expired_and_revoked_creator_cannot_continue(tenant,cases,plan):
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.coordinator_runs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE id=%s",(plan['id'],))
    with pytest.raises(AccessDenied,match='not_active'):
        cases.advance_coordinator(tenant.token,plan['id'])
    assert cases.get_coordinator(tenant.token,plan['id'])['status']=='expired'


def test_other_tenant_and_viewer_cannot_control(tenant,cases,plan,case):
    password=secrets.token_urlsafe(24)
    other,_=provision_organization(tenant.db.owner,'Generated other coordinator tenant','owner',password)
    token=tenant.service.login(other,'owner',password).token
    for operation in (cases.get_coordinator,cases.advance_coordinator,cases.stop_coordinator):
        with pytest.raises(AccessDenied): operation(token,plan['id'])
    tenant.service.create_member(tenant.token,'generated-viewer',password,'viewer')
    viewer=tenant.service.login(tenant.org,'generated-viewer',password).token
    assert cases.get_coordinator(viewer,plan['id'])['status']=='pending_local_steps'
    for operation in (cases.advance_coordinator,cases.stop_coordinator):
        with pytest.raises(AccessDenied): operation(viewer,plan['id'])
    with pytest.raises(AccessDenied): cases.begin_coordinator(viewer,case['id'],uuid4())


def test_other_analyst_cannot_drive_creator_plan(tenant,cases,case):
    tokens=[]
    for name in ('generated-analyst-a','generated-analyst-b'):
        password=secrets.token_urlsafe(24)
        tenant.service.create_member(tenant.token,name,password,'analyst')
        tokens.append(tenant.service.login(tenant.org,name,password).token)
    plan=cases.begin_coordinator(tokens[0],case['id'],uuid4())
    with pytest.raises(AccessDenied): cases.advance_coordinator(tokens[1],plan['id'])
    with pytest.raises(AccessDenied): cases.stop_coordinator(tokens[1],plan['id'])
    assert cases.advance_coordinator(tokens[0],plan['id'])['completed_steps']==1


def test_creator_demotion_blocks_admin_takeover_until_new_plan(tenant,cases,case):
    password=secrets.token_urlsafe(24)
    member=tenant.service.create_member(tenant.token,'generated-plan-creator',password,'analyst')
    token=tenant.service.login(tenant.org,'generated-plan-creator',password).token
    plan=cases.begin_coordinator(token,case['id'],uuid4())
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.memberships SET role='viewer' WHERE organization_id=%s AND user_id=%s",(tenant.org,member))
    assert cases.get_coordinator(tenant.token,plan['id'])['status']=='authority_lost'
    with pytest.raises(AccessDenied): cases.advance_coordinator(tenant.token,plan['id'])
    assert cases.stop_coordinator(tenant.token,plan['id'])['status']=='stopped'


def test_audit_failure_rolls_back_plan_and_claim(tenant,cases,case,plan):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.begin_coordinator(tenant.token,case['id'],uuid4())
        with pytest.raises(IdentityUnavailable): cases.advance_coordinator(tenant.token,plan['id'])
    finally:
        audit_permission(tenant,True)
    assert cases.get_coordinator(tenant.token,plan['id'])['steps'][0]['claimed_at'] is None
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.coordinator_runs WHERE case_id=%s',(case['id'],)).fetchone()['n']==1


def test_interrupted_specialist_receipt_reuses_original_request(tenant,cases,case,plan,monkeypatch):
    cases.advance_coordinator(tenant.token,plan['id'])
    original=coordinator._audit
    def fail_receipt(conn,event,*args):
        if event=='coordinator.local_step_completed': raise IdentityUnavailable('generated_receipt_failure')
        return original(conn,event,*args)
    monkeypatch.setattr(coordinator,'_audit',fail_receipt)
    with pytest.raises(IdentityUnavailable): cases.advance_coordinator(tenant.token,plan['id'])
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE case_id=%s',(case['id'],)).fetchone()['n']==1
    monkeypatch.setattr(coordinator,'_audit',original)
    done=CaseService(tenant.db.app,cases.store).advance_coordinator(tenant.token,plan['id'])
    assert done['status']=='local_plan_complete'
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE case_id=%s',(case['id'],)).fetchone()['n']==1


def test_wrong_step_output_and_tampered_receipt_are_denied(tenant,cases,plan,monkeypatch):
    original=coordinator.execute_local
    monkeypatch.setattr(coordinator,'execute_local',lambda *args:dict(operation='execute_external'))
    with pytest.raises(AccessDenied,match='binding_failed'): cases.advance_coordinator(tenant.token,plan['id'])
    monkeypatch.setattr(coordinator,'execute_local',original)
    cases.advance_coordinator(tenant.token,plan['id'])
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.coordinator_results SET result_digest=%s WHERE run_id=%s",('0'*64,plan['id']))
    with pytest.raises(AccessDenied,match='integrity_failed'): cases.get_coordinator(tenant.token,plan['id'])


def test_runtime_cannot_mutate_or_delete_coordinator_history(tenant,plan):
    for table in ('coordinator_runs','coordinator_sources','coordinator_steps','coordinator_claims','coordinator_results','coordinator_stops'):
        with psycopg.connect(tenant.db.app) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute('DELETE FROM gabriel_identity.'+table)


@pytest.mark.parametrize('mode',['expiry','session_revocation'])
def test_authority_or_deadline_loss_during_execution_blocks_receipt(tenant,cases,plan,monkeypatch,mode):
    original=coordinator.execute_local
    def interrupted(*args):
        result=original(*args)
        if mode=='session_revocation':
            tenant.service.logout(tenant.token)
        else:
            with owner_connection(tenant.db) as conn:
                conn.execute("UPDATE gabriel_identity.coordinator_runs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE id=%s",(plan['id'],))
        return result
    monkeypatch.setattr(coordinator,'execute_local',interrupted)
    with pytest.raises((AccessDenied,AuthenticationDenied)):
        cases.advance_coordinator(tenant.token,plan['id'])
    token=tenant.service.login(tenant.org,'owner',tenant.password).token
    status=cases.get_coordinator(token,plan['id'])
    assert status['completed_steps']==0 and status['steps'][0]['claimed_at'] is not None


def test_database_fk_prevents_cross_case_evidence_binding(tenant,cases,case,plan):
    other=cases.create_case(tenant.token,'Generated other source case')
    artifact=cases.acquire(tenant.token,other['id'],uuid4(),'Generated separate evidence','Generated fixture',approved=True)
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute('INSERT INTO gabriel_identity.coordinator_sources VALUES (%s,%s,%s,%s,%s)',
                (tenant.org,plan['id'],case['id'],artifact['id'],artifact['digest']))


def test_schema_upgrade_failure_rolls_back_all_new_tables(tenant,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v17(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v17.sql' else value
    monkeypatch.setattr(Path,'read_text',broken)
    with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT to_regclass('gabriel_identity.coordinator_runs') AS t").fetchone()['t'] is None
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==16
    monkeypatch.setattr(Path,'read_text',original)
    migrate(tenant.db.owner)
