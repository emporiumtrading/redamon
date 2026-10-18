"""Human approval and transactional local effects against real PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.actions import ActionService
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import (AccessDenied,AuthenticationDenied,IdentityUnavailable,
    InvalidIdentityInput,migrate,provision_organization)
from testing.gabriel_identity.db_history import remove_v6
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,intake,audit_permission
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection

pytestmark = pytest.mark.integration


@pytest.fixture
def actions(tenant,cases):
    return ActionService(tenant.db.app,cases.store)


@pytest.fixture
def pending(tenant,actions,case,evidence):
    actions.set_policy(tenant.token)
    password = secrets.token_urlsafe(24)
    admin = actions.create_member(tenant.token,'review-admin',password,'admin')
    token = actions.login(tenant.org,'review-admin',password).token
    request = actions.propose_close(tenant.token,case['id'],uuid4(),'Reviewed generated case closure')
    actions.submit(tenant.token,request['id'])
    return SimpleNamespace(request=request,admin=admin,token=token)


@pytest.fixture
def approved(tenant,actions,pending):
    actions.approve(pending.token,pending.request['id'],pending.request['digest'])
    return pending


def test_policy_is_required_and_only_real_local_operation_is_proposed(tenant,actions,case,evidence):
    with pytest.raises(AccessDenied,match='action_policy_required'):
        actions.propose_close(tenant.token,case['id'],uuid4(),'Generated proposal')
    with pytest.raises(AccessDenied,match='case_closure_approval_required'):
        actions.close_case(tenant.token,case['id'])
    actions.set_policy(tenant.token)
    row = actions.propose_close(tenant.token,case['id'],uuid4(),'Generated proposal')
    assert row['state']=='proposed' and row['operation']=='case.close'
    assert row['payload']['scope']=='gabriel-local-case' and len(row['payload']['evidence'])==1
    assert 'requester_session' not in row and tenant.token not in repr(row)
    with pytest.raises(AccessDenied):
        actions.approve(tenant.token,row['id'],row['digest'])


def test_approval_closes_exact_case_and_records_atomic_receipt(tenant,actions,case,evidence,approved):
    row = actions.get_action(tenant.token,approved.request['id'])
    assert row['state']=='approved' and row['approval']['approved_by']==approved.admin
    assert [r['decision'] for r in row['decisions']]==['submitted','approved']
    assert 'approver_session' not in row['approval']
    result = actions.execute(tenant.token,row['id'])
    assert result['case_id']==str(case['id']) and result['digest']==row['digest']
    assert actions.get_case(tenant.token,case['id'])['case']['state']=='closed'
    fresh = ActionService(tenant.db.app,actions.store)
    assert fresh.execute(tenant.token,row['id'])==result
    saved = fresh.get_action(tenant.token,row['id'])
    assert saved['state']=='succeeded' and saved['execution']['result']==result
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE event='case.closed' AND target_id=%s",(case['id'],)).fetchone()['n']==1


def test_default_self_approval_denied_and_explicit_local_policy_can_allow_it(tenant,actions,pending):
    with pytest.raises(AccessDenied,match='action_self_approval_denied'):
        actions.approve(tenant.token,pending.request['id'],pending.request['digest'])
    actions.set_policy(tenant.token,distinct_approver=False)
    with pytest.raises(AccessDenied,match='action_policy_changed'):
        actions.approve(tenant.token,pending.request['id'],pending.request['digest'])
    request = actions.propose_close(tenant.token,pending.request['case_id'],uuid4(),'New policy reviewed local closure')
    actions.submit(tenant.token,request['id'])
    actions.approve(tenant.token,request['id'],request['digest'])
    assert actions.execute(tenant.token,request['id'])['state']=='closed'


def test_wrong_digest_cannot_approve_and_no_execution_before_approval(tenant,actions,pending):
    with pytest.raises(AccessDenied,match='action_not_approvable'):
        actions.approve(pending.token,pending.request['id'],'0'*64)
    with pytest.raises(AccessDenied):
        actions.execute(tenant.token,pending.request['id'])
    assert actions.get_action(tenant.token,pending.request['id'])['state']=='pending_approval'


def test_concurrent_proposal_retries_preserve_one_immutable_request(tenant,actions,case,evidence):
    actions.set_policy(tenant.token)
    key = uuid4()
    def propose(_):
        return actions.propose_close(tenant.token,case['id'],key,'Concurrent proposal')
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(propose,range(4)))
    assert len({row['id'] for row in rows})==1
    with pytest.raises(AccessDenied,match='action_request_conflict'):
        actions.propose_close(tenant.token,case['id'],key,'Changed rationale')
    with pytest.raises(AccessDenied,match='action_request_conflict'):
        actions.propose_close(tenant.token,case['id'],key,'Concurrent proposal',ttl=1000)


def test_concurrent_approvals_admit_one_decision(tenant,actions,pending):
    def approve(_):
        try:
            actions.approve(pending.token,pending.request['id'],pending.request['digest'])
            return 'approved'
        except AccessDenied:
            return 'denied'
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(approve,range(4)))
    assert values.count('approved')==1
    assert len(actions.get_action(tenant.token,pending.request['id'])['decisions'])==2


def test_concurrent_execution_replays_one_case_effect_and_receipt(tenant,actions,approved):
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda _:actions.execute(tenant.token,approved.request['id']),range(4)))
    assert all(value==values[0] for value in values)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.action_executions WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==1
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE event='case.closed' AND target_id=%s",(approved.request['case_id'],)).fetchone()['n']==1


@pytest.mark.parametrize('stage',['approval','execution'])
def test_new_evidence_invalidates_prior_snapshot(tenant,actions,case,pending,stage):
    if stage=='execution':
        actions.approve(pending.token,pending.request['id'],pending.request['digest'])
    intake(tenant,actions,case)
    with pytest.raises(AccessDenied,match='action_evidence_changed'):
        if stage=='approval':
            actions.approve(pending.token,pending.request['id'],pending.request['digest'])
        else:
            actions.execute(tenant.token,pending.request['id'])
    assert actions.get_case(tenant.token,case['id'])['case']['state']=='open'


def test_access_custody_append_does_not_invalidate_verified_proposal(tenant,actions,evidence,approved):
    actions.read_evidence(tenant.token,evidence['id'])
    assert actions.execute(tenant.token,approved.request['id'])['state']=='closed'


@pytest.mark.parametrize('damage',['policy_revision','policy_contents','payload','case_version','custody'])
def test_changed_policy_target_payload_or_custody_denies(tenant,actions,case,approved,damage):
    if damage=='policy_revision':
        actions.set_policy(tenant.token,approval_ttl=600)
    else:
        with owner_connection(tenant.db) as conn:
            if damage=='policy_contents':
                conn.execute('UPDATE gabriel_identity.action_policies SET distinct_approver=false WHERE organization_id=%s',(tenant.org,))
            elif damage=='payload':
                conn.execute("UPDATE gabriel_identity.action_requests SET payload=jsonb_set(payload,'{rationale}','\"changed\"'::jsonb) WHERE organization_id=%s",(tenant.org,))
            elif damage=='case_version':
                conn.execute("UPDATE gabriel_identity.cases SET created_at=created_at-interval '1 second' WHERE organization_id=%s",(tenant.org,))
            else:
                conn.execute('DELETE FROM gabriel_identity.custody_events WHERE organization_id=%s AND sequence=2',(tenant.org,))
    with pytest.raises((AccessDenied,EvidenceError)):
        actions.execute(tenant.token,approved.request['id'])
    assert actions.get_case(tenant.token,case['id'])['case']['state']=='open'


@pytest.mark.parametrize('actor,change',[('requester','logout'),('approver','logout'),('approver','demote'),('approver','disable'),('requester','password')])
def test_current_actor_authority_is_required_at_execution(tenant,actions,approved,actor,change):
    target = tenant.owner if actor=='requester' else approved.admin
    if change=='logout':
        actions.logout(tenant.token if actor=='requester' else approved.token)
    elif change=='demote':
        actions.set_membership(tenant.token,target,'analyst',True)
    elif change=='disable':
        actions.set_membership(tenant.token,target,'admin',False)
    else:
        actions.reset_password(tenant.token,target,secrets.token_urlsafe(24))
    executor = actions.login(tenant.org,'owner',tenant.password).token if change=='logout' and actor=='requester' else approved.token if change=='password' else tenant.token
    with pytest.raises((AccessDenied,AuthenticationDenied)):
        actions.execute(executor,approved.request['id'])


@pytest.mark.parametrize('what',['request','approval'])
def test_expiry_is_visible_and_cannot_dispatch(tenant,actions,approved,what):
    with owner_connection(tenant.db) as conn:
        if what=='request':
            conn.execute("UPDATE gabriel_identity.action_requests SET created_at=statement_timestamp()-interval '30 minutes',expires_at=statement_timestamp()-interval '15 minutes' WHERE organization_id=%s",(tenant.org,))
        else:
            conn.execute("UPDATE gabriel_identity.action_approvals SET created_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '10 minutes' WHERE organization_id=%s",(tenant.org,))
    assert actions.get_action(tenant.token,approved.request['id'])['effective_state']=='expired'
    with pytest.raises(AccessDenied):
        actions.execute(tenant.token,approved.request['id'])


@pytest.mark.parametrize('state',['cancelled','rejected'])
def test_termination_is_durable_and_blocks_execution(tenant,actions,approved,state):
    actions.end(tenant.token,approved.request['id'],state)
    assert actions.get_action(tenant.token,approved.request['id'])['state']==state
    with pytest.raises(AccessDenied):
        actions.execute(tenant.token,approved.request['id'])
    with pytest.raises(AccessDenied):
        actions.submit(tenant.token,approved.request['id'])


def test_cancel_race_has_no_execution_after_committed_cancellation(tenant,actions,approved):
    def execute():
        try:
            return actions.execute(tenant.token,approved.request['id'])['state']
        except AccessDenied:
            return 'cancelled'
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(execute)
        try:
            actions.end(tenant.token,approved.request['id'],'cancelled')
        except AccessDenied:
            pass
        outcome = future.result()
    row = actions.get_action(tenant.token,approved.request['id'])
    assert (row['state'],outcome) in {('cancelled','cancelled'),('succeeded','closed')}
    if row['state']=='cancelled':
        with pytest.raises(AccessDenied):
            actions.execute(tenant.token,row['id'])


def test_foreign_tenant_cannot_view_decide_or_execute(tenant,actions,pending):
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Other generated action tenant','owner',password)
    token = actions.login(org,'owner',password).token
    for call in (lambda:actions.get_action(token,pending.request['id']),
        lambda:actions.approve(token,pending.request['id'],pending.request['digest']),
        lambda:actions.execute(token,pending.request['id']),lambda:actions.end(token,pending.request['id'],'cancelled')):
        with pytest.raises(AccessDenied):
            call()


@pytest.mark.parametrize('role',['viewer','analyst'])
def test_role_separates_requesting_approving_and_executing(tenant,actions,case,pending,role):
    password = secrets.token_urlsafe(24)
    actions.create_member(tenant.token,'limited-member',password,role)
    token = actions.login(tenant.org,'limited-member',password).token
    assert actions.get_action(token,pending.request['id'])['id']==pending.request['id']
    for call in (lambda:actions.set_policy(token),lambda:actions.approve(token,pending.request['id'],pending.request['digest']),
                 lambda:actions.execute(token,pending.request['id'])):
        with pytest.raises(AccessDenied):
            call()
    if role=='analyst':
        request = actions.propose_close(token,case['id'],uuid4(),'Analyst proposal')
        actions.submit(token,request['id'])
        actions.end(token,request['id'],'cancelled')
    else:
        with pytest.raises(AccessDenied):
            actions.propose_close(token,case['id'],uuid4(),'Viewer proposal')


def test_worker_has_no_action_management_authority(tenant,actions,case,pending):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'generated action worker',['evidence.hash'])
    worker = service.issue_service(tenant.token,'generated worker',task['id'],['evidence.hash'])
    for call in (lambda:actions.get_action(worker.token,pending.request['id']),lambda:actions.set_policy(worker.token),
                 lambda:actions.propose_close(worker.token,case['id'],uuid4(),'Denied worker proposal')):
        with pytest.raises(AuthenticationDenied):
            call()


def test_audit_failure_rolls_back_policy_approval_and_cancellation(tenant,actions,pending):
    audit_permission(tenant,False)
    try:
        for call in (lambda:actions.set_policy(tenant.token),
            lambda:actions.approve(pending.token,pending.request['id'],pending.request['digest']),
            lambda:actions.end(tenant.token,pending.request['id'],'cancelled')):
            with pytest.raises(IdentityUnavailable):
                call()
    finally:
        audit_permission(tenant,True)
    assert actions.get_policy(tenant.token)['revision']==1
    row = actions.get_action(tenant.token,pending.request['id'])
    assert row['state']=='pending_approval' and 'approval' not in row and len(row['decisions'])==1


def test_receipt_failure_after_case_update_rolls_back_real_local_effect(tenant,actions,case,approved):
    with owner_connection(tenant.db) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.action_executions FROM gabriel_identity_app')
    try:
        with pytest.raises(IdentityUnavailable):
            actions.execute(tenant.token,approved.request['id'])
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.action_executions TO gabriel_identity_app')
    assert actions.get_case(tenant.token,case['id'])['case']['state']=='open'
    row = actions.get_action(tenant.token,approved.request['id'])
    assert row['state']=='approved' and row['execution'] is None
    assert actions.execute(tenant.token,row['id'])['state']=='closed'


def test_approver_session_expiring_during_verification_denies_dispatch(tenant,actions,case,approved,monkeypatch):
    original = ActionService._unchanged
    def expires_after_verification(self,conn,p,row,target):
        original(self,conn,p,row,target)
        with owner_connection(tenant.db) as owner:
            owner.execute("UPDATE gabriel_identity.sessions SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE organization_id=%s AND user_id=%s",
                (tenant.org,approved.admin))
    with monkeypatch.context() as patch:
        patch.setattr(ActionService,'_unchanged',expires_after_verification)
        with pytest.raises(AccessDenied,match='action_approver_revoked'):
            actions.execute(tenant.token,approved.request['id'])
    assert actions.get_case(tenant.token,case['id'])['case']['state']=='open'
    assert actions.get_action(tenant.token,approved.request['id'])['execution'] is None


@pytest.mark.parametrize('table,column',[
    ('action_requests',"digest=repeat('0',64)"),('action_approvals',"digest=repeat('0',64)"),
    ('action_policies','distinct_approver=false'),('action_decisions',"decision='cancelled'"),
    ('action_executions',"digest=repeat('0',64)")])
def test_runtime_cannot_rewrite_immutable_policy_decision_or_receipt(tenant,table,column):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f'UPDATE gabriel_identity.{table} SET {column}')
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f'DELETE FROM gabriel_identity.{table}')
        conn.rollback()


@pytest.mark.parametrize('ttl,distinct',[(59,True),(901,True),(True,True),(300,1)])
def test_invalid_policy_rejected(tenant,actions,ttl,distinct):
    with pytest.raises(InvalidIdentityInput):
        actions.set_policy(tenant.token,approval_ttl=ttl,distinct_approver=distinct)


def test_v5_upgrade_preserves_case_and_evidence_without_invented_approval(tenant,actions,case,evidence):
    with owner_connection(tenant.db) as conn:
        remove_v6(conn)
    migrate(tenant.db.owner)
    assert actions.read_evidence(tenant.token,evidence['id']).metadata['id']==evidence['id']
    with pytest.raises(AccessDenied,match='action_policy_required'):
        actions.get_policy(tenant.token)
    with pytest.raises(AccessDenied,match='case_closure_approval_required'):
        actions.close_case(tenant.token,case['id'])


def test_interrupted_v6_migration_rolls_back_and_preserves_evidence(tenant,actions,evidence,monkeypatch):
    original = Path.read_text
    with owner_connection(tenant.db) as conn:
        remove_v6(conn)
    def interrupted(path,*args,**kwargs):
        value = original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v6.sql' else value
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable):
                migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.action_requests') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==5
        assert actions.read_evidence(tenant.token,evidence['id']).metadata['id']==evidence['id']
    finally:
        migrate(tenant.db.owner)
