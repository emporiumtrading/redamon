"""Persisted task admission and receipt semantics against real PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import (AccessDenied, AuthenticationDenied, IdentityUnavailable,
    InvalidIdentityInput, migrate, provision_organization)
from testing.gabriel_identity.db_history import remove_v4
from testing.gabriel_identity.test_identity_integration import database, tenant, owner_connection

pytestmark = pytest.mark.integration
REQUEST = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'task fixture'}}


@pytest.fixture
def worker(tenant):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'task fixture',['capabilities.list','evidence.hash'],3600,3)
    grant = service.issue_service(tenant.token,'task worker',task['id'],['evidence.hash'],3600)
    return service,task,grant


def executions(tenant):
    with owner_connection(tenant.db) as conn:
        return conn.execute('SELECT * FROM gabriel_identity.task_executions WHERE organization_id=%s',(tenant.org,)).fetchall()


def test_task_and_receipt_persist_without_request_content(tenant,worker):
    service,task,grant = worker
    request_id = uuid4()
    response = service.execute_service(grant.token,task['id'],REQUEST,request_id)
    assert response['request_id']==str(request_id)
    assert response['result']['digest']==sha256(REQUEST['arguments']['content'].encode()).hexdigest()
    assert ServiceIdentityService(tenant.db.app).get_task(tenant.token,task['id'])['used_steps']==1
    rows = executions(tenant)
    assert len(rows)==1 and rows[0]['response']==response
    assert REQUEST['arguments']['content'] not in repr(rows)
    assert tenant.token not in repr(rows) and grant.token not in repr(rows)
    assert task['created_by']==tenant.owner and task['organization_id']==tenant.org


def test_new_grants_cannot_match_the_previous_worker_protocol(tenant,worker):
    _,_,grant = worker
    assert grant.token.startswith('gbs2_')
    with owner_connection(tenant.db) as conn:
        row = conn.execute('SELECT audience FROM gabriel_identity.service_grants WHERE id=%s',(grant.id,)).fetchone()
        assert row['audience']=='gabriel-local-worker-v2'
        assert conn.execute("SELECT id FROM gabriel_identity.service_grants WHERE token_digest=%s AND audience='gabriel-local-worker-v1'",
            (sha256(grant.token.encode()).hexdigest(),)).fetchone() is None


def test_duplicate_request_returns_same_receipt_after_budget_exhaustion(tenant,worker):
    service,task,grant = worker
    ids = [uuid4() for _ in range(3)]
    first = service.execute_service(grant.token,task['id'],REQUEST,ids[0])
    for request_id in ids[1:]:
        service.execute_service(grant.token,task['id'],REQUEST,request_id)
    assert service.get_task(tenant.token,task['id'])['state']=='exhausted'
    reordered = {'arguments':REQUEST['arguments'],'operation':REQUEST['operation'],'schema_version':1}
    assert service.execute_service(grant.token,task['id'],reordered,ids[0])==first
    assert service.get_task(tenant.token,task['id'])['used_steps']==3 and len(executions(tenant))==3
    with pytest.raises(AccessDenied):
        service.execute_service(grant.token,task['id'],REQUEST,uuid4())
    with pytest.raises(AccessDenied):
        service.issue_service(tenant.token,'exhausted',task['id'],['evidence.hash'])


def test_idempotency_conflicts_on_changed_payload_or_service(tenant,worker):
    service,task,grant = worker
    second = service.issue_service(tenant.token,'other worker',task['id'],['evidence.hash'])
    request_id = uuid4()
    service.execute_service(grant.token,task['id'],REQUEST,request_id)
    with pytest.raises(AccessDenied,match='task_request_conflict'):
        service.execute_service(grant.token,task['id'],{**REQUEST,'arguments':{'content':'different fixture'}},request_id)
    with pytest.raises(AccessDenied,match='task_request_conflict'):
        service.execute_service(second.token,task['id'],REQUEST,request_id)
    assert service.get_task(tenant.token,task['id'])['used_steps']==1 and len(executions(tenant))==1


def test_concurrent_duplicates_commit_one_step_and_one_receipt(tenant,worker):
    service,task,grant = worker
    request_id = uuid4()
    def run(_):
        return ServiceIdentityService(tenant.db.app).execute_service(grant.token,task['id'],REQUEST,request_id)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(run,range(4)))
    assert all(response==responses[0] for response in responses)
    assert len(executions(tenant))==1 and service.get_task(tenant.token,task['id'])['used_steps']==1


def test_concurrent_unique_requests_cannot_overspend_task(tenant,worker):
    service,task,grant = worker
    def run(_):
        try:
            return service.execute_service(grant.token,task['id'],REQUEST,uuid4())
        except AccessDenied:
            return 'budget denied'
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(run,range(5)))
    assert results.count('budget denied')==2
    assert len(executions(tenant))==3 and service.get_task(tenant.token,task['id'])['used_steps']==3


@pytest.mark.parametrize('state',['cancelled','completed'])
def test_terminal_state_revokes_grants_and_cannot_be_reopened(tenant,worker,state):
    service,task,grant = worker
    request_id = uuid4()
    service.execute_service(grant.token,task['id'],REQUEST,request_id)
    assert service.end_task(tenant.token,task['id'],state)['state']==state
    assert service.end_task(tenant.token,task['id'],state)['state']==state
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token,task['id'],REQUEST,request_id)
    with pytest.raises(AccessDenied):
        service.issue_service(tenant.token,'closed',task['id'],['evidence.hash'])
    with pytest.raises(AccessDenied):
        service.end_task(tenant.token,task['id'],'completed' if state=='cancelled' else 'cancelled')


def test_expiry_blocks_new_grants_and_receipt_replay(tenant,worker):
    service,task,grant = worker
    request_id = uuid4()
    service.execute_service(grant.token,task['id'],REQUEST,request_id)
    with owner_connection(tenant.db) as conn:
        conn.execute('''UPDATE gabriel_identity.investigation_tasks SET created_at=clock_timestamp()-interval '2 hours',
            expires_at=clock_timestamp()-interval '90 minutes' WHERE organization_id=%s AND id=%s''',(tenant.org,task['id']))
    assert service.get_task(tenant.token,task['id'])['state']=='expired'
    with pytest.raises(AccessDenied):
        service.execute_service(grant.token,task['id'],REQUEST,request_id)
    with pytest.raises(AccessDenied):
        service.issue_service(tenant.token,'expired',task['id'],['evidence.hash'])


def test_grant_expiry_never_exceeds_task_deadline(tenant):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'short task',['evidence.hash'],60,2)
    grant = service.issue_service(tenant.token,'bounded lifetime',task['id'],['evidence.hash'],3600)
    assert grant.expires_at==task['expires_at']


def test_unknown_task_or_overbroad_operation_never_issues_grant(tenant):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'limited task',['evidence.hash'])
    with pytest.raises(AccessDenied):
        service.issue_service(tenant.token,'unknown task',uuid4(),['evidence.hash'])
    with pytest.raises(AccessDenied):
        service.issue_service(tenant.token,'overbroad',task['id'],['capabilities.list'])
    assert service.list_services(tenant.token)==[]


def test_foreign_task_is_not_readable_cancellable_or_grantable(tenant,worker):
    service,task,_ = worker
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Other task fixture','owner',password)
    token = service.login(org,'owner',password).token
    assert service.list_tasks(token)==[]
    for call in (lambda:service.get_task(token,task['id']),lambda:service.end_task(token,task['id'],'cancelled'),
                 lambda:service.issue_service(token,'foreign',task['id'],['evidence.hash'])):
        with pytest.raises(AccessDenied):
            call()


def test_roles_and_creator_revocation_are_enforced(tenant):
    service = ServiceIdentityService(tenant.db.app)
    password = secrets.token_urlsafe(24)
    analyst = service.create_member(tenant.token,'task-analyst',password,'analyst')
    token = service.login(tenant.org,'task-analyst',password).token
    task = service.create_task(token,'analyst task',['evidence.hash'])
    grant = service.issue_service(tenant.token,'owner approved',task['id'],['evidence.hash'])
    owner_task = service.create_task(tenant.token,'owner task',['evidence.hash'])
    with pytest.raises(AccessDenied):
        service.end_task(token,owner_task['id'],'cancelled')
    service.set_membership(tenant.token,analyst,'viewer',True)
    assert service.get_task(tenant.token,task['id'])['creator_authorized'] is False
    with pytest.raises(AccessDenied):
        service.execute_service(grant.token,task['id'],REQUEST,uuid4())
    viewer_token = service.login(tenant.org,'task-analyst',password).token
    assert service.get_task(viewer_token,task['id'])['id']==task['id']
    with pytest.raises(AccessDenied):
        service.create_task(viewer_token,'not allowed',['evidence.hash'])
    with pytest.raises(AccessDenied):
        service.end_task(viewer_token,task['id'],'cancelled')


def test_service_credential_has_no_task_management_authority(tenant,worker):
    service,task,grant = worker
    for call in (lambda:service.create_task(grant.token,'nested',['evidence.hash']),
                 lambda:service.list_tasks(grant.token),lambda:service.get_task(grant.token,task['id']),
                 lambda:service.end_task(grant.token,task['id'],'cancelled')):
        with pytest.raises(AuthenticationDenied):
            call()


def test_audit_failure_rolls_back_task_budget_receipt_and_cancellation(tenant,worker):
    service,task,grant = worker
    request_id = uuid4()
    original = service.execute_service(grant.token,task['id'],REQUEST,request_id)
    with owner_connection(tenant.db) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.audit_events FROM gabriel_identity_app')
    try:
        for call in (lambda:service.create_task(tenant.token,'not persisted',['evidence.hash']),
                     lambda:service.end_task(tenant.token,task['id'],'cancelled'),
                     lambda:service.execute_service(grant.token,task['id'],REQUEST,uuid4()),
                     lambda:service.execute_service(grant.token,task['id'],REQUEST,request_id)):
            with pytest.raises(IdentityUnavailable):
                call()
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.audit_events TO gabriel_identity_app')
    assert len(service.list_tasks(tenant.token))==1
    assert service.get_task(tenant.token,task['id'])['used_steps']==1 and len(executions(tenant))==1
    assert service.execute_service(grant.token,task['id'],REQUEST,request_id)==original


def test_cancel_concurrent_with_dispatch_has_no_later_admission(tenant,worker):
    service,task,grant = worker
    def run():
        try:
            return service.execute_service(grant.token,task['id'],REQUEST,uuid4())
        except (AccessDenied,AuthenticationDenied):
            return 'cancelled'
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(run)
        service.end_task(tenant.token,task['id'],'cancelled')
        assert future.result() is not None
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token,task['id'],REQUEST,uuid4())
    assert len(executions(tenant)) in {0,1}


@pytest.mark.parametrize('operation',['UPDATE','DELETE','TRUNCATE'])
def test_runtime_cannot_rewrite_or_erase_receipts(tenant,worker,operation):
    query = {'UPDATE':"UPDATE gabriel_identity.task_executions SET request_digest=repeat('0',64)",
        'DELETE':'DELETE FROM gabriel_identity.task_executions','TRUNCATE':'TRUNCATE gabriel_identity.task_executions'}[operation]
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query)
        conn.rollback()


@pytest.mark.parametrize('ttl,steps',[(True,1),(59,1),(3601,1),(900,False),(900,0),(900,1001)])
def test_invalid_task_limits_fail_closed(tenant,ttl,steps):
    with pytest.raises(InvalidIdentityInput):
        ServiceIdentityService(tenant.db.app).create_task(tenant.token,'bad limit',['evidence.hash'],ttl,steps)


@pytest.mark.parametrize('name,operations',[('', ['evidence.hash']),('bad\nname',['evidence.hash']),
    ('a'*81,['evidence.hash']),('valid',[]),('valid',['browser.login']),('valid',['evidence.hash']*2)])
def test_invalid_task_name_or_operations_rejected(tenant,name,operations):
    with pytest.raises(InvalidIdentityInput):
        ServiceIdentityService(tenant.db.app).create_task(tenant.token,name,operations)


def test_active_task_quota_and_bounded_listing(tenant):
    service = ServiceIdentityService(tenant.db.app)
    tasks = [service.create_task(tenant.token,'bounded task',['evidence.hash']) for _ in range(100)]
    assert len(service.list_tasks(tenant.token))==100
    with pytest.raises(AccessDenied):
        service.create_task(tenant.token,'overflow',['evidence.hash'])
    service.end_task(tenant.token,tasks[0]['id'],'cancelled')
    assert service.create_task(tenant.token,'replacement',['evidence.hash'])['id']


def test_database_rejects_forged_unbound_active_grant(tenant,worker):
    service,task,grant = worker
    other = service.create_task(tenant.token,'other task',['evidence.hash'])
    with owner_connection(tenant.db) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute('UPDATE gabriel_identity.service_grants SET bound_task_id=NULL WHERE organization_id=%s AND id=%s',(tenant.org,grant.id))
        conn.rollback()
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute('''INSERT INTO gabriel_identity.task_executions
                (organization_id,task_id,request_id,service_id,request_digest,response)
                VALUES (%s,%s,%s,%s,repeat('0',64),'{}'::jsonb)''',
                (tenant.org,other['id'],uuid4(),grant.id))
        conn.rollback()
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            fake = uuid4()
            conn.execute('UPDATE gabriel_identity.service_grants SET bound_task_id=%s,task_id=%s WHERE organization_id=%s AND id=%s',
                         (fake,fake,tenant.org,grant.id))
        conn.rollback()


def test_v3_upgrade_revokes_old_labels_without_inventing_tasks(tenant,worker):
    service,task,grant = worker
    with owner_connection(tenant.db) as conn:
        remove_v4(conn)
    migrate(tenant.db.owner)
    assert service.whoami(tenant.token).user_id==tenant.owner
    assert service.list_tasks(tenant.token)==[]
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token,task['id'],REQUEST,uuid4())
    with owner_connection(tenant.db) as conn:
        row = conn.execute('SELECT revoked_at,bound_task_id FROM gabriel_identity.service_grants WHERE organization_id=%s AND id=%s',
                           (tenant.org,grant.id)).fetchone()
        assert row['revoked_at'] is not None and row['bound_task_id'] is None
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE target_id=%s AND event='identity.unbound_service_migrated'",(grant.id,)).fetchone()['n']==1


def test_cli_creates_task_and_replays_worker_request(tenant,tmp_path):
    tokenfile = tmp_path/'human'
    tokenfile.write_text(tenant.token)
    def cli(*args,data=None):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.cli',*args],input=data,
            capture_output=True,text=True,timeout=10)
        assert not result.stderr and tenant.token not in result.stdout and tenant.db.app not in result.stdout
        return result.returncode,json.loads(result.stdout)
    code,task = cli('task-create','--token-file',str(tokenfile),'--name','CLI task','--operation','evidence.hash','--max-steps','1')
    assert code==0
    task_id = task['result']['id']
    code,grant = cli('issue-service','--token-file',str(tokenfile),'--name','CLI worker','--task-id',task_id,'--operation','evidence.hash')
    assert code==0
    workerfile = tmp_path/'worker'
    workerfile.write_text(grant['result']['service_token'])
    request_id = str(uuid4())
    command = ('service-execute','--token-file',str(workerfile),'--task-id',task_id,'--request-id',request_id)
    code,first = cli(*command,data=json.dumps(REQUEST))
    assert code==0
    code,again = cli(*command,data=json.dumps(REQUEST))
    assert code==0 and again==first
    code,state = cli('task-get','--token-file',str(tokenfile),'--task-id',task_id)
    assert code==0 and state['result']['used_steps']==1
    assert cli('task-complete','--token-file',str(tokenfile),'--task-id',task_id)[0]==0
    assert cli(*command,data=json.dumps(REQUEST))[0]==1


def test_interrupted_v4_migration_rolls_back_revocations_and_audit(tenant,worker,monkeypatch):
    from pathlib import Path
    _,_,grant = worker
    original = Path.read_text
    with owner_connection(tenant.db) as conn:
        remove_v4(conn)
        count = conn.execute('SELECT count(*) AS n FROM gabriel_identity.audit_events').fetchone()['n']
    def interrupted(path,*args,**kwargs):
        text = original(path,*args,**kwargs)
        return text+'\nSELECT 1/0;' if path.name=='schema_v4.sql' else text
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable):
                migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.investigation_tasks') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.audit_events').fetchone()['n']==count
            assert conn.execute('SELECT revoked_at FROM gabriel_identity.service_grants WHERE id=%s',(grant.id,)).fetchone()['revoked_at'] is None
    finally:
        migrate(tenant.db.owner)
