"""Machine grants exercise real PostgreSQL and the shipped CLI, not authorization mocks."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import (AccessDenied, AuthenticationDenied, IdentityConfigurationError,
    IdentityUnavailable, InvalidIdentityInput, migrate)
from testing.gabriel_identity.test_identity_integration import database, tenant, owner_connection

pytestmark = pytest.mark.integration
REQUEST = {'schema_version':1, 'operation':'evidence.hash', 'arguments':{'content':'supplied test fixture'}}


@pytest.fixture
def machine(tenant):
    service = ServiceIdentityService(tenant.db.app)
    task = uuid4()
    grant = service.issue_service(tenant.token, 'fixture worker', task, ['evidence.hash'])
    return service, task, grant


def test_machine_identity_persists_without_raw_credential(tenant, machine):
    service, task, grant = machine
    result = ServiceIdentityService(tenant.db.app).execute_service(grant.token, task, REQUEST)
    assert result['organization_id'] == str(tenant.org)
    assert result['service_id'] == str(grant.id) and result['task_id'] == str(task)
    assert result['result']['digest'] == sha256(REQUEST['arguments']['content'].encode()).hexdigest()
    assert 'user_id' not in result and 'role' not in result
    with owner_connection(tenant.db) as conn:
        rows = conn.execute('SELECT * FROM gabriel_identity.service_grants WHERE organization_id=%s', (tenant.org,)).fetchall()
        assert rows[0]['token_digest'] == sha256(grant.token.encode()).hexdigest()
        assert grant.token not in repr(rows) and grant.token not in repr(grant)
        events = conn.execute('SELECT * FROM gabriel_identity.audit_events WHERE organization_id=%s', (tenant.org,)).fetchall()
        assert any(row['event'] == 'identity.service_executed' and row['actor_id'] == grant.id for row in events)
        assert grant.token not in repr(events) and REQUEST['arguments']['content'] not in repr(events)


def test_service_cannot_impersonate_human_or_issue_credentials(tenant, machine):
    service, task, grant = machine
    for call in (lambda: service.whoami(grant.token), lambda: service.list_members(grant.token),
                 lambda: service.issue_service(grant.token, 'nested', task, ['evidence.hash']),
                 lambda: service.list_services(grant.token),
                 lambda: service.revoke_service(grant.token, grant.id),
                 lambda: service.execute(grant.token, REQUEST)):
        with pytest.raises(AuthenticationDenied):
            call()
    with pytest.raises(AuthenticationDenied):
        service.execute_service(tenant.token, task, REQUEST)


def test_task_operation_and_request_authority_are_restricted(tenant, machine):
    service, task, grant = machine
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token, uuid4(), REQUEST)
    for op in ('capabilities.list', 'isolate_endpoint', 'run_command', None, []):
        with pytest.raises(AccessDenied):
            service.execute_service(grant.token, task, {**REQUEST, 'operation': op})
    from gabriel.capabilities import InvalidRequest
    for field in ('organization_id', 'role', 'approved', 'task_id'):
        with pytest.raises(InvalidRequest):
            service.execute_service(grant.token, task, {**REQUEST, field:str(uuid4())})


@pytest.mark.parametrize('token', [None, '', 'gbs1_short', 'gbs1_'+'a'*43])
def test_forged_machine_credentials_denied(tenant, token):
    with pytest.raises(AuthenticationDenied):
        ServiceIdentityService(tenant.db.app).execute_service(token, uuid4(), REQUEST)


def test_cross_tenant_list_and_revocation_denied(tenant, machine):
    service, task, grant = machine
    from gabriel.identity.service import provision_organization
    secret = secrets.token_urlsafe(24)
    org, _ = provision_organization(tenant.db.owner, 'Other service fixture', 'owner', secret)
    token = service.login(org, 'owner', secret).token
    assert service.list_services(token) == []
    with pytest.raises(AccessDenied):
        service.revoke_service(token, grant.id)
    assert service.execute_service(grant.token, task, REQUEST)['organization_id'] == str(tenant.org)


@pytest.mark.parametrize('role', ['analyst', 'viewer'])
def test_unprivileged_human_cannot_manage_service_grants(tenant, machine, role):
    service, task, grant = machine
    secret = secrets.token_urlsafe(24)
    service.create_member(tenant.token, role, secret, role)
    token = service.login(tenant.org, role, secret).token
    for call in (lambda: service.issue_service(token, 'blocked', task, ['evidence.hash']),
                 lambda: service.list_services(token), lambda: service.revoke_service(token, grant.id)):
        with pytest.raises(AccessDenied):
            call()


def test_revocation_and_expiry_are_checked_on_each_execution(tenant, machine):
    service, task, grant = machine
    service.revoke_service(tenant.token, grant.id)
    service.revoke_service(tenant.token, grant.id)
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token, task, REQUEST)
    expired = service.issue_service(tenant.token, 'expired fixture', task, ['evidence.hash'])
    with owner_connection(tenant.db) as conn:
        conn.execute('''UPDATE gabriel_identity.service_grants SET created_at=clock_timestamp()-interval '2 hours',
            expires_at=clock_timestamp()-interval '1 hour' WHERE id=%s''', (expired.id,))
    with pytest.raises(AuthenticationDenied):
        service.execute_service(expired.token, task, REQUEST)


@pytest.mark.parametrize('change', ['membership', 'password', 'direct_disable'])
def test_issuer_lifecycle_invalidates_delegation(tenant, change):
    service = ServiceIdentityService(tenant.db.app)
    secret, task = secrets.token_urlsafe(24), uuid4()
    admin = service.create_member(tenant.token, 'issuing-admin', secret, 'admin')
    token = service.login(tenant.org, 'issuing-admin', secret).token
    grant = service.issue_service(token, 'issued fixture', task, ['evidence.hash'])
    if change == 'membership':
        service.set_membership(tenant.token, admin, 'analyst', True)
    elif change == 'password':
        service.reset_password(tenant.token, admin, secrets.token_urlsafe(24))
    else:
        with owner_connection(tenant.db) as conn:
            conn.execute('UPDATE gabriel_identity.users SET active=false WHERE organization_id=%s AND id=%s', (tenant.org,admin))
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token, task, REQUEST)


def test_audit_failure_blocks_issue_execute_and_revoke(tenant, machine):
    service, task, grant = machine
    before = service.list_services(tenant.token)
    with owner_connection(tenant.db) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.audit_events FROM gabriel_identity_app')
    try:
        for call in (lambda: service.issue_service(tenant.token, 'not persisted', task, ['evidence.hash']),
                     lambda: service.execute_service(grant.token, task, REQUEST),
                     lambda: service.revoke_service(tenant.token, grant.id)):
            with pytest.raises(IdentityUnavailable):
                call()
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.audit_events TO gabriel_identity_app')
    assert service.list_services(tenant.token) == before
    assert service.execute_service(grant.token, task, REQUEST)['service_id'] == str(grant.id)


def test_concurrent_revoke_has_no_lock_cycle_and_prevents_later_use(tenant, machine):
    service, task, grant = machine
    def run():
        try:
            return service.execute_service(grant.token, task, REQUEST)
        except AuthenticationDenied:
            return 'revoked'
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(run)
        service.revoke_service(tenant.token, grant.id)
        assert future.result() is not None
    with pytest.raises(AuthenticationDenied):
        service.execute_service(grant.token, task, REQUEST)


@pytest.mark.parametrize('operations,ttl', [([],900), (['run_command'],900), (['evidence.hash']*2,900),
    (['evidence.hash'],True), (['evidence.hash'],59), (['evidence.hash'],3601), ('evidence.hash',900)])
def test_invalid_scope_and_lifetime_rejected(tenant, operations, ttl):
    with pytest.raises(InvalidIdentityInput):
        ServiceIdentityService(tenant.db.app).issue_service(tenant.token,'fixture',uuid4(),operations,ttl)


def test_database_enforces_tenant_fk_and_fixed_claims(tenant, machine):
    _, _, grant = machine
    with owner_connection(tenant.db) as conn:
        for clause, value, error in (('issued_by', uuid4(), psycopg.errors.ForeignKeyViolation),
                ('audience','human',psycopg.errors.CheckViolation),
                ('issuer','forged',psycopg.errors.CheckViolation),
                ('resource','all',psycopg.errors.CheckViolation)):
            with pytest.raises(error):
                conn.execute(f'UPDATE gabriel_identity.service_grants SET {clause}=%s WHERE id=%s', (value,grant.id))
            conn.rollback()


def test_cli_issue_execute_list_and_revoke(tenant, tmp_path):
    human = tmp_path/'human'
    human.write_text(tenant.token)
    task = str(uuid4())
    def cli(*args, data=None):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.cli',*args],input=data,
            capture_output=True,text=True,timeout=10)
        assert not result.stderr
        assert tenant.db.app not in result.stdout and tenant.token not in result.stdout
        return result.returncode,json.loads(result.stdout)
    code, result = cli('issue-service','--token-file',str(human),'--task-id',task,'--name','CLI fixture','--operation','evidence.hash')
    assert code == 0
    service_file = tmp_path/'service'
    service_file.write_text(result['result']['service_token'])
    code, execution = cli('service-execute','--token-file',str(service_file),'--task-id',task,data=json.dumps(REQUEST))
    assert code == 0 and execution['result']['service_id'] == result['result']['grant_id']
    code, listing = cli('services','--token-file',str(human))
    assert code == 0 and service_file.read_text() not in repr(listing)
    code, _ = cli('revoke-service','--token-file',str(human),'--grant-id',result['result']['grant_id'])
    assert code == 0
    code, denied = cli('service-execute','--token-file',str(service_file),'--task-id',task,data=json.dumps(REQUEST))
    assert code == 1 and denied['status'] == 'denied'


def test_upgrade_from_v1_preserves_account_and_session(tenant):
    # The disposable DB is sequential/per-file. Recreate the actual pre-v2 state.
    with owner_connection(tenant.db) as conn:
        conn.execute('DROP TABLE gabriel_identity.service_grants')
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=2')
    migrate(tenant.db.owner)
    migrate(tenant.db.owner)
    assert tenant.service.whoami(tenant.token).user_id == tenant.owner
    service = ServiceIdentityService(tenant.db.app)
    task = uuid4()
    grant = service.issue_service(tenant.token,'after upgrade',task,['evidence.hash'])
    assert service.execute_service(grant.token,task,REQUEST)['service_id'] == str(grant.id)


def test_unknown_migration_and_checksum_change_fail_closed(tenant):
    with owner_connection(tenant.db) as conn:
        original = conn.execute('SELECT checksum FROM gabriel_identity.migrations WHERE version=2').fetchone()['checksum']
        conn.execute("UPDATE gabriel_identity.migrations SET checksum='changed' WHERE version=2")
    try:
        with pytest.raises(IdentityConfigurationError):
            migrate(tenant.db.owner)
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('UPDATE gabriel_identity.migrations SET checksum=%s WHERE version=2',(original,))
    with owner_connection(tenant.db) as conn:
        conn.execute("INSERT INTO gabriel_identity.migrations VALUES (99,'unknown')")
    try:
        with pytest.raises(IdentityConfigurationError):
            migrate(tenant.db.owner)
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=99')


def test_failed_upgrade_rolls_back_schema_and_version_without_losing_session(tenant, monkeypatch):
    from pathlib import Path
    original = Path.read_text
    with owner_connection(tenant.db) as conn:
        conn.execute('DROP TABLE gabriel_identity.service_grants')
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=2')
    def damaged(path, *args, **kwargs):
        text = original(path, *args, **kwargs)
        # A runtime error occurs after valid DDL, exercising rollback of partial work.
        return text + '\nSELECT 1/0;' if path.name == 'schema_v2.sql' else text
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, 'read_text', damaged)
            with pytest.raises(IdentityUnavailable):
                migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.service_grants') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations WHERE version=2').fetchone()['n'] == 0
        assert tenant.service.whoami(tenant.token).user_id == tenant.owner
    finally:
        migrate(tenant.db.owner)


def test_scope_boundaries_active_grant_quota_and_safe_listing(tenant):
    service, task = ServiceIdentityService(tenant.db.app), uuid4()
    grants = [service.issue_service(tenant.token,'bounded worker',task,
        ['capabilities.list','evidence.hash'],60 if i == 0 else 3600) for i in range(100)]
    assert service.execute_service(grants[0].token,task,
        {'schema_version':1,'operation':'capabilities.list','arguments':{}})['result']['response_execution'] is False
    with pytest.raises(AccessDenied):
        service.issue_service(tenant.token,'overflow',task,['evidence.hash'])
    rows = service.list_services(tenant.token)
    assert len(rows) == 100
    assert all('token_digest' not in row for row in rows)
    assert all(grant.token not in repr(rows) for grant in grants)
    service.revoke_service(tenant.token,grants[0].id)
    assert service.issue_service(tenant.token,'replacement',task,['evidence.hash']).id


@pytest.mark.parametrize('name,task', [('',uuid4()), ('bad\nname',uuid4()), ('a'*81,uuid4()), ('valid','not-a-uuid')])
def test_name_and_task_bounds_rejected(tenant, name, task):
    with pytest.raises(InvalidIdentityInput):
        ServiceIdentityService(tenant.db.app).issue_service(tenant.token,name,task,['evidence.hash'])
