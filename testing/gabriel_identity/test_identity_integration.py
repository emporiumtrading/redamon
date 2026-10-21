"""Authorized disposable PostgreSQL fixtures; never mock persistence or authorization."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import secrets
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

from argon2 import PasswordHasher
import psycopg
from psycopg.rows import dict_row
import pytest

from gabriel.capabilities import InvalidRequest
from gabriel.identity.cli import read_secret
from gabriel.identity.service import (AccessDenied, AuthenticationDenied, HASHER,
    IdentityConfigurationError, IdentityService, IdentityUnavailable, InvalidIdentityInput,
    migrate, provision_organization)

pytestmark = pytest.mark.integration


@pytest.fixture(scope='module')
def database():
    app_file, owner_file = os.environ.get('GABRIEL_IDENTITY_DSN_FILE'), os.environ.get('GABRIEL_MIGRATION_DSN_FILE')
    if not app_file or not owner_file:
        pytest.skip('isolated PostgreSQL secret files required')
    app, owner = read_secret(app_file), read_secret(owner_file)
    try:
        with psycopg.connect(owner, connect_timeout=2):
            pass
    except psycopg.OperationalError:
        pytest.skip('isolated PostgreSQL fixture unavailable')
    migrate(owner)
    migrate(owner)
    return SimpleNamespace(app=app, owner=owner)


@pytest.fixture
def tenant(database):
    password = secrets.token_urlsafe(24)
    org, user = provision_organization(database.owner, 'Identity test fixture', 'owner', password)
    service = IdentityService(database.app)
    grant = service.login(org, 'owner', password)
    return SimpleNamespace(db=database, org=org, owner=user, password=password,
                           token=grant.token, service=service)


def owner_connection(database):
    return psycopg.connect(database.owner, row_factory=dict_row)


def test_accounts_hashes_sessions_and_migration_persist(tenant):
    with owner_connection(tenant.db) as conn:
        row = conn.execute('SELECT password_hash FROM gabriel_identity.users WHERE organization_id=%s AND id=%s',
                           (tenant.org, tenant.owner)).fetchone()
        assert row['password_hash'].startswith('$argon2id$')
        assert tenant.password not in row['password_hash']
        digest = conn.execute('SELECT token_digest FROM gabriel_identity.sessions WHERE organization_id=%s', (tenant.org,)).fetchone()['token_digest']
        assert digest == sha256(tenant.token.encode()).hexdigest()
        assert digest != tenant.token
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n'] == 20
    assert IdentityService(tenant.db.app).whoami(tenant.token).organization_id == tenant.org


def test_session_repr_does_not_leak_token(tenant):
    grant = tenant.service.login(tenant.org, 'owner', tenant.password)
    assert grant.token not in repr(grant)


@pytest.mark.parametrize('token', ['', 'gb1_short', 'gb1_' + 'a' * 43, 'Bearer malicious', None])
def test_missing_forged_or_unknown_session_denied(tenant, token):
    with pytest.raises(AuthenticationDenied):
        tenant.service.whoami(token)


def test_cross_tenant_member_and_password_changes_denied(tenant):
    org_b, user_b = provision_organization(tenant.db.owner, 'Other fixture', 'owner', secrets.token_urlsafe(24))
    with pytest.raises(AccessDenied):
        tenant.service.set_membership(tenant.token, user_b, 'viewer', False)
    with pytest.raises(AccessDenied):
        tenant.service.reset_password(tenant.token, user_b, secrets.token_urlsafe(24))
    assert all(member['id'] != user_b for member in tenant.service.list_members(tenant.token))
    assert org_b != tenant.org


def test_same_username_has_separate_tenant_password(tenant):
    other_password = secrets.token_urlsafe(24)
    org_b, user_b = provision_organization(tenant.db.owner, 'Other fixture', 'owner', other_password)
    with pytest.raises(AuthenticationDenied):
        tenant.service.login(org_b, 'owner', tenant.password)
    principal = tenant.service.whoami(tenant.service.login(org_b, 'owner', other_password).token)
    assert principal.user_id == user_b and principal.organization_id == org_b


def test_forged_tenant_and_approval_fields_do_not_grant_authority(tenant):
    for field in ('organization_id', 'tenant_id', 'approved', 'role'):
        with pytest.raises(InvalidRequest):
            tenant.service.execute(tenant.token, {'schema_version':1, 'operation':'capabilities.list',
                'arguments':{}, field:str(uuid4())})
    result = tenant.service.execute(tenant.token, {'schema_version':1, 'operation':'evidence.hash', 'arguments':{'content':'fixture'}})
    assert result['organization_id'] == str(tenant.org)
    forged = replace(tenant.service.whoami(tenant.token), organization_id=uuid4(), role='owner')
    with pytest.raises(AuthenticationDenied):
        tenant.service.execute(forged, {'schema_version':1,'operation':'capabilities.list','arguments':{}})


@pytest.mark.parametrize('role', ['analyst', 'viewer'])
def test_read_only_roles_cannot_manage_identity(tenant, role):
    secret = secrets.token_urlsafe(24)
    tenant.service.create_member(tenant.token, role, secret, role)
    token = tenant.service.login(tenant.org, role, secret).token
    with pytest.raises(AccessDenied):
        tenant.service.create_member(token, 'other', secret, 'owner')
    with pytest.raises(AccessDenied):
        tenant.service.list_members(token)
    assert tenant.service.execute(token, {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'fixture'}})['role'] == role


def test_admin_cannot_create_or_edit_privileged_members(tenant):
    secret = secrets.token_urlsafe(24)
    admin = tenant.service.create_member(tenant.token, 'admin', secret, 'admin')
    token = tenant.service.login(tenant.org, 'admin', secret).token
    with pytest.raises(AccessDenied):
        tenant.service.create_member(token, 'root', secret, 'owner')
    with pytest.raises(AccessDenied):
        tenant.service.set_membership(token, tenant.owner, 'viewer', False)
    with pytest.raises(AccessDenied):
        tenant.service.reset_password(token, admin, secret)
    member = tenant.service.create_member(token, 'analyst', secret, 'analyst')
    tenant.service.set_membership(token, member, 'viewer', True)


def test_role_changes_disable_old_sessions_and_recheck_membership(tenant):
    secret = secrets.token_urlsafe(24)
    member = tenant.service.create_member(tenant.token, 'analyst', secret, 'analyst')
    token = tenant.service.login(tenant.org, 'analyst', secret).token
    tenant.service.set_membership(tenant.token, member, 'viewer', True)
    with pytest.raises(AuthenticationDenied):
        tenant.service.whoami(token)
    token = tenant.service.login(tenant.org, 'analyst', secret).token
    assert tenant.service.whoami(token).role == 'viewer'
    tenant.service.set_membership(tenant.token, member, 'viewer', False)
    with pytest.raises(AuthenticationDenied):
        tenant.service.whoami(token)
    with pytest.raises(AuthenticationDenied):
        tenant.service.login(tenant.org, 'analyst', secret)


def test_password_reset_revokes_sessions_and_rejects_old_password(tenant):
    secret, replacement = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    member = tenant.service.create_member(tenant.token, 'analyst', secret)
    token = tenant.service.login(tenant.org, 'analyst', secret).token
    tenant.service.reset_password(tenant.token, member, replacement)
    with pytest.raises(AuthenticationDenied):
        tenant.service.whoami(token)
    with pytest.raises(AuthenticationDenied):
        tenant.service.login(tenant.org, 'analyst', secret)
    assert tenant.service.whoami(tenant.service.login(tenant.org, 'analyst', replacement).token).user_id == member


def test_logout_and_expired_sessions_denied(tenant):
    tenant.service.logout(tenant.token)
    with pytest.raises(AuthenticationDenied):
        tenant.service.whoami(tenant.token)
    token = tenant.service.login(tenant.org, 'owner', tenant.password).token
    with owner_connection(tenant.db) as conn:
        conn.execute('''UPDATE gabriel_identity.sessions SET created_at=clock_timestamp()-interval '2 hours',
            expires_at=clock_timestamp()-interval '1 hour' WHERE token_digest=%s''', (sha256(token.encode()).hexdigest(),))
    with pytest.raises(AuthenticationDenied):
        tenant.service.whoami(token)


def test_login_budget_shared_across_service_instances(tenant):
    secret = secrets.token_urlsafe(24)
    tenant.service.create_member(tenant.token, 'budget', secret)
    for _ in range(5):
        with pytest.raises(AuthenticationDenied):
            IdentityService(tenant.db.app).login(tenant.org, 'budget', 'wrong fixture password')
    with pytest.raises(AuthenticationDenied):
        IdentityService(tenant.db.app).login(tenant.org, 'budget', secret)


def test_authorized_password_reset_recovers_locked_account(tenant):
    old, new = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    member = tenant.service.create_member(tenant.token, 'recover', old)
    for _ in range(5):
        with pytest.raises(AuthenticationDenied):
            tenant.service.login(tenant.org, 'recover', 'incorrect fixture')
    tenant.service.reset_password(tenant.token, member, new)
    assert tenant.service.whoami(tenant.service.login(tenant.org, 'recover', new).token).user_id == member


def test_database_rejects_cross_tenant_foreign_keys(tenant):
    _, user_b = provision_organization(tenant.db.owner, 'Other fixture', 'owner', secrets.token_urlsafe(24))
    with owner_connection(tenant.db) as conn:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute('INSERT INTO gabriel_identity.memberships VALUES (%s,%s,%s,true)', (tenant.org,user_b,'viewer'))
        conn.rollback()


def test_last_owner_guard_is_concurrency_safe(tenant):
    secret = secrets.token_urlsafe(24)
    other_owner = tenant.service.create_member(tenant.token, 'second-owner', secret, 'owner')
    def demote(user):
        try:
            IdentityService(tenant.db.app).set_membership(tenant.token, user, 'viewer', True)
            return 'changed'
        except (AccessDenied, AuthenticationDenied):
            return 'denied'
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(demote, [tenant.owner, other_owner]))
    assert sorted(results) == ['changed', 'denied']
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.memberships WHERE organization_id=%s AND role='owner' AND active", (tenant.org,)).fetchone()['n'] == 1


def test_password_reset_and_target_request_have_consistent_lock_order(tenant):
    secret = secrets.token_urlsafe(24)
    member = tenant.service.create_member(tenant.token, 'concurrent-target', secret)
    for _ in range(3):
        token = tenant.service.login(tenant.org, 'concurrent-target', secret).token
        replacement = secrets.token_urlsafe(24)
        def read():
            try:
                return IdentityService(tenant.db.app).execute(token,
                    {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'fixture'}})
            except AuthenticationDenied:
                return 'revoked'
        with ThreadPoolExecutor(max_workers=2) as executor:
            future = executor.submit(read)
            tenant.service.reset_password(tenant.token, member, replacement)
            assert future.result() is not None
        with pytest.raises(AuthenticationDenied):
            tenant.service.whoami(token)
        secret = replacement


def test_audit_failure_blocks_mutation_and_successful_login(tenant):
    with owner_connection(tenant.db) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.audit_events FROM gabriel_identity_app')
    try:
        with pytest.raises(IdentityUnavailable):
            tenant.service.create_member(tenant.token, 'blocked', secrets.token_urlsafe(24))
        with pytest.raises(IdentityUnavailable):
            tenant.service.login(tenant.org, 'owner', tenant.password)
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.audit_events TO gabriel_identity_app')
    assert 'blocked' not in {member['username'] for member in tenant.service.list_members(tenant.token)}


@pytest.mark.parametrize('operation', ['UPDATE', 'DELETE', 'TRUNCATE'])
def test_runtime_cannot_rewrite_or_erase_audit(tenant, operation):
    query = {'UPDATE':"UPDATE gabriel_identity.audit_events SET event='forged'", 'DELETE':'DELETE FROM gabriel_identity.audit_events', 'TRUNCATE':'TRUNCATE gabriel_identity.audit_events'}[operation]
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query)
        conn.rollback()


def test_owner_credentials_are_refused_by_runtime_service(tenant):
    with pytest.raises(IdentityConfigurationError):
        IdentityService(tenant.db.owner).whoami(tenant.token)


def test_password_parameters_rehashed_after_success(tenant):
    weak_fixture_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(tenant.password)
    with owner_connection(tenant.db) as conn:
        conn.execute('UPDATE gabriel_identity.users SET password_hash=%s WHERE organization_id=%s AND id=%s', (weak_fixture_hash, tenant.org, tenant.owner))
    tenant.service.login(tenant.org, 'owner', tenant.password)
    with owner_connection(tenant.db) as conn:
        row = conn.execute('SELECT password_hash FROM gabriel_identity.users WHERE organization_id=%s AND id=%s', (tenant.org, tenant.owner)).fetchone()
        assert not HASHER.check_needs_rehash(row['password_hash'])


def test_duplicate_member_is_atomic_and_audit_has_no_credentials(tenant):
    with owner_connection(tenant.db) as conn:
        before = conn.execute('SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE organization_id=%s', (tenant.org,)).fetchone()['n']
    with pytest.raises(IdentityUnavailable):
        tenant.service.create_member(tenant.token, 'owner', secrets.token_urlsafe(24))
    with owner_connection(tenant.db) as conn:
        rows = conn.execute('SELECT * FROM gabriel_identity.audit_events WHERE organization_id=%s', (tenant.org,)).fetchall()
        assert len(rows) == before
        assert tenant.password not in repr(rows) and tenant.token not in repr(rows)


def test_cli_round_trip_uses_real_session_and_hides_storage_configuration(tenant, tmp_path):
    token_file = tmp_path / 'token'
    token_file.write_text(tenant.token)
    token_file.chmod(0o600)
    proc = subprocess.run([sys.executable, '-m', 'gabriel.identity.cli', 'whoami', '--token-file', str(token_file)], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert str(tenant.org) in proc.stdout
    assert tenant.token not in proc.stdout and tenant.db.app not in proc.stdout
    assert not proc.stderr
