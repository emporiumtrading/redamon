"""Tenant-scoped identities and revocable opaque sessions; no HTTP surface."""
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
import re
import secrets
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
import psycopg
from psycopg.rows import dict_row

from gabriel.capabilities import execute

ROLES = frozenset({'owner', 'admin', 'analyst', 'viewer'})
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
AUDIENCE = 'gabriel-identity-v1'
MIGRATION_FILES = ((1, 'schema.sql'), (2, 'schema_v2.sql'), (3, 'schema_v3.sql'), (4, 'schema_v4.sql'), (5, 'schema_v5.sql'), (6, 'schema_v6.sql'), (7, 'schema_v7.sql'), (8, 'schema_v8.sql'), (9, 'schema_v9.sql'), (10, 'schema_v10.sql'), (11, 'schema_v11.sql'), (12, 'schema_v12.sql'), (13, 'schema_v13.sql'), (14, 'schema_v14.sql'), (15, 'schema_v15.sql'), (16, 'schema_v16.sql'), (17, 'schema_v17.sql'), (18, 'schema_v18.sql'), (19, 'schema_v19.sql'), (20, 'schema_v20.sql'), (21, 'schema_v21.sql'))


class IdentityError(Exception):
    """Public errors must never contain database/credential details."""


class AuthenticationDenied(IdentityError):
    pass


class AccessDenied(IdentityError):
    pass


class InvalidIdentityInput(IdentityError):
    pass


class IdentityUnavailable(IdentityError):
    pass


class IdentityConfigurationError(IdentityError):
    pass


@dataclass(frozen=True)
class Principal:
    organization_id: UUID
    user_id: UUID
    role: str


@dataclass(frozen=True)
class SessionGrant:
    token: str = field(repr=False)
    expires_at: object


def identifier(value):
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise InvalidIdentityInput('invalid_identifier') from None


def username(value):
    if not isinstance(value, str):
        raise InvalidIdentityInput('invalid_username')
    value = value.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._@+\-]{2,253}', value):
        raise InvalidIdentityInput('invalid_username')
    return value


def password(value, *, creating=False):
    try:
        valid = isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 1024
    except UnicodeError:
        valid = False
    if not valid or (creating and len(value) < 16):
        raise InvalidIdentityInput('invalid_password_length')
    return value


def _digest(token):
    if not isinstance(token, str) or not re.fullmatch(r'gb1_[A-Za-z0-9_\-]{43}', token):
        raise AuthenticationDenied('invalid_session')
    return sha256(token.encode('ascii')).hexdigest()


def _attempt_key(org, name):
    return sha256((str(org) + '|' + name).encode('utf-8')).hexdigest()


@contextmanager
def connection(dsn, *, runtime=True):
    if not isinstance(dsn, str) or not dsn.strip():
        raise IdentityConfigurationError('database_configuration_required')
    try:
        with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5,
                             options='-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=3000') as conn:
            if runtime:
                role = conn.execute('''SELECT r.rolsuper, r.rolbypassrls,
                    r.rolcreatedb,r.rolcreaterole,r.rolreplication,
                    pg_has_role(current_user, n.nspowner, 'MEMBER') AS owns_schema,
                    has_table_privilege(current_user, 'gabriel_identity.audit_events', 'UPDATE,DELETE,TRUNCATE') AS edits_audit
                    FROM pg_roles r CROSS JOIN pg_namespace n
                    WHERE r.rolname = current_user AND n.nspname = 'gabriel_identity' ''').fetchone()
                if not role or any(role.values()):
                    raise IdentityConfigurationError('restricted_runtime_role_required')
            yield conn
    except psycopg.Error:
        raise IdentityUnavailable('identity_storage_unavailable') from None


def _audit(conn, event, principal=None, target=None):
    conn.execute('''INSERT INTO gabriel_identity.audit_events
        (id, organization_id, actor_id, event, target_id) VALUES (%s,%s,%s,%s,%s)''',
        (uuid4(), principal.organization_id if principal else None,
         principal.user_id if principal else None, event, target))


def migrate(owner_dsn):
    with connection(owner_dsn, runtime=False) as conn:
        conn.execute('SELECT pg_advisory_xact_lock(73582301)')
        conn.execute('CREATE SCHEMA IF NOT EXISTS gabriel_identity')
        conn.execute('REVOKE ALL ON SCHEMA gabriel_identity FROM PUBLIC')
        conn.execute('''CREATE TABLE IF NOT EXISTS gabriel_identity.migrations
            (version integer PRIMARY KEY, checksum text NOT NULL)''')
        versions = conn.execute('SELECT version,checksum FROM gabriel_identity.migrations ORDER BY version').fetchall()
        if [row['version'] for row in versions] != [v for v, _ in MIGRATION_FILES[:len(versions)]]:
            raise IdentityConfigurationError('unsupported_migration_history')
        for version, filename in MIGRATION_FILES:
            script = Path(__file__).with_name(filename).read_text()
            checksum = sha256(script.encode()).hexdigest()
            existing = next((row for row in versions if row['version'] == version), None)
            if existing:
                if existing['checksum'] != checksum:
                    raise IdentityConfigurationError('migration_checksum_mismatch')
            else:
                conn.execute(script)
                conn.execute('INSERT INTO gabriel_identity.migrations VALUES (%s,%s)', (version, checksum))


def provision_organization(owner_dsn, name, login, secret):
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or any(ord(c) < 32 for c in name):
        raise InvalidIdentityInput('invalid_organization_name')
    login, secret = username(login), password(secret, creating=True)
    org_id, user_id = uuid4(), uuid4()
    hashed = HASHER.hash(secret)
    with connection(owner_dsn, runtime=False) as conn:
        conn.execute('INSERT INTO gabriel_identity.organizations VALUES (%s,%s)', (org_id, name.strip()))
        conn.execute('''INSERT INTO gabriel_identity.users
            (organization_id,id,username,password_hash) VALUES (%s,%s,%s,%s)''',
            (org_id, user_id, login, hashed))
        conn.execute('INSERT INTO gabriel_identity.memberships VALUES (%s,%s,%s,true)', (org_id, user_id, 'owner'))
        _audit(conn, 'identity.organization_provisioned', Principal(org_id, user_id, 'owner'), user_id)
    return org_id, user_id


class IdentityService:
    def __init__(self, dsn):
        self._dsn = dsn

    def _principal(self, conn, token, *, lock=False):
        query = '''SELECT s.organization_id,s.user_id,m.role FROM gabriel_identity.sessions s
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(s.organization_id,s.user_id)
            JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(s.organization_id,s.user_id)
            WHERE s.token_digest=%s AND s.audience=%s AND s.revoked_at IS NULL
              AND s.expires_at > clock_timestamp() AND u.active AND m.active'''
        parameters = (_digest(token), AUDIENCE)
        row = conn.execute(query, parameters).fetchone()
        if row and lock:
            # One order for login, revocation and target changes avoids session/user lock cycles.
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,73582302))', (str(row['organization_id']),))
            row = conn.execute(query + ' FOR UPDATE OF s,u,m', parameters).fetchone()
        if not row:
            raise AuthenticationDenied('invalid_session')
        return Principal(**row)

    def _admin(self, conn, token):
        principal = self._principal(conn, token, lock=True)
        if principal.role not in {'owner', 'admin'}:
            raise AccessDenied('operation_not_permitted')
        return principal

    def login(self, organization_id, login, secret):
        try:
            org, name, secret = identifier(organization_id), username(login), password(secret)
        except InvalidIdentityInput:
            raise AuthenticationDenied('invalid_credentials') from None
        key = _attempt_key(org, name)
        # Commit admission before locking an account: concurrent guesses share one budget.
        with connection(self._dsn) as conn:
            count = conn.execute('''INSERT INTO gabriel_identity.login_attempts
                (identity_digest,attempts) VALUES (%s,1)
                ON CONFLICT (identity_digest) DO UPDATE SET
                  attempts=CASE WHEN login_attempts.window_started < clock_timestamp()-interval '15 minutes'
                     THEN 1 ELSE LEAST(login_attempts.attempts+1,6) END,
                  window_started=CASE WHEN login_attempts.window_started < clock_timestamp()-interval '15 minutes'
                     THEN clock_timestamp() ELSE login_attempts.window_started END
                RETURNING attempts''', (key,)).fetchone()['attempts']
            _audit(conn, 'identity.login_admission')
        if count > 5:
            raise AuthenticationDenied('invalid_credentials')
        grant = None
        with connection(self._dsn) as conn:
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,73582302))', (str(org),))
            row = conn.execute('''SELECT u.id,u.password_hash,u.active AS user_active,m.active,m.role
                FROM gabriel_identity.users u JOIN gabriel_identity.memberships m
                  ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE u.organization_id=%s AND u.username=%s FOR UPDATE OF u,m''', (org, name)).fetchone()
            try:
                verified = HASHER.verify(row['password_hash'] if row else DUMMY_HASH, secret)
            except (VerificationError, InvalidHashError):
                verified = False
            if verified and row and row['user_active'] and row['active']:
                if HASHER.check_needs_rehash(row['password_hash']):
                    conn.execute('UPDATE gabriel_identity.users SET password_hash=%s WHERE organization_id=%s AND id=%s',
                                 (HASHER.hash(secret), org, row['id']))
                token = 'gb1_' + secrets.token_urlsafe(32)
                expires = conn.execute('''INSERT INTO gabriel_identity.sessions
                    (token_digest,organization_id,user_id,audience,expires_at)
                    VALUES (%s,%s,%s,%s,clock_timestamp()+interval '1 hour') RETURNING expires_at''',
                    (_digest(token), org, row['id'], AUDIENCE)).fetchone()['expires_at']
                conn.execute('UPDATE gabriel_identity.login_attempts SET attempts=0,window_started=clock_timestamp() WHERE identity_digest=%s', (key,))
                principal = Principal(org, row['id'], row['role'])
                _audit(conn, 'identity.login_succeeded', principal)
                grant = SessionGrant(token, expires)
            else:
                _audit(conn, 'identity.login_failed')
        if grant is None:
            raise AuthenticationDenied('invalid_credentials')
        return grant

    def whoami(self, token):
        with connection(self._dsn) as conn:
            return self._principal(conn, token)

    def execute(self, token, request):
        with connection(self._dsn) as conn:
            principal = self._principal(conn, token, lock=True)
            result = execute(request)
            return {'organization_id': str(principal.organization_id), 'user_id': str(principal.user_id),
                    'role': principal.role, 'result': result}

    def logout(self, token):
        with connection(self._dsn) as conn:
            principal = self._principal(conn, token, lock=True)
            _audit(conn, 'identity.session_revoked', principal)
            conn.execute('UPDATE gabriel_identity.sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s', (_digest(token),))

    def list_members(self, token):
        with connection(self._dsn) as conn:
            principal = self._admin(conn, token)
            return conn.execute('''SELECT u.id,u.username,m.role,m.active
                FROM gabriel_identity.users u JOIN gabriel_identity.memberships m
                  ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE u.organization_id=%s ORDER BY u.username''', (principal.organization_id,)).fetchall()

    def create_member(self, token, login, secret, role='analyst'):
        login, secret = username(login), password(secret, creating=True)
        if not isinstance(role, str) or role not in ROLES:
            raise InvalidIdentityInput('invalid_role')
        hashed, user_id = HASHER.hash(secret), uuid4()
        with connection(self._dsn) as conn:
            principal = self._admin(conn, token)
            if principal.role == 'admin' and role in {'owner', 'admin'}:
                raise AccessDenied('operation_not_permitted')
            _audit(conn, 'identity.member_created', principal, user_id)
            conn.execute('''INSERT INTO gabriel_identity.users
                (organization_id,id,username,password_hash) VALUES (%s,%s,%s,%s)''',
                (principal.organization_id, user_id, login, hashed))
            conn.execute('INSERT INTO gabriel_identity.memberships VALUES (%s,%s,%s,true)',
                         (principal.organization_id, user_id, role))
        return user_id

    def _target(self, conn, principal, user_id):
        row = conn.execute('''SELECT u.id,u.username,m.role,m.active FROM gabriel_identity.users u
            JOIN gabriel_identity.memberships m ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
            WHERE u.organization_id=%s AND u.id=%s FOR UPDATE OF u,m''',
            (principal.organization_id, identifier(user_id))).fetchone()
        if not row or (principal.role == 'admin' and row['role'] in {'owner', 'admin'}):
            raise AccessDenied('operation_not_permitted')
        return row

    def set_membership(self, token, user_id, role, active):
        if not isinstance(role, str) or role not in ROLES or type(active) is not bool:
            raise InvalidIdentityInput('invalid_membership')
        with connection(self._dsn) as conn:
            principal = self._admin(conn, token)
            target = self._target(conn, principal, user_id)
            if principal.role == 'admin' and role in {'owner', 'admin'}:
                raise AccessDenied('operation_not_permitted')
            if target['role'] == 'owner' and target['active'] and (role != 'owner' or not active):
                count = conn.execute('''SELECT count(*) AS n FROM gabriel_identity.memberships m
                    JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                    WHERE m.organization_id=%s AND m.role='owner' AND m.active AND u.active''',
                    (principal.organization_id,)).fetchone()['n']
                if count <= 1:
                    raise AccessDenied('last_owner_required')
            _audit(conn, 'identity.membership_changed', principal, target['id'])
            conn.execute('UPDATE gabriel_identity.memberships SET role=%s,active=%s WHERE organization_id=%s AND user_id=%s',
                         (role, active, principal.organization_id, target['id']))
            conn.execute('UPDATE gabriel_identity.sessions SET revoked_at=clock_timestamp() WHERE organization_id=%s AND user_id=%s',
                         (principal.organization_id, target['id']))
            conn.execute('UPDATE gabriel_identity.service_grants SET revoked_at=clock_timestamp() WHERE organization_id=%s AND issued_by=%s',
                         (principal.organization_id, target['id']))

    def reset_password(self, token, user_id, secret):
        hashed = HASHER.hash(password(secret, creating=True))
        with connection(self._dsn) as conn:
            principal = self._admin(conn, token)
            target = self._target(conn, principal, user_id)
            _audit(conn, 'identity.password_reset', principal, target['id'])
            conn.execute('UPDATE gabriel_identity.users SET password_hash=%s WHERE organization_id=%s AND id=%s',
                         (hashed, principal.organization_id, target['id']))
            conn.execute('UPDATE gabriel_identity.sessions SET revoked_at=clock_timestamp() WHERE organization_id=%s AND user_id=%s',
                         (principal.organization_id, target['id']))
            conn.execute('UPDATE gabriel_identity.service_grants SET revoked_at=clock_timestamp() WHERE organization_id=%s AND issued_by=%s',
                         (principal.organization_id, target['id']))
            conn.execute('UPDATE gabriel_identity.login_attempts SET attempts=0,window_started=clock_timestamp() WHERE identity_digest=%s',
                         (_attempt_key(principal.organization_id, target['username']),))
