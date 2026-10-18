"""Revocable machine credentials for fixed local computation, never human authority."""
from dataclasses import dataclass, field
from hashlib import sha256
import re
import secrets
from uuid import uuid4

from gabriel.capabilities import execute
from gabriel.identity.service import (AccessDenied, AuthenticationDenied, IdentityService,
    InvalidIdentityInput, _audit, connection, identifier)

ISSUER = 'gabriel-identity-service-v1'
AUDIENCE = 'gabriel-local-worker-v1'
RESOURCE = 'local-inspection-v1'
OPERATIONS = frozenset({'capabilities.list', 'evidence.hash'})


@dataclass(frozen=True)
class ServiceGrant:
    id: object
    token: str = field(repr=False)
    expires_at: object


def _digest(token):
    if not isinstance(token, str) or not re.fullmatch(r'gbs1_[A-Za-z0-9_\-]{43}', token):
        raise AuthenticationDenied('invalid_service_credential')
    return sha256(token.encode('ascii')).hexdigest()


class ServiceIdentityService(IdentityService):
    def issue_service(self, human_token, name, task_id, operations, ttl_seconds=900):
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._ -]{0,79}', name):
            raise InvalidIdentityInput('invalid_service_name')
        task_id = identifier(task_id)
        if (not isinstance(operations, list) or not operations or len(operations) > 2
                or any(not isinstance(op, str) or op not in OPERATIONS for op in operations)
                or len(set(operations)) != len(operations)):
            raise InvalidIdentityInput('invalid_service_operations')
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 3600:
            raise InvalidIdentityInput('invalid_service_lifetime')
        token, grant_id = 'gbs1_' + secrets.token_urlsafe(32), uuid4()
        with connection(self._dsn) as conn:
            principal = self._admin(conn, human_token)
            count = conn.execute('''SELECT count(*) AS n FROM gabriel_identity.service_grants
                WHERE organization_id=%s AND revoked_at IS NULL AND expires_at>clock_timestamp()''',
                (principal.organization_id,)).fetchone()['n']
            if count >= 100:
                raise AccessDenied('service_grant_limit')
            expires = conn.execute('''INSERT INTO gabriel_identity.service_grants
                (organization_id,id,token_digest,issued_by,name,task_id,issuer,audience,resource,
                 operations,created_at,expires_at)
                SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,t,t+%s*interval '1 second'
                FROM (SELECT clock_timestamp() AS t) admitted RETURNING expires_at''',
                (principal.organization_id, grant_id, _digest(token), principal.user_id, name,
                 task_id, ISSUER, AUDIENCE, RESOURCE, sorted(operations), ttl_seconds)).fetchone()['expires_at']
            _audit(conn, 'identity.service_issued', principal, grant_id)
        return ServiceGrant(grant_id, token, expires)

    def list_services(self, human_token):
        with connection(self._dsn) as conn:
            principal = self._admin(conn, human_token)
            return conn.execute('''SELECT id,name,issued_by,task_id,operations,created_at,expires_at,revoked_at
                FROM gabriel_identity.service_grants WHERE organization_id=%s
                ORDER BY created_at DESC,id LIMIT 100''', (principal.organization_id,)).fetchall()

    def revoke_service(self, human_token, grant_id):
        grant_id = identifier(grant_id)
        with connection(self._dsn) as conn:
            principal = self._admin(conn, human_token)
            row = conn.execute('''UPDATE gabriel_identity.service_grants SET revoked_at=clock_timestamp()
                WHERE organization_id=%s AND id=%s RETURNING id''',
                (principal.organization_id, grant_id)).fetchone()
            if not row:
                raise AccessDenied('service_not_accessible')
            _audit(conn, 'identity.service_revoked', principal, grant_id)

    def execute_service(self, token, task_id, request):
        digest, task_id = _digest(token), identifier(task_id)
        with connection(self._dsn) as conn:
            org = conn.execute('SELECT organization_id FROM gabriel_identity.service_grants WHERE token_digest=%s',
                               (digest,)).fetchone()
            if not org:
                raise AuthenticationDenied('invalid_service_credential')
            # Same organization-before-row order as human administration and revocation.
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,73582302))',
                         (str(org['organization_id']),))
            row = conn.execute('''SELECT g.id,g.organization_id,g.task_id,g.operations FROM gabriel_identity.service_grants g
                JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(g.organization_id,g.issued_by)
                JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE g.token_digest=%s AND g.issuer=%s AND g.audience=%s AND g.resource=%s
                  AND g.task_id=%s AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()
                  AND m.active AND u.active AND m.role IN ('owner','admin') FOR UPDATE OF g,m,u''',
                (digest, ISSUER, AUDIENCE, RESOURCE, task_id)).fetchone()
            if not row:
                raise AuthenticationDenied('invalid_service_credential')
            if not isinstance(request, dict) or not isinstance(request.get('operation'), str) or request['operation'] not in row['operations']:
                raise AccessDenied('service_operation_not_permitted')
            result = execute(request)
            # No raw token, arguments or evidence content enters the audit event.
            conn.execute('''INSERT INTO gabriel_identity.audit_events
                (id,organization_id,actor_id,event,target_id) VALUES (%s,%s,%s,%s,%s)''',
                (uuid4(), row['organization_id'], row['id'], 'identity.service_executed', row['task_id']))
            return {'organization_id': str(row['organization_id']), 'service_id': str(row['id']),
                    'task_id': str(row['task_id']), 'resource': RESOURCE, 'result': result}
