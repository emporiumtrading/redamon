"""Persisted, bounded local investigation tasks; no browser or response authority."""
import re
from uuid import uuid4

from gabriel.identity.service import (AccessDenied, IdentityService, InvalidIdentityInput,
    _audit, connection, identifier)

OPERATIONS = frozenset({'capabilities.list','evidence.hash'})


def operation_scope(operations):
    if (not isinstance(operations,list) or not 1<=len(operations)<=2
            or any(not isinstance(op,str) or op not in OPERATIONS for op in operations)
            or len(set(operations))!=len(operations)):
        raise InvalidIdentityInput('invalid_task_operations')
    return sorted(operations)


def task_record(conn, organization_id, task_id):
    row = conn.execute('''SELECT t.*,clock_timestamp()>=t.expires_at AS expired,
        (u.active AND m.active AND m.role IN ('owner','admin','analyst')) AS creator_authorized
        FROM gabriel_identity.investigation_tasks t
        JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(t.organization_id,t.created_by)
        JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
        WHERE t.organization_id=%s AND t.id=%s FOR UPDATE OF t''',
        (organization_id,identifier(task_id))).fetchone()
    if not row:
        raise AccessDenied('task_not_accessible')
    return row


def available(row, *, replay=False):
    states = {'active','exhausted'} if replay else {'active'}
    if row['state'] not in states or row['expired'] or not row['creator_authorized']:
        raise AccessDenied('task_not_active')
    if not replay and row['used_steps']>=row['max_steps']:
        raise AccessDenied('task_step_limit')


def public_task(row):
    result = dict(row)
    if result.pop('expired',False) and result['state']=='active':
        result['state']='expired'
    authorized = result.pop('creator_authorized',True)
    result['creator_authorized'] = authorized
    return result


class TaskService(IdentityService):
    def create_task(self, token, name, operations, ttl_seconds=900, max_steps=20):
        if not isinstance(name,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._ -]{0,79}',name):
            raise InvalidIdentityInput('invalid_task_name')
        operations = operation_scope(operations)
        if type(ttl_seconds) is not int or not 60<=ttl_seconds<=3600 or type(max_steps) is not int or not 1<=max_steps<=1000:
            raise InvalidIdentityInput('invalid_task_limits')
        with connection(self._dsn) as conn:
            principal = self._principal(conn,token,lock=True)
            if principal.role not in {'owner','admin','analyst'}:
                raise AccessDenied('operation_not_permitted')
            count = conn.execute('''SELECT count(*) AS n FROM gabriel_identity.investigation_tasks
                WHERE organization_id=%s AND state='active' AND expires_at>clock_timestamp()''',
                (principal.organization_id,)).fetchone()['n']
            if count>=100:
                raise AccessDenied('active_task_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.investigation_tasks
                (organization_id,id,created_by,name,resource,operations,max_steps,created_at,expires_at)
                SELECT %s,%s,%s,%s,'local-inspection-v1',%s,%s,t,t+%s*interval '1 second'
                FROM (SELECT clock_timestamp() AS t) admitted RETURNING *''',
                (principal.organization_id,uuid4(),principal.user_id,name,operations,max_steps,ttl_seconds)).fetchone()
            _audit(conn,'task.created',principal,row['id'])
            return public_task(row)

    def get_task(self, token, task_id):
        with connection(self._dsn) as conn:
            principal = self._principal(conn,token,lock=True)
            return public_task(task_record(conn,principal.organization_id,task_id))

    def list_tasks(self, token):
        with connection(self._dsn) as conn:
            principal = self._principal(conn,token)
            rows = conn.execute('''SELECT t.*,clock_timestamp()>=t.expires_at AS expired,
                (u.active AND m.active AND m.role IN ('owner','admin','analyst')) AS creator_authorized
                FROM gabriel_identity.investigation_tasks t
                JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(t.organization_id,t.created_by)
                JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE t.organization_id=%s ORDER BY t.created_at DESC,t.id LIMIT 100''',(principal.organization_id,)).fetchall()
            return [public_task(row) for row in rows]

    def end_task(self, token, task_id, state):
        if not isinstance(state,str) or state not in {'cancelled','completed'}:
            raise InvalidIdentityInput('invalid_task_transition')
        with connection(self._dsn) as conn:
            principal = self._principal(conn,token,lock=True)
            row = task_record(conn,principal.organization_id,task_id)
            if principal.role not in {'owner','admin'} and not (principal.role=='analyst' and principal.user_id==row['created_by']):
                raise AccessDenied('operation_not_permitted')
            if row['state']==state:
                return public_task(row)
            if row['state'] not in {'active','exhausted'}:
                raise AccessDenied('task_transition_not_permitted')
            conn.execute('UPDATE gabriel_identity.investigation_tasks SET state=%s WHERE organization_id=%s AND id=%s',
                         (state,principal.organization_id,row['id']))
            conn.execute('''UPDATE gabriel_identity.service_grants SET revoked_at=clock_timestamp()
                WHERE organization_id=%s AND bound_task_id=%s''',(principal.organization_id,row['id']))
            _audit(conn,'task.'+state,principal,row['id'])
            row['state'] = state
            return public_task(row)
