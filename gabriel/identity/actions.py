"""Exact human approvals for the admitted, transactional local case-close operation."""
from datetime import timedelta
from hashlib import sha256
import re
from uuid import uuid4

from gabriel.identity.cases import CaseService,object_aad,iso
from gabriel.identity.evidence_store import EvidenceError,canonical
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,_digest,connection,identifier


def digest(value):
    return sha256(canonical(value)).hexdigest()


def policy_digest(policy):
    return digest([policy['revision'],policy['distinct_approver'],policy['approval_ttl']])


class ActionService(CaseService):
    def _policy(self,conn,principal):
        row = conn.execute('''SELECT p.* FROM gabriel_identity.action_policies p
            JOIN gabriel_identity.action_policy_state s USING (organization_id,revision)
            WHERE p.organization_id=%s''',(principal.organization_id,)).fetchone()
        if not row:
            raise AccessDenied('action_policy_required')
        return row

    def set_policy(self,token,*,distinct_approver=True,approval_ttl=300):
        if type(distinct_approver) is not bool or type(approval_ttl) is not int or not 60<=approval_ttl<=900:
            raise InvalidIdentityInput('invalid_action_policy')
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            revision = conn.execute('SELECT COALESCE(max(revision),0)+1 AS n FROM gabriel_identity.action_policies WHERE organization_id=%s',
                (p.organization_id,)).fetchone()['n']
            if revision>1024:
                raise AccessDenied('action_policy_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.action_policies
                (organization_id,revision,distinct_approver,approval_ttl,created_by) VALUES (%s,%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,revision,distinct_approver,approval_ttl,p.user_id)).fetchone()
            conn.execute('''INSERT INTO gabriel_identity.action_policy_state VALUES (%s,%s)
                ON CONFLICT (organization_id) DO UPDATE SET revision=EXCLUDED.revision''',(p.organization_id,revision))
            _audit(conn,'action.policy_changed',p)
            return row

    def get_policy(self,token):
        with connection(self._dsn) as conn:
            return self._policy(conn,self._human(conn,token))

    def _request(self,conn,p,request_id):
        row = conn.execute('SELECT * FROM gabriel_identity.action_requests WHERE organization_id=%s AND id=%s FOR UPDATE',
            (p.organization_id,identifier(request_id))).fetchone()
        if not row:
            raise AccessDenied('action_not_accessible')
        if digest(row['payload'])!=row['digest']:
            raise AccessDenied('action_payload_invalid')
        payload = row['payload']
        fields = {'schema_version','operation','case_id','resource_version','policy_revision',
                  'scope','rationale','ttl','evidence','policy_digest'}
        if (set(payload)!=fields or payload.get('schema_version')!=1
                or payload.get('scope')!='gabriel-local-case'
                or payload.get('operation')!=row['operation'] or payload.get('case_id')!=str(row['case_id'])
                or payload.get('policy_revision')!=row['policy_revision']
                or type(payload['ttl']) is not int or not 60<=payload['ttl']<=3600
                or (row['expires_at']-row['created_at']).total_seconds()!=payload['ttl']
                or not isinstance(payload['evidence'],list) or not 1<=len(payload['evidence'])<=64
                or not isinstance(payload['policy_digest'],str) or not re.fullmatch('[a-f0-9]{64}',payload['policy_digest'])):
            raise AccessDenied('action_payload_invalid')
        for item in payload['evidence']:
            if (not isinstance(item,dict) or set(item)!={'id','context_digest','sequence','head'}
                    or type(item['sequence']) is not int or not 1<=item['sequence']<=4096
                    or any(not isinstance(item[k],str) or not re.fullmatch('[a-f0-9]{64}',item[k]) for k in ('context_digest','head'))):
                raise AccessDenied('action_payload_invalid')
            identifier(item['id'])
        return row

    def _snapshot(self,conn,p,case):
        if case['state']!='open':
            raise AccessDenied('case_not_open')
        rows = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND case_id=%s ORDER BY id',
            (p.organization_id,case['id'])).fetchall()
        if not rows:
            raise EvidenceError('case_evidence_integrity_failed')
        entries = []
        for row in rows:
            self._verify(conn,row)
            chain = self._chain(conn,row)
            entries.append({'id':str(row['id']),'context_digest':sha256(object_aad(row)).hexdigest(),
                'sequence':chain[-1]['sequence'],'head':chain[-1]['event_hash']})
        return entries

    def _context(self,conn,p,row):
        policy = self._policy(conn,p)
        if policy['revision']!=row['policy_revision'] or policy_digest(policy)!=row['payload']['policy_digest']:
            raise AccessDenied('action_policy_changed')
        now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        if row['expires_at']<=now:
            raise AccessDenied('action_expired')
        actor = conn.execute('''SELECT s.user_id,m.role FROM gabriel_identity.sessions s
            JOIN gabriel_identity.memberships m USING (organization_id,user_id)
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(s.organization_id,s.user_id)
            WHERE s.organization_id=%s AND s.user_id=%s AND s.token_digest=%s AND s.audience='gabriel-identity-v1'
            AND s.revoked_at IS NULL AND s.expires_at>%s AND m.active AND u.active''',
            (p.organization_id,row['requested_by'],row['requester_session'],now)).fetchone()
        if not actor or actor['role'] not in {'owner','admin','analyst'}:
            raise AccessDenied('action_requester_revoked')
        return policy,now

    def _unchanged(self,conn,p,row,case):
        if row['payload']['resource_version']!=iso(case['created_at']):
            raise AccessDenied('action_resource_changed')
        current = self._snapshot(conn,p,case)
        expected = row['payload']['evidence']
        if [(r['id'],r['context_digest']) for r in current]!=[(r['id'],r['context_digest']) for r in expected]:
            raise AccessDenied('action_evidence_changed')
        for item in expected:
            event = conn.execute('''SELECT event_hash FROM gabriel_identity.custody_events
                WHERE organization_id=%s AND evidence_id=%s AND sequence=%s''',
                (p.organization_id,identifier(item['id']),item['sequence'])).fetchone()
            if not event or event['event_hash']!=item['head']:
                raise AccessDenied('action_evidence_changed')

    def propose_close(self,token,case_id,request_id,rationale,*,ttl=900):
        if (not isinstance(rationale,str) or not 1<=len(rationale.strip())<=400
                or any(ord(c)<32 or ord(c)==127 for c in rationale)
                or type(ttl) is not int or not 60<=ttl<=3600):
            raise InvalidIdentityInput('invalid_action_request')
        request_id = identifier(request_id)
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            case = self._case(conn,p,case_id)
            old = conn.execute("SELECT id FROM gabriel_identity.action_requests WHERE organization_id=%s AND operation='case.close' AND request_id=%s",
                (p.organization_id,request_id)).fetchone()
            if old:
                row = self._request(conn,p,old['id'])
                if (row['requested_by']!=p.user_id or row['case_id']!=case['id']
                        or row['payload']['rationale']!=rationale.strip() or row['payload']['ttl']!=ttl):
                    raise AccessDenied('action_request_conflict')
                _audit(conn,'action.proposal_replayed',p,row['id'])
                return {k:v for k,v in row.items() if k!='requester_session'}
            policy = self._policy(conn,p)
            count = conn.execute("SELECT count(*) AS n FROM gabriel_identity.action_requests WHERE organization_id=%s AND state IN ('proposed','pending_approval','approved') AND expires_at>clock_timestamp()",
                (p.organization_id,)).fetchone()['n']
            if count>=100:
                raise AccessDenied('active_action_limit')
            evidence = self._snapshot(conn,p,case)
            payload = {'schema_version':1,'operation':'case.close','case_id':str(case['id']),
                'resource_version':iso(case['created_at']),'policy_revision':policy['revision'],
                'scope':'gabriel-local-case','rationale':rationale.strip(),'ttl':ttl,'evidence':evidence,
                'policy_digest':policy_digest(policy)}
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            row = conn.execute('''INSERT INTO gabriel_identity.action_requests
                (organization_id,id,request_id,operation,case_id,requested_by,requester_session,policy_revision,payload,digest,created_at,expires_at)
                VALUES (%s,%s,%s,'case.close',%s,%s,%s,%s,%s::jsonb,%s,%s,%s) RETURNING *''',
                (p.organization_id,uuid4(),request_id,case['id'],p.user_id,_digest(token),policy['revision'],
                 canonical(payload).decode(),digest(payload),now,now+timedelta(seconds=ttl))).fetchone()
            _audit(conn,'action.proposed',p,row['id'])
            return {k:v for k,v in row.items() if k!='requester_session'}

    def _decision(self,conn,p,row,event,state):
        conn.execute('INSERT INTO gabriel_identity.action_decisions (organization_id,id,request_id,actor_id,decision) VALUES (%s,%s,%s,%s,%s)',
            (p.organization_id,uuid4(),row['id'],p.user_id,event))
        conn.execute('UPDATE gabriel_identity.action_requests SET state=%s WHERE organization_id=%s AND id=%s',
            (state,p.organization_id,row['id']))
        _audit(conn,'action.'+event,p,row['id'])

    def submit(self,token,request_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            row = self._request(conn,p,request_id)
            self._context(conn,p,row)
            if row['requested_by']!=p.user_id or row['state']!='proposed':
                raise AccessDenied('action_not_submittable')
            self._unchanged(conn,p,row,self._case(conn,p,row['case_id']))
            self._context(conn,p,row)
            self._decision(conn,p,row,'submitted','pending_approval')

    def approve(self,token,request_id,expected_digest):
        with connection(self._dsn) as conn:
            p = self._admin(conn,token)
            row = self._request(conn,p,request_id)
            policy,now = self._context(conn,p,row)
            if row['state']!='pending_approval' or expected_digest!=row['digest']:
                raise AccessDenied('action_not_approvable')
            if policy['distinct_approver'] and row['requested_by']==p.user_id:
                raise AccessDenied('action_self_approval_denied')
            self._unchanged(conn,p,row,self._case(conn,p,row['case_id']))
            policy,now = self._context(conn,p,row)
            expires = min(row['expires_at'],now+timedelta(seconds=policy['approval_ttl']))
            conn.execute('''INSERT INTO gabriel_identity.action_approvals
                (organization_id,request_id,approved_by,approver_session,digest,created_at,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                (p.organization_id,row['id'],p.user_id,_digest(token),row['digest'],now,expires))
            self._decision(conn,p,row,'approved','approved')

    def end(self,token,request_id,state):
        if state not in {'rejected','cancelled'}:
            raise InvalidIdentityInput('invalid_action_end_state')
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            row = self._request(conn,p,request_id)
            if (p.role not in {'owner','admin'} and (state=='rejected' or row['requested_by']!=p.user_id)
                    or row['state'] not in {'proposed','pending_approval','approved'}):
                raise AccessDenied('action_not_terminable')
            self._decision(conn,p,row,state,state)

    def get_action(self,token,request_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            row = self._request(conn,p,request_id)
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            approval = conn.execute('SELECT * FROM gabriel_identity.action_approvals WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,row['id'])).fetchone()
            row['effective_state'] = row['state']
            if row['state'] in {'proposed','pending_approval','approved'}:
                try:
                    self._context(conn,p,row)
                except AccessDenied as exc:
                    row['effective_state'] = 'expired' if str(exc)=='action_expired' else 'invalidated'
                    row['invalidation_code'] = str(exc)
            if row['state'] in {'proposed','pending_approval','approved'} and (row['expires_at']<=now or approval and approval['expires_at']<=now):
                row['effective_state'] = 'expired'
            if approval:
                row['approval'] = {k:v for k,v in approval.items() if k!='approver_session'}
            row['decisions'] = conn.execute('SELECT id,actor_id,decision,created_at FROM gabriel_identity.action_decisions WHERE organization_id=%s AND request_id=%s ORDER BY created_at,id',
                (p.organization_id,row['id'])).fetchall()
            row['execution'] = conn.execute('SELECT executor_id,digest,result,created_at FROM gabriel_identity.action_executions WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,row['id'])).fetchone()
            return {k:v for k,v in row.items() if k!='requester_session'}

    def execute(self,token,request_id):
        row = self.get_action(token,request_id)
        return self.close_case(token,row['case_id'],approval_id=row['id'])

    def _approval_current(self,conn,p,row,approval,policy,now):
        if not approval or approval['digest']!=row['digest'] or approval['expires_at']<=now:
            raise AccessDenied('action_approval_expired_or_invalid')
        actor = conn.execute('''SELECT m.role FROM gabriel_identity.sessions s
            JOIN gabriel_identity.memberships m USING (organization_id,user_id)
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(s.organization_id,s.user_id)
            WHERE s.organization_id=%s AND s.user_id=%s AND s.token_digest=%s AND s.audience='gabriel-identity-v1'
            AND s.revoked_at IS NULL AND s.expires_at>%s AND m.active AND u.active''',
            (p.organization_id,approval['approved_by'],approval['approver_session'],now)).fetchone()
        if (not actor or actor['role'] not in {'owner','admin'}
                or policy['distinct_approver'] and approval['approved_by']==row['requested_by']):
            raise AccessDenied('action_approver_revoked')

    def _execute_close(self,conn,p,case,request_id,token):
        if p.role not in {'owner','admin'}:
            raise AccessDenied('operation_not_permitted')
        row = self._request(conn,p,request_id)
        policy,now = self._context(conn,p,row)
        if row['case_id']!=case['id'] or row['state'] not in {'approved','succeeded'}:
            raise AccessDenied('action_not_executable')
        approval = conn.execute('SELECT * FROM gabriel_identity.action_approvals WHERE organization_id=%s AND request_id=%s',
            (p.organization_id,row['id'])).fetchone()
        self._approval_current(conn,p,row,approval,policy,now)
        if row['state']=='succeeded':
            receipt = conn.execute('SELECT * FROM gabriel_identity.action_executions WHERE organization_id=%s AND request_id=%s',
                (p.organization_id,row['id'])).fetchone()
            expected = {'case_id':str(case['id']),'state':'closed','request_id':str(row['id']),'digest':row['digest']}
            if (not receipt or receipt['executor_id']!=p.user_id or case['state']!='closed'
                    or receipt['digest']!=row['digest'] or receipt['result']!=expected):
                raise AccessDenied('action_receipt_invalid')
            _audit(conn,'action.execution_replayed',p,row['id'])
            return receipt['result']
        self._unchanged(conn,p,row,case)
        self._principal(conn,token,lock=True)
        policy,dispatch_time = self._context(conn,p,row)
        self._approval_current(conn,p,row,approval,policy,dispatch_time)
        conn.execute("UPDATE gabriel_identity.action_requests SET state='dispatching' WHERE organization_id=%s AND id=%s",(p.organization_id,row['id']))
        _audit(conn,'action.dispatching',p,row['id'])
        # Transaction-local context makes older closure SQL fail at the database boundary.
        conn.execute("SELECT set_config('gabriel.action_request',%s,true)",(str(row['id']),))
        conn.execute("UPDATE gabriel_identity.cases SET state='closed',closed_at=clock_timestamp() WHERE organization_id=%s AND id=%s",(p.organization_id,case['id']))
        _audit(conn,'case.closed',p,case['id'])
        result = {'case_id':str(case['id']),'state':'closed','request_id':str(row['id']),'digest':row['digest']}
        conn.execute('''INSERT INTO gabriel_identity.action_executions (organization_id,request_id,executor_id,digest,result)
            VALUES (%s,%s,%s,%s,%s::jsonb)''',(p.organization_id,row['id'],p.user_id,row['digest'],canonical(result).decode()))
        conn.execute("UPDATE gabriel_identity.action_requests SET state='succeeded' WHERE organization_id=%s AND id=%s",(p.organization_id,row['id']))
        _audit(conn,'action.succeeded',p,row['id'])
        return result
