"""Durable local cost reservations. No transport, model admission or evidence egress.

All amounts use integer micro-USD; all buckets use database UTC. Unknown claimed
outcomes retain their full reservation across bucket boundaries and cancellation.
"""
from datetime import timezone
import re
from uuid import uuid4

from gabriel.identity.model_routes import ROUTES

from gabriel.identity.service import (
    AccessDenied, IdentityService, InvalidIdentityInput, _audit, connection, identifier,
)

DEFAULTS = dict(enabled=True, month_microusd=18000000, day_microusd=500000,
                investigation_microusd=50000)
MODELS = {'openrouter': set(ROUTES)|{'google/gemini-2.5-flash-lite', 'google/gemini-2.5-flash'},
          'nvidia': {'nvidia/nemotron-3-super-120b-a12b'}}


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise InvalidIdentityInput('invalid_model_budget_integer')
    return value


def fingerprint(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise InvalidIdentityInput('invalid_model_budget_digest')
    return value


def now(conn):
    return conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']


def limits(conn, org):
    row = conn.execute('''SELECT enabled,month_microusd,day_microusd,investigation_microusd
        FROM gabriel_identity.model_budget_policies WHERE organization_id=%s
        ORDER BY created_at DESC,id DESC LIMIT 1''', (org,)).fetchone()
    return dict(row) if row else dict(DEFAULTS)


def usage(conn, org, at):
    day = at.astimezone(timezone.utc).date()
    month = day.replace(day=1)
    # An unknown charge carries forward. A late settlement counts conservatively
    # in its originating and reconciliation buckets rather than creating free capacity.
    row = conn.execute('''SELECT
        COALESCE(sum(COALESCE(s.actual_microusd,r.reserved_microusd)) FILTER
          (WHERE s.reservation_id IS NULL OR (r.created_at AT TIME ZONE 'UTC')::date>=%s
             OR (s.created_at AT TIME ZONE 'UTC')::date>=%s),0) AS month_used,
        COALESCE(sum(COALESCE(s.actual_microusd,r.reserved_microusd)) FILTER
          (WHERE s.reservation_id IS NULL OR (r.created_at AT TIME ZONE 'UTC')::date>=%s
             OR (s.created_at AT TIME ZONE 'UTC')::date>=%s),0) AS day_used,
        count(*) FILTER (WHERE s.reservation_id IS NULL) AS held_slots
        FROM gabriel_identity.model_reservations r
        LEFT JOIN gabriel_identity.model_settlements s
          ON (s.organization_id,s.reservation_id)=(r.organization_id,r.id)
        WHERE r.organization_id=%s''', (month,month,day,day,org)).fetchone()
    return {key: int(value) for key,value in row.items()}


def investigation(conn, principal, investigation_id, *, active=False):
    row = conn.execute('''SELECT i.*,c.state AS case_state,
        (u.active AND m.active AND m.role IN ('owner','admin','analyst')) AS creator_current,
        EXISTS(SELECT 1 FROM gabriel_identity.model_investigation_stops x
          WHERE (x.organization_id,x.investigation_id)=(i.organization_id,i.id)) AS stopped
        FROM gabriel_identity.model_investigations i
        JOIN gabriel_identity.cases c ON (c.organization_id,c.id)=(i.organization_id,i.case_id)
        JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(i.organization_id,i.requested_by)
        JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
        WHERE i.organization_id=%s AND i.id=%s''',
        (principal.organization_id,identifier(investigation_id))).fetchone()
    if not row:
        raise AccessDenied('model_investigation_not_accessible')
    if active and (row['stopped'] or row['case_state']!='open' or not row['creator_current']
                   or row['expires_at']<=now(conn)):
        raise AccessDenied('model_investigation_not_active')
    if active and principal.role not in {'owner','admin'} and principal.user_id!=row['requested_by']:
        raise AccessDenied('model_investigation_not_owned')
    return row


def reservation(conn, principal, reservation_id):
    row = conn.execute('''SELECT r.*,s.outcome,s.actual_microusd,s.receipt_digest,
        d.id AS claim_id FROM gabriel_identity.model_reservations r
        LEFT JOIN gabriel_identity.model_settlements s ON
          (s.organization_id,s.reservation_id)=(r.organization_id,r.id)
        LEFT JOIN gabriel_identity.model_dispatch_claims d ON
          (d.organization_id,d.reservation_id)=(r.organization_id,r.id)
        WHERE r.organization_id=%s AND r.id=%s''',
        (principal.organization_id,identifier(reservation_id))).fetchone()
    if not row:
        raise AccessDenied('model_reservation_not_accessible')
    return row


def public(row):
    return {**dict(row), 'transport_enabled': False, 'model_admitted': False}


class ModelBudgetService(IdentityService):
    def status(self, token):
        with connection(self._dsn) as conn:
            principal = self._principal(conn,token,lock=True)
            at = now(conn)
            return dict(limits=limits(conn,principal.organization_id),
                        usage=usage(conn,principal.organization_id,at),
                        sampled_at=at, timezone='UTC', unit='microUSD',
                        transport_enabled=False, model_admitted=False,
                        settlement_provenance='operator_attested_not_provider_verified')

    def configure(self, token, *, enabled=True, month_microusd=18000000,
                  day_microusd=500000, investigation_microusd=50000):
        if type(enabled) is not bool:
            raise InvalidIdentityInput('invalid_model_budget_policy')
        values = dict(enabled=enabled,
                      month_microusd=integer(month_microusd,1,18000000),
                      day_microusd=integer(day_microusd,1,500000),
                      investigation_microusd=integer(investigation_microusd,1,50000))
        with connection(self._dsn) as conn:
            principal = self._admin(conn,token)
            count = conn.execute('''SELECT count(*) AS n FROM gabriel_identity.model_budget_policies
                WHERE organization_id=%s''',(principal.organization_id,)).fetchone()['n']
            if count>=4096:
                raise AccessDenied('model_budget_policy_history_limit')
            policy_id=uuid4()
            conn.execute('''INSERT INTO gabriel_identity.model_budget_policies
                (organization_id,id,created_by,enabled,month_microusd,day_microusd,investigation_microusd)
                VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                (principal.organization_id,policy_id,principal.user_id,enabled,month_microusd,day_microusd,investigation_microusd))
            _audit(conn,'model_budget.policy_changed',principal,policy_id)
            return values

    def quote(self, token, provider, model, configuration_digest,
              input_microusd_per_million, output_microusd_per_million, ttl_seconds=900):
        if not isinstance(provider,str) or provider not in MODELS or not isinstance(model,str) or model not in MODELS[provider]:
            raise InvalidIdentityInput('unsupported_model_budget_route')
        configuration_digest=fingerprint(configuration_digest)
        input_rate=integer(input_microusd_per_million,0,100000000)
        output_rate=integer(output_microusd_per_million,0,100000000)
        ttl_seconds=integer(ttl_seconds,60,3600)
        with connection(self._dsn) as conn:
            principal=self._admin(conn,token)
            count=conn.execute('''SELECT count(*) AS n FROM gabriel_identity.model_price_quotes
                WHERE organization_id=%s AND created_at>clock_timestamp()-interval '1 day' ''',
                (principal.organization_id,)).fetchone()['n']
            if count>=256:
                raise AccessDenied('model_price_quote_limit')
            row=conn.execute('''INSERT INTO gabriel_identity.model_price_quotes
                (organization_id,id,created_by,provider,model,configuration_digest,
                 input_microusd_per_million,output_microusd_per_million,created_at,expires_at)
                SELECT %s,%s,%s,%s,%s,%s,%s,%s,t,t+%s*interval '1 second'
                FROM (SELECT clock_timestamp() AS t) sampled RETURNING *''',
                (principal.organization_id,uuid4(),principal.user_id,provider,model,configuration_digest,
                 input_rate,output_rate,ttl_seconds)).fetchone()
            _audit(conn,'model_budget.price_attested',principal,row['id'])
            return public(row)

    def begin(self, token, case_id, request_id):
        case_id,request_id=identifier(case_id),identifier(request_id)
        with connection(self._dsn) as conn:
            principal=self._principal(conn,token,lock=True)
            if principal.role not in {'owner','admin','analyst'}:
                raise AccessDenied('operation_not_permitted')
            row=conn.execute('''SELECT * FROM gabriel_identity.model_investigations
                WHERE organization_id=%s AND request_id=%s''',(principal.organization_id,request_id)).fetchone()
            if row:
                if row['case_id']!=case_id or row['requested_by']!=principal.user_id:
                    raise AccessDenied('model_request_conflict')
                return public(investigation(conn,principal,row['id']))
            case=conn.execute('SELECT state FROM gabriel_identity.cases WHERE organization_id=%s AND id=%s',
                (principal.organization_id,case_id)).fetchone()
            if not case or case['state']!='open':
                raise AccessDenied('model_case_not_open')
            if not limits(conn,principal.organization_id)['enabled']:
                raise AccessDenied('model_budget_paused')
            count=conn.execute('''SELECT count(*) AS n FROM gabriel_identity.model_investigations
                WHERE organization_id=%s AND created_at>clock_timestamp()-interval '1 day' ''',
                (principal.organization_id,)).fetchone()['n']
            if count>=1000:
                raise AccessDenied('model_investigation_daily_limit')
            row=conn.execute('''INSERT INTO gabriel_identity.model_investigations
                (organization_id,id,case_id,requested_by,request_id,created_at,expires_at)
                SELECT %s,%s,%s,%s,%s,t,t+interval '15 minutes'
                FROM (SELECT clock_timestamp() AS t) sampled RETURNING *''',
                (principal.organization_id,uuid4(),case_id,principal.user_id,request_id)).fetchone()
            _audit(conn,'model_budget.investigation_created',principal,row['id'])
            return public(row)

    def reserve(self, token, investigation_id, request_id, quote_id, input_digest,
                max_input_tokens=8000, max_output_tokens=1500):
        request_id,quote_id=identifier(request_id),identifier(quote_id)
        input_digest=fingerprint(input_digest)
        inputs=integer(max_input_tokens,1,8000)
        outputs=integer(max_output_tokens,1,1500)
        with connection(self._dsn) as conn:
            principal=self._principal(conn,token,lock=True)
            if principal.role not in {'owner','admin','analyst'}:
                raise AccessDenied('operation_not_permitted')
            job=investigation(conn,principal,investigation_id,active=True)
            existing=conn.execute('''SELECT * FROM gabriel_identity.model_reservations WHERE
                organization_id=%s AND investigation_id=%s AND request_id=%s''',
                (principal.organization_id,job['id'],request_id)).fetchone()
            if existing:
                if (existing['quote_id'],existing['input_digest'],existing['max_input_tokens'],existing['max_output_tokens'])!=(quote_id,input_digest,inputs,outputs):
                    raise AccessDenied('model_request_conflict')
                return public(reservation(conn,principal,existing['id']))
            policy=limits(conn,principal.organization_id)
            if not policy['enabled']:
                raise AccessDenied('model_budget_paused')
            at=now(conn)
            price=conn.execute('''SELECT q.*,(u.active AND m.active AND m.role IN ('owner','admin')) AS current_authority
                FROM gabriel_identity.model_price_quotes q
                JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(q.organization_id,q.created_by)
                JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE q.organization_id=%s AND q.id=%s''',(principal.organization_id,quote_id)).fetchone()
            if not price or price['expires_at']<=at or not price['current_authority']:
                raise AccessDenied('current_model_price_required')
            amount=max(1,(inputs*price['input_microusd_per_million']+outputs*price['output_microusd_per_million']+999999)//1000000)
            used=usage(conn,principal.organization_id,at)
            job_usage=conn.execute('''SELECT count(*) AS attempts,
                COALESCE(sum(COALESCE(s.actual_microusd,r.reserved_microusd)),0) AS used
                FROM gabriel_identity.model_reservations r LEFT JOIN gabriel_identity.model_settlements s
                ON (s.organization_id,s.reservation_id)=(r.organization_id,r.id)
                WHERE r.organization_id=%s AND r.investigation_id=%s''',
                (principal.organization_id,job['id'])).fetchone()
            if used['held_slots']>=2:
                raise AccessDenied('model_concurrency_or_unknown_limit')
            if job_usage['attempts']>=6:
                raise AccessDenied('model_investigation_call_limit')
            if (used['month_used']+amount>policy['month_microusd'] or used['day_used']+amount>policy['day_microusd']
                    or job_usage['used']+amount>policy['investigation_microusd']):
                raise AccessDenied('model_cost_budget_exhausted')
            if price['expires_at']<=now(conn):
                raise AccessDenied('current_model_price_required')
            investigation(conn,principal,job['id'],active=True)
            row=conn.execute('''INSERT INTO gabriel_identity.model_reservations
                (organization_id,id,investigation_id,quote_id,request_id,input_digest,
                 max_input_tokens,max_output_tokens,reserved_microusd,attempt)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                (principal.organization_id,uuid4(),job['id'],quote_id,request_id,input_digest,
                 inputs,outputs,amount,job_usage['attempts']+1)).fetchone()
            _audit(conn,'model_budget.cost_reserved',principal,row['id'])
            return public(row)

    def claim(self, token, reservation_id, *, _guard=None):
        with connection(self._dsn) as conn:
            principal=self._principal(conn,token,lock=True)
            if principal.role not in {'owner','admin','analyst'}:
                raise AccessDenied('operation_not_permitted')
            row=reservation(conn,principal,reservation_id)
            investigation(conn,principal,row['investigation_id'],active=True)
            if _guard is not None: _guard(conn,principal)
            if row['outcome'] is not None:
                raise AccessDenied('model_reservation_settled')
            if row['claim_id']:
                return dict(claim_id=row['claim_id'],new_claim=False,transport_enabled=False)
            policy=limits(conn,principal.organization_id)
            if not policy['enabled']:
                raise AccessDenied('model_budget_paused')
            used=usage(conn,principal.organization_id,now(conn))
            job_used=conn.execute('''SELECT COALESCE(sum(COALESCE(s.actual_microusd,r.reserved_microusd)),0) AS n
                FROM gabriel_identity.model_reservations r LEFT JOIN gabriel_identity.model_settlements s
                ON (s.organization_id,s.reservation_id)=(r.organization_id,r.id)
                WHERE r.organization_id=%s AND r.investigation_id=%s''',
                (principal.organization_id,row['investigation_id'])).fetchone()['n']
            if (used['month_used']>policy['month_microusd'] or used['day_used']>policy['day_microusd']
                    or job_used>policy['investigation_microusd']):
                raise AccessDenied('model_cost_budget_exhausted')
            price=conn.execute('''SELECT q.expires_at,u.active AS user_active,m.active,m.role
                FROM gabriel_identity.model_price_quotes q
                JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(q.organization_id,q.created_by)
                JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE q.organization_id=%s AND q.id=%s''',(principal.organization_id,row['quote_id'])).fetchone()
            if price['expires_at']<=now(conn) or not price['user_active'] or not price['active'] or price['role'] not in {'owner','admin'}:
                raise AccessDenied('current_model_price_required')
            claim_id=uuid4()
            conn.execute('''INSERT INTO gabriel_identity.model_dispatch_claims
                (organization_id,reservation_id,id,claimed_by) VALUES (%s,%s,%s,%s)''',
                (principal.organization_id,row['id'],claim_id,principal.user_id))
            _audit(conn,'model_budget.dispatch_claimed',principal,row['id'])
            return dict(claim_id=claim_id,new_claim=True,transport_enabled=False)

    def settle(self, token, reservation_id, actual_microusd, receipt_digest):
        amount=integer(actual_microusd,0,100000000)
        receipt_digest=fingerprint(receipt_digest)
        with connection(self._dsn) as conn:
            principal=self._admin(conn,token)
            row=reservation(conn,principal,reservation_id)
            if row['outcome'] is not None:
                if (row['outcome'],row['actual_microusd'],row['receipt_digest'])!=('operator_reported',amount,receipt_digest):
                    raise AccessDenied('model_settlement_conflict')
                return public(row)
            if not row['claim_id']:
                raise AccessDenied('model_dispatch_claim_required')
            duplicate=conn.execute('''SELECT reservation_id FROM gabriel_identity.model_settlements
                WHERE organization_id=%s AND receipt_digest=%s''',(principal.organization_id,receipt_digest)).fetchone()
            if duplicate:
                raise AccessDenied('model_receipt_already_used')
            conn.execute('''INSERT INTO gabriel_identity.model_settlements
                (organization_id,reservation_id,attested_by,outcome,actual_microusd,receipt_digest)
                VALUES (%s,%s,%s,'operator_reported',%s,%s)''',
                (principal.organization_id,row['id'],principal.user_id,amount,receipt_digest))
            _audit(conn,'model_budget.operator_settlement',principal,row['id'])
            return public(reservation(conn,principal,row['id']))

    def stop(self, token, investigation_id):
        with connection(self._dsn) as conn:
            principal=self._principal(conn,token,lock=True)
            row=investigation(conn,principal,investigation_id)
            if principal.role not in {'owner','admin'} and not (principal.role=='analyst' and principal.user_id==row['requested_by']):
                raise AccessDenied('operation_not_permitted')
            conn.execute('''INSERT INTO gabriel_identity.model_investigation_stops
                (organization_id,investigation_id,stopped_by) VALUES (%s,%s,%s)
                ON CONFLICT (organization_id,investigation_id) DO NOTHING''',
                (principal.organization_id,row['id'],principal.user_id))
            # Only never-claimed work is known to have incurred no provider effect.
            conn.execute('''INSERT INTO gabriel_identity.model_settlements
                (organization_id,reservation_id,attested_by,outcome,actual_microusd)
                SELECT r.organization_id,r.id,%s,'not_sent',0
                FROM gabriel_identity.model_reservations r
                WHERE r.organization_id=%s AND r.investigation_id=%s
                AND NOT EXISTS (SELECT 1 FROM gabriel_identity.model_dispatch_claims d
                  WHERE (d.organization_id,d.reservation_id)=(r.organization_id,r.id))
                ON CONFLICT (organization_id,reservation_id) DO NOTHING''',
                (principal.user_id,principal.organization_id,row['id']))
            _audit(conn,'model_budget.investigation_stopped',principal,row['id'])
            return public(investigation(conn,principal,row['id']))
