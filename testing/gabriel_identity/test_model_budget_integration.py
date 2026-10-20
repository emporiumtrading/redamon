"""Real PostgreSQL budget admission, concurrency and unknown-cost accounting."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import secrets
import json
import os
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.model_budget import ModelBudgetService
from gabriel.identity.service import (AccessDenied, AuthenticationDenied, IdentityUnavailable,
    InvalidIdentityInput, migrate, provision_organization)
from testing.gabriel_identity.test_identity_integration import database, tenant, owner_connection
from testing.gabriel_identity.test_cases_integration import cases, case, audit_permission
from testing.gabriel_identity.db_history import remove_v16

pytestmark=pytest.mark.integration


@pytest.fixture
def budget(tenant):
    return ModelBudgetService(tenant.db.app)


@pytest.fixture
def quote(tenant,budget):
    return budget.quote(tenant.token,'openrouter','google/gemini-2.5-flash-lite','a'*64,100000,400000)


@pytest.fixture
def job(tenant,budget,case):
    return budget.begin(tenant.token,case['id'],uuid4())


def reserve(tenant,budget,job,quote,**kwargs):
    return budget.reserve(tenant.token,job['id'],uuid4(),quote['id'],'b'*64,**kwargs)


def test_defaults_and_integer_reservation_survive_new_service(tenant,budget,job,quote):
    row=reserve(tenant,budget,job,quote)
    assert row['reserved_microusd']==1400 and not row['transport_enabled'] and not row['model_admitted']
    result=ModelBudgetService(tenant.db.app).status(tenant.token)
    assert result['limits']['month_microusd']==18000000
    assert result['usage']==dict(month_used=1400,day_used=1400,held_slots=1)
    assert result['timezone']=='UTC' and result['unit']=='microUSD'
    assert tenant.token not in repr(row) and tenant.db.app not in repr(result)


def test_zero_cost_quote_still_reserves_a_microdollar(tenant,budget,job):
    quote=budget.quote(tenant.token,'nvidia','nvidia/nemotron-3-super-120b-a12b','a'*64,0,0)
    assert reserve(tenant,budget,job,quote)['reserved_microusd']==1


def test_concurrent_distinct_requests_never_exceed_two_slots(tenant,budget,job,quote):
    def attempt(_):
        try:
            return reserve(tenant,budget,job,quote)['id']
        except AccessDenied as error:
            assert str(error)=='model_concurrency_or_unknown_limit'
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(attempt,range(4)))
    assert len([r for r in results if r])==2
    assert budget.status(tenant.token)['usage']['held_slots']==2


def test_duplicate_reservation_and_claim_do_not_repeat_effect(tenant,budget,job,quote):
    request=uuid4()
    def admit(_):
        return budget.reserve(tenant.token,job['id'],request,quote['id'],'b'*64)
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(admit,range(3)))
    assert len({r['id'] for r in rows})==1
    with ThreadPoolExecutor(max_workers=3) as pool:
        claims=list(pool.map(lambda _:budget.claim(tenant.token,rows[0]['id']),range(3)))
    assert sum(c['new_claim'] for c in claims)==1 and len({c['claim_id'] for c in claims})==1
    assert all(not c['transport_enabled'] for c in claims)


def test_changed_idempotent_request_is_denied(tenant,budget,job,quote):
    request=uuid4()
    budget.reserve(tenant.token,job['id'],request,quote['id'],'b'*64)
    with pytest.raises(AccessDenied,match='model_request_conflict'):
        budget.reserve(tenant.token,job['id'],request,quote['id'],'c'*64)


def test_stop_releases_only_never_claimed_reservations(tenant,budget,job,quote):
    first=reserve(tenant,budget,job,quote)
    second=reserve(tenant,budget,job,quote)
    budget.claim(tenant.token,first['id'])
    assert budget.stop(tenant.token,job['id'])['stopped']
    assert budget.status(tenant.token)['usage']==dict(month_used=1400,day_used=1400,held_slots=1)
    with pytest.raises(AccessDenied): budget.claim(tenant.token,first['id'])
    with pytest.raises(AccessDenied): budget.claim(tenant.token,second['id'])
    assert budget.stop(tenant.token,job['id'])['stopped']
    assert budget.status(tenant.token)['usage']['held_slots']==1


def test_reconcile_unknown_after_stop_and_duplicate_settlement(tenant,budget,job,quote):
    row=reserve(tenant,budget,job,quote)
    budget.claim(tenant.token,row['id'])
    budget.stop(tenant.token,job['id'])
    settled=budget.settle(tenant.token,row['id'],700,'c'*64)
    assert settled['outcome']=='operator_reported' and settled['actual_microusd']==700
    assert budget.settle(tenant.token,row['id'],700,'c'*64)==settled
    assert budget.status(tenant.token)['usage']==dict(month_used=700,day_used=700,held_slots=0)
    with pytest.raises(AccessDenied): budget.settle(tenant.token,row['id'],0,'c'*64)


def test_settlement_cannot_create_missing_dispatch_or_reuse_receipt(tenant,budget,job,quote):
    first=reserve(tenant,budget,job,quote)
    with pytest.raises(AccessDenied): budget.settle(tenant.token,first['id'],10,'c'*64)
    budget.claim(tenant.token,first['id'])
    budget.settle(tenant.token,first['id'],10,'c'*64)
    second=reserve(tenant,budget,job,quote)
    budget.claim(tenant.token,second['id'])
    with pytest.raises(AccessDenied,match='model_receipt_already_used'):
        budget.settle(tenant.token,second['id'],10,'c'*64)
    assert budget.status(tenant.token)['usage']['held_slots']==1


def test_all_attempts_including_fallback_share_six_call_limit(tenant,budget,job,quote):
    fallback=budget.quote(tenant.token,'nvidia','nvidia/nemotron-3-super-120b-a12b','d'*64,100000,400000)
    for index in range(6):
        row=reserve(tenant,budget,job,quote if index%2==0 else fallback)
        assert row['attempt']==index+1
        budget.claim(tenant.token,row['id'])
        budget.settle(tenant.token,row['id'],100,sha256(str(index).encode()).hexdigest())
    with pytest.raises(AccessDenied,match='model_investigation_call_limit'):
        reserve(tenant,budget,job,quote)


@pytest.mark.parametrize('field,value',[('month_microusd',1000),('day_microusd',1000),('investigation_microusd',1000)])
def test_configured_cost_limit_blocks_reservation(tenant,budget,job,quote,field,value):
    budget.configure(tenant.token,**{field:value})
    with pytest.raises(AccessDenied,match='model_cost_budget_exhausted'):
        reserve(tenant,budget,job,quote)
    assert budget.status(tenant.token)['usage']['held_slots']==0


def test_lowered_limit_and_pause_prevent_claim_of_existing_reservation(tenant,budget,job,quote):
    row=reserve(tenant,budget,job,quote)
    budget.configure(tenant.token,day_microusd=1)
    with pytest.raises(AccessDenied,match='model_cost_budget_exhausted'): budget.claim(tenant.token,row['id'])
    budget.configure(tenant.token,enabled=False)
    with pytest.raises(AccessDenied,match='model_budget_paused'): budget.claim(tenant.token,row['id'])
    budget.stop(tenant.token,job['id'])
    assert budget.status(tenant.token)['usage']['held_slots']==0


def test_actual_cost_overrun_is_recorded_and_blocks_future_work(tenant,budget,job,quote):
    row=reserve(tenant,budget,job,quote)
    budget.claim(tenant.token,row['id'])
    budget.settle(tenant.token,row['id'],19000000,'c'*64)
    assert budget.status(tenant.token)['usage']['month_used']==19000000
    with pytest.raises(AccessDenied): reserve(tenant,budget,job,quote)


def test_expired_price_and_expired_investigation_block_claim(tenant,budget,job,quote):
    row=reserve(tenant,budget,job,quote)
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.model_price_quotes SET created_at=created_at-interval '2 hours',expires_at=expires_at-interval '2 hours' WHERE id=%s",(quote['id'],))
    with pytest.raises(AccessDenied,match='current_model_price_required'): budget.claim(tenant.token,row['id'])
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.model_investigations SET created_at=created_at-interval '1 hour',expires_at=expires_at-interval '1 hour' WHERE id=%s",(job['id'],))
    with pytest.raises(AccessDenied,match='model_investigation_not_active'): reserve(tenant,budget,job,quote)


def test_unknown_charge_carries_over_utc_month_boundary(tenant,budget,job,quote):
    row=reserve(tenant,budget,job,quote)
    budget.claim(tenant.token,row['id'])
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.model_reservations SET created_at=date_trunc('month',clock_timestamp())-interval '2 days' WHERE id=%s",(row['id'],))
    assert budget.status(tenant.token)['usage']==dict(month_used=1400,day_used=1400,held_slots=1)
    budget.settle(tenant.token,row['id'],700,'c'*64)
    assert budget.status(tenant.token)['usage']==dict(month_used=700,day_used=700,held_slots=0)


def test_viewer_denied_mutations_and_revocation_is_immediate(tenant,budget,job,quote):
    secret=secrets.token_urlsafe(24)
    member=budget.create_member(tenant.token,'budget-viewer',secret,'viewer')
    viewer=budget.login(tenant.org,'budget-viewer',secret).token
    assert not budget.status(viewer)['transport_enabled']
    for operation in (lambda:budget.configure(viewer),lambda:budget.begin(viewer,job['case_id'],uuid4()),
                      lambda:budget.reserve(viewer,job['id'],uuid4(),quote['id'],'b'*64),
                      lambda:budget.quote(viewer,'openrouter','google/gemini-2.5-flash','a'*64,1,1)):
        with pytest.raises(AccessDenied): operation()
    budget.set_membership(tenant.token,member,'viewer',False)
    with pytest.raises(AuthenticationDenied): budget.status(viewer)


def test_analyst_cannot_spend_anothers_investigation_or_attest_cost(tenant,budget,job,quote):
    secret=secrets.token_urlsafe(24)
    budget.create_member(tenant.token,'budget-analyst',secret,'analyst')
    analyst=budget.login(tenant.org,'budget-analyst',secret).token
    with pytest.raises(AccessDenied): budget.reserve(analyst,job['id'],uuid4(),quote['id'],'b'*64)
    with pytest.raises(AccessDenied): budget.stop(analyst,job['id'])
    row=reserve(tenant,budget,job,quote)
    budget.claim(tenant.token,row['id'])
    with pytest.raises(AccessDenied): budget.settle(analyst,row['id'],1,'c'*64)
    own=budget.begin(analyst,job['case_id'],uuid4())
    assert budget.reserve(analyst,own['id'],uuid4(),quote['id'],'d'*64)['attempt']==1


def test_foreign_ids_and_weak_budget_types_denied(tenant,budget,job,quote):
    secret=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated budget outsider','owner',secret)
    foreign=budget.login(org,'owner',secret).token
    for operation in (lambda:budget.reserve(foreign,job['id'],uuid4(),quote['id'],'b'*64),
                      lambda:budget.begin(foreign,job['case_id'],uuid4())):
        with pytest.raises(AccessDenied): operation()
    for value in (True,-1,0,18000001,1.5,'1000'):
        with pytest.raises(InvalidIdentityInput): budget.configure(tenant.token,month_microusd=value)
    for value in (True,0,8001):
        with pytest.raises(InvalidIdentityInput): reserve(tenant,budget,job,quote,max_input_tokens=value)


def test_revoked_price_author_and_job_creator_block_new_claim(tenant,budget,job,quote):
    secret=secrets.token_urlsafe(24)
    admin=budget.create_member(tenant.token,'budget-admin',secret,'admin')
    token=budget.login(tenant.org,'budget-admin',secret).token
    own_quote=budget.quote(token,'openrouter','google/gemini-2.5-flash-lite','a'*64,100000,400000)
    row=reserve(tenant,budget,job,own_quote)
    budget.set_membership(tenant.token,admin,'viewer',True)
    with pytest.raises(AccessDenied,match='current_model_price_required'): budget.claim(tenant.token,row['id'])


def test_revoked_investigation_creator_blocks_admin_claim(tenant,budget,quote,case):
    secret=secrets.token_urlsafe(24)
    actor=budget.create_member(tenant.token,'budget-creator',secret,'analyst')
    token=budget.login(tenant.org,'budget-creator',secret).token
    own=budget.begin(token,case['id'],uuid4())
    row=budget.reserve(token,own['id'],uuid4(),quote['id'],'d'*64)
    budget.set_membership(tenant.token,actor,'analyst',False)
    with pytest.raises(AccessDenied,match='model_investigation_not_active'):
        budget.claim(tenant.token,row['id'])
    budget.stop(tenant.token,own['id'])
    assert budget.status(tenant.token)['usage']['held_slots']==0


def test_cli_uses_private_session_and_dsn_files_without_echo(tenant,budget,tmp_path):
    token_file=tmp_path/'session'
    dsn_file=tmp_path/'app-dsn'
    for target,value in ((token_file,tenant.token),(dsn_file,tenant.db.app)):
        target.write_text(value)
        target.chmod(0o600)
    env={**os.environ,'GABRIEL_IDENTITY_DSN_FILE':str(dsn_file)}
    def call(*args):
        return subprocess.run([sys.executable,'-m','gabriel.identity.budget_cli','--token-file',str(token_file),*args],
                              env=env,capture_output=True,text=True,timeout=20)
    result=call('status')
    assert result.returncode==0 and json.loads(result.stdout)['result']['unit']=='microUSD'
    assert tenant.token not in result.stdout and tenant.db.app not in result.stdout
    result=call('configure','--pause')
    assert result.returncode==0 and not budget.status(tenant.token)['limits']['enabled']
    token_file.write_text('invalid-session')
    result=call('status')
    assert result.returncode==1 and json.loads(result.stdout)['code']=='model_budget_operation_denied'


def test_audit_failure_rolls_back_reservation_and_claim(tenant,budget,job,quote):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): reserve(tenant,budget,job,quote)
    finally:
        audit_permission(tenant,True)
    assert budget.status(tenant.token)['usage']['held_slots']==0
    row=reserve(tenant,budget,job,quote)
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): budget.claim(tenant.token,row['id'])
    finally:
        audit_permission(tenant,True)
    assert budget.claim(tenant.token,row['id'])['new_claim']


def test_append_only_runtime_permissions_and_upgrade_rollback(tenant,budget,job,quote,monkeypatch):
    for table in ('model_reservations','model_settlements','model_dispatch_claims','model_budget_policies'):
        with psycopg.connect(tenant.db.app) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute('DELETE FROM gabriel_identity.'+table)
    with owner_connection(tenant.db) as conn:
        remove_v16(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v16.sql' else value
    monkeypatch.setattr(Path,'read_text',broken)
    with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT to_regclass('gabriel_identity.model_reservations') AS t").fetchone()['t'] is None
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==15
    monkeypatch.setattr(Path,'read_text',original)
    migrate(tenant.db.owner)
    assert budget.status(tenant.token)['usage']['held_slots']==0
