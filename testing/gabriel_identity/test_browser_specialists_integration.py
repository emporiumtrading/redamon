"""Real encrypted captures publish all twelve local reviews atomically and replayably."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity import browser_specialists,specialist_analysis_runs
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,migrate
from gabriel.identity.specialist_contracts import ROLES
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_navigation_integration import browser,grant
from testing.gabriel_identity.test_browser_observations_integration import payload,rows
from testing.gabriel_identity.test_browser_events_integration import admitted,capture,browser_document
from testing.gabriel_identity.test_attack_pattern_runs_integration import event_document
from testing.gabriel_identity.db_history import remove_v26

pytestmark=pytest.mark.integration


@pytest.fixture
def captured(tenant,browser,grant,admitted,payload,case):
    return capture(tenant,browser,grant,payload,browser_document(event_document(case['id'],dict(id=uuid4(),digest='a'*64))))


def test_two_snapshots_publish_twelve_roles_with_real_source_links_and_abstention(tenant,browser,grant,admitted,context,payload,case):
    document=event_document(case['id'],dict(id=uuid4(),digest='a'*64))
    first=capture(tenant,browser,grant,payload,browser_document(document))
    one=browser.review_browser_specialists(tenant.token,grant.token,context,first['observation_id'])
    second=capture(tenant,browser,grant,payload,browser_document(document,5),2)
    two=browser.review_browser_specialists(tenant.token,grant.token,context,second['observation_id'])
    assert two['unique_event_count']==10 and two['specialist_count']==12 and set(two['specialists'])==set(ROLES)
    assert two['abstained_count']==6 and two['model_cost_usd']=='0'
    assert not two['external_actions_authorized'] and not two['quality_qualified']
    facts=json.loads(browser.read_evidence(tenant.token,two['facts_evidence_id']).reveal())
    assert sum(row['data']['count'] for row in facts['facts'] if row['type']=='activity')==10
    assert {row['evidence_id'] for row in facts['facts']}=={str(first['evidence_id']),str(second['evidence_id'])}
    for role,receipt in two['specialists'].items():
        run=browser.get_specialist_run(tenant.token,case['id'],receipt['id'])
        assert run['role']==role and run['result_digest']==receipt['result_digest']
        assert run['packet']['input_evidence_id']==two['facts_evidence_id']
        assert run['result']['confidence']=='unqualified' and not run['grants_authority']
    assert browser.review_browser_specialists(tenant.token,grant.token,context,first['observation_id'])==one
    assert len(rows(tenant,'specialist_runs'))==24 and len(rows(tenant,'browser_specialist_suites'))==2
    assert document['events'][0]['actor_id'] not in json.dumps(rows(tenant,'browser_specialist_suites'),default=str)


def test_concurrent_calls_converge_to_one_suite_and_derived_artifact(tenant,browser,grant,context,captured):
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda _:browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id']),range(3)))
    assert all(row==results[0] for row in results)
    assert len(rows(tenant,'browser_specialist_suites'))==1 and len(rows(tenant,'specialist_runs'))==12
    assert len(rows(tenant,'evidence_objects'))==3


@pytest.mark.parametrize('boundary',['specialist','suite'])
def test_any_receipt_failure_rolls_back_all_twelve_results_then_retry_is_idempotent(tenant,browser,grant,context,captured,monkeypatch,boundary):
    module=specialist_analysis_runs if boundary=='specialist' else browser_specialists
    original=module._audit;seen=[]
    def fail(conn,event,*args):
        if event==('specialist.run_completed' if boundary=='specialist' else 'browser.specialist_suite_completed'):
            seen.append(event)
            if boundary=='suite' or len(seen)==5: raise IdentityUnavailable('generated_atomic_receipt_failure')
        return original(conn,event,*args)
    with monkeypatch.context() as patch:
        patch.setattr(module,'_audit',fail)
        with pytest.raises(IdentityUnavailable): browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    assert not rows(tenant,'specialist_runs') and not rows(tenant,'browser_specialist_suites')
    result=browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    assert result['specialist_count']==12 and len(rows(tenant,'evidence_objects'))==3


@pytest.mark.parametrize('boundary',['stop','logout'])
def test_authority_loss_after_derivation_prevents_all_specialist_writes(tenant,browser,grant,context,captured,monkeypatch,boundary):
    original=browser.acquire
    def interrupted(*args,**kwargs):
        value=original(*args,**kwargs)
        if args[4]=='Browser specialist fact projection':
            if boundary=='stop': browser.disconnect_browser(grant.token)
            else: browser.logout(tenant.token)
        return value
    monkeypatch.setattr(browser,'acquire',interrupted)
    with pytest.raises(AuthenticationDenied): browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    assert not rows(tenant,'specialist_runs') and not rows(tenant,'browser_specialist_suites')


def test_corrupt_original_capture_denies_replay_without_changing_saved_suite(tenant,browser,grant,context,captured):
    browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    with owner_connection(tenant.db) as conn:
        row=conn.execute('SELECT object_id FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND id=%s',(tenant.org,captured['evidence_id'])).fetchone()
    path=browser.store.root/(row['object_id'].hex+'.gbe');path.chmod(0o600);path.write_bytes(b'generated-corrupt-capture')
    with pytest.raises(EvidenceError): browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    assert len(rows(tenant,'specialist_runs'))==12 and len(rows(tenant,'browser_specialist_suites'))==1


def test_expired_wall_clock_budget_rolls_back_partial_local_work(tenant,browser,grant,context,captured,monkeypatch):
    original=browser_specialists.run_in_connection
    real_clock=browser_specialists.time.monotonic;offset=[0];completed=[]
    def delayed(*args,**kwargs):
        result=original(*args,**kwargs);completed.append(result['id'])
        if len(completed)==3: offset[0]=11
        return result
    with monkeypatch.context() as patch:
        patch.setattr(browser_specialists.time,'monotonic',lambda:real_clock()+offset[0])
        patch.setattr(browser_specialists,'run_in_connection',delayed)
        with pytest.raises(AccessDenied,match='browser_specialist_time_budget'):
            browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    assert len(completed)==3 and not rows(tenant,'specialist_runs') and not rows(tenant,'browser_specialist_suites')


def test_tampered_suite_receipt_is_rejected(tenant,browser,grant,context,captured):
    browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.browser_specialist_suites SET result_digest=%s WHERE organization_id=%s",('0'*64,tenant.org))
    with pytest.raises(AccessDenied,match='receipt_mismatch'): browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    assert len(rows(tenant,'specialist_runs'))==12


def test_case_quota_rejects_entire_new_suite_before_partial_publication(tenant,browser,grant,admitted,context,captured,payload,case):
    result=browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    with owner_connection(tenant.db) as conn:
        conn.execute('''INSERT INTO gabriel_identity.specialist_runs
            (organization_id,id,case_id,request_id,requested_by,role,engine_version,packet,result,packet_digest,result_digest)
            SELECT organization_id,gen_random_uuid(),case_id,gen_random_uuid(),requested_by,role,engine_version,
                packet,result,packet_digest,result_digest FROM gabriel_identity.specialist_runs CROSS JOIN generate_series(1,105)
            WHERE organization_id=%s AND id=%s''',(tenant.org,result['specialists']['telemetry_health']['id']))
    second=capture(tenant,browser,grant,payload,browser_document(event_document(case['id'],dict(id=uuid4(),digest='a'*64))),2)
    with pytest.raises(AccessDenied,match='case_specialist_run_limit'):
        browser.review_browser_specialists(tenant.token,grant.token,context,second['observation_id'])
    assert len(rows(tenant,'specialist_runs'))==117 and len(rows(tenant,'browser_specialist_suites'))==1


def test_v26_upgrade_failure_is_atomic(tenant,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v26(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        text=original(path,*args,**kwargs);return text+'\nSELECT 1/0;' if path.name=='schema_v26.sql' else text
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_text',broken)
        with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==25
        assert conn.execute("SELECT to_regclass('gabriel_identity.browser_specialist_suites') AS t").fetchone()['t'] is None
    migrate(tenant.db.owner)


def test_runtime_cannot_mutate_or_delete_suite_history(tenant,browser,grant,context,captured):
    browser.review_browser_specialists(tenant.token,grant.token,context,captured['observation_id'])
    for sql in ('DELETE FROM gabriel_identity.browser_specialist_suites',
            'UPDATE gabriel_identity.browser_specialist_suites SET result_digest=result_digest'):
        with psycopg.connect(tenant.db.app) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(sql)
