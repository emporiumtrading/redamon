"""Real PostgreSQL, browser authority and persisted bounded specialist results."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import json
import secrets
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.browser_sessions import BrowserSessionService
from gabriel.identity.cases import CaseService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,migrate,provision_organization
from gabriel.identity.specialist_contracts import catalog,validate_result,validate_packet
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,CONTENT,audit_permission
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.db_history import remove_v14

pytestmark=pytest.mark.integration


def test_empty_run_persists_replays_and_never_invents_detection(tenant,cases,case,evidence):
    request=uuid4()
    run=cases.run_specialist(tenant.token,case['id'],request,'telemetry_health')
    result=run['result']
    assert result['attack_status']=='unknown' and result['incident_assessment']=='not_performed'
    assert result['coverage']=='partial' and result['execution']['provider'] is None and result['execution']['model_cost_usd']=='0'
    assert result['observations'][0]['references']==['case/'+str(case['id'])] and not result['observations'][0]['source_verified']
    assert cases.run_specialist(tenant.token,case['id'],request,'telemetry_health')==run
    assert CaseService(tenant.db.app,cases.store).get_specialist_run(tenant.token,case['id'],run['id'])==run
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1 and not run['grants_authority']
    raw=json.dumps(run)
    assert all(secret not in raw for secret in (CONTENT,tenant.token,tenant.db.app,str(cases.store.root),cases.store.keys.active))
    contracts=catalog()
    assert len(contracts)==12 and sum(row['engine'] is not None for row in contracts)==1
    assert all(not row['model_enabled'] and not row['external_actions_enabled'] for row in contracts)


def test_actual_connected_and_revoked_browser_samples_remain_historical(tenant,cases,case,context):
    browser=BrowserSessionService(tenant.db.app,cases.store)
    task=browser.create_browser_task(tenant.token,'Generated specialist task')
    grant=browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    browser.connect_browser(grant.token,context)
    first=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    ref=next(row for row in first['packet']['references'] if row['kind']=='browser_lease_sample')
    assert ref['sample']['health']=='recent_heartbeat' and ref['sample']['page_visibility']=='unverified' and ref['sample']['sampled_at']
    assert first['result']['observations'][0]['references']==['browser_lease/'+str(grant.id)]
    browser.revoke_browser_lease(tenant.token,grant.id)
    second=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    assert 'disconnected' in second['result']['observations'][0]['statement']
    assert cases.get_specialist_run(tenant.token,case['id'],first['id'])==first
    assert first['time_basis']=='historical_individual_samples'


def test_source_samples_are_case_scoped_not_all_tenant_leases(tenant,cases,case,context):
    browser=BrowserSessionService(tenant.db.app,cases.store)
    other=cases.create_case(tenant.token,'Generated unrelated source case')
    task=browser.create_browser_task(tenant.token,'Generated unrelated browser task')
    grant=browser.issue_browser_lease(tenant.token,task['id'],other['id'],context)
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    assert str(grant.id) not in json.dumps(run)
    assert all(row['kind']!='browser_lease_sample' for row in run['packet']['references'])


def test_concurrent_same_request_converges_without_duplicate_run(tenant,cases,case):
    request=uuid4()
    with ThreadPoolExecutor(max_workers=3) as pool:
        runs=list(pool.map(lambda _:cases.run_specialist(tenant.token,case['id'],request,'telemetry_health'),range(3)))
    assert len({row['id'] for row in runs})==1 and all(row==runs[0] for row in runs)
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1


@pytest.mark.parametrize('role',['alert_triage','threat_hunting','response_remediation','arbitrary_shell'])
def test_catalog_or_unrecognized_name_never_enables_engine(tenant,cases,case,role):
    with pytest.raises((AccessDenied,InvalidIdentityInput)): cases.run_specialist(tenant.token,case['id'],uuid4(),role)
    assert not cases.list_specialist_runs(tenant.token,case['id'])['runs']


def test_viewer_history_access_denies_execution_and_revocation_is_live(tenant,cases,case):
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    password=secrets.token_urlsafe(24)
    member=cases.create_member(tenant.token,'specialist-viewer',password,'viewer')
    token=cases.login(tenant.org,'specialist-viewer',password).token
    assert cases.get_specialist_run(token,case['id'],run['id'])['id']==run['id']
    with pytest.raises(AccessDenied): cases.run_specialist(token,case['id'],uuid4(),'telemetry_health')
    cases.set_membership(tenant.token,member,'viewer',False)
    with pytest.raises(AuthenticationDenied): cases.get_specialist_run(token,case['id'],run['id'])


def test_foreign_case_and_other_case_run_ids_are_denied(tenant,cases,case):
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    other=cases.create_case(tenant.token,'Generated wrong specialist case')
    with pytest.raises(AccessDenied): cases.get_specialist_run(tenant.token,other['id'],run['id'])
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated specialist outsider','owner',password)
    foreign=cases.login(org,'owner',password).token
    for operation in (lambda:cases.get_specialist_run(foreign,case['id'],run['id']),lambda:cases.list_specialist_runs(foreign,case['id']),
            lambda:cases.run_specialist(foreign,case['id'],uuid4(),'telemetry_health')):
        with pytest.raises(AccessDenied): operation()


def test_audit_failure_and_completion_failure_leave_no_run(tenant,cases,case,monkeypatch):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    finally: audit_permission(tenant,True)
    import gabriel.identity.specialists as module
    original=module._audit
    def fail_completion(conn,event,*args,**kwargs):
        if event=='specialist.run_completed': raise IdentityUnavailable('injected_completion_audit_failure')
        return original(conn,event,*args,**kwargs)
    monkeypatch.setattr(module,'_audit',fail_completion)
    with pytest.raises(IdentityUnavailable): cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    assert not cases.list_specialist_runs(tenant.token,case['id'])['runs']


def test_session_loss_after_sampling_denies_persistence(tenant,cases,case,monkeypatch):
    import gabriel.identity.specialists as module
    original=module.source_health
    def logout_after_sample(*args,**kwargs):
        data=original(*args,**kwargs)
        cases.logout(tenant.token)
        return data
    monkeypatch.setattr(module,'source_health',logout_after_sample)
    with pytest.raises(AuthenticationDenied): cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


@pytest.mark.parametrize('operation',['UPDATE','DELETE'])
def test_runtime_cannot_edit_or_remove_history(tenant,cases,case,operation):
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            if operation=='DELETE': conn.execute('DELETE FROM gabriel_identity.specialist_runs WHERE id=%s',(run['id'],))
            else: conn.execute("UPDATE gabriel_identity.specialist_runs SET role='telemetry_health' WHERE id=%s",(run['id'],))


@pytest.mark.parametrize('attack',['unknown_reference','truth_claim','attack_conclusion','extra_action','model_claim','wrong_role','empty_uncertainty'])
def test_result_contract_rejects_unadmitted_claims(tenant,cases,case,attack):
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    value=deepcopy(run['result'])
    if attack=='unknown_reference': value['observations'][0]['references']=['case/'+str(uuid4())]
    elif attack=='truth_claim': value['observations'][0]['source_verified']=True
    elif attack=='attack_conclusion': value['attack_status']='no_attack'
    elif attack=='extra_action': value['execute']='isolate_host'
    elif attack=='model_claim': value['execution']['model']='invented-model'
    elif attack=='wrong_role': value['role']='threat_hunting'
    else: value['uncertainty']=[]
    with pytest.raises(InvalidIdentityInput): validate_result(run['packet'],value)


def test_privileged_record_tamper_is_detected(tenant,cases,case):
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.specialist_runs SET result_digest=repeat('0',64) WHERE id=%s",(run['id'],))
    with pytest.raises(AccessDenied,match='specialist_record_integrity_failed'): cases.get_specialist_run(tenant.token,case['id'],run['id'])


@pytest.mark.parametrize('attack',['foreign_case','duplicate_reference','body_field','verified_content','unknown_role','source_limit'])
def test_packet_contract_rejects_scope_and_content_drift(tenant,cases,case,evidence,attack):
    packet=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')['packet']
    if attack=='foreign_case': packet['case_id']=str(uuid4())
    elif attack=='duplicate_reference': packet['references'].append(deepcopy(packet['references'][0]))
    elif attack=='body_field': packet['body']='Unadmitted generated content'
    elif attack=='verified_content': packet['references'][1]['content_integrity']='verified'
    elif attack=='unknown_role': packet['role']='arbitrary_shell'
    else: packet['source_limit']=True
    with pytest.raises(InvalidIdentityInput): validate_packet(packet)


def test_run_quota_is_explicit_and_replay_does_not_create_another_record(tenant,cases,case):
    request=uuid4()
    run=cases.run_specialist(tenant.token,case['id'],request,'telemetry_health')
    with owner_connection(tenant.db) as conn:
        conn.execute('''INSERT INTO gabriel_identity.specialist_runs
            (organization_id,id,case_id,request_id,requested_by,role,engine_version,packet,result,packet_digest,result_digest)
            SELECT organization_id,gen_random_uuid(),case_id,gen_random_uuid(),requested_by,role,engine_version,packet,result,packet_digest,result_digest
            FROM gabriel_identity.specialist_runs CROSS JOIN generate_series(1,127) WHERE id=%s''',(run['id'],))
    with pytest.raises(AccessDenied,match='case_specialist_run_limit'): cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    assert cases.run_specialist(tenant.token,case['id'],request,'telemetry_health')==run
    history=cases.list_specialist_runs(tenant.token,case['id'])
    assert len(history['runs'])==50 and history['truncated']


def test_v13_upgrade_and_interrupted_ddl_preserve_cases(tenant,cases,case,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v14(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v14.sql' else value
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_text',broken)
        with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT to_regclass('gabriel_identity.specialist_runs') AS t").fetchone()['t'] is None
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==13
    migrate(tenant.db.owner)
    assert cases.get_case(tenant.token,case['id'])['case']['title']==case['title']
    assert cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')['result']['attack_status']=='unknown'
