"""Persist twelve bounded local role reviews against real PostgreSQL and crypto."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import secrets
from uuid import uuid4

import pytest

from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied, InvalidIdentityInput, IdentityUnavailable, migrate
from gabriel.identity.specialist_contracts import validate_packet,validate_result
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,row_and_file,audit_permission
from testing.gabriel_identity.test_specialist_analysis import CASES,document
from testing.gabriel_identity.db_history import remove_v20

pytestmark=pytest.mark.integration


def intake(tenant,cases,case,evidence,kind='alert',data=None):
    doc=document(kind,data or dict(severity='critical',state='open'))
    doc['case_id']=str(case['id'])
    doc['facts'][0].update(evidence_id=str(evidence['id']),evidence_digest=evidence['digest'])
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(doc),'Generated typed specialist facts',approved=True)
    return doc,holder


@pytest.mark.parametrize('role,kind,data,expected,urgency',CASES)
def test_each_role_persists_replays_and_reads_from_fresh_service(tenant,cases,case,evidence,role,kind,data,expected,urgency):
    doc,holder=intake(tenant,cases,case,evidence,kind,data)
    request=uuid4()
    run=cases.run_specialist(tenant.token,case['id'],request,role,input_evidence_id=holder['id'])
    assert expected in run['result']['observations'][0]['statement']
    assert run['result']['urgency']==urgency and not run['grants_authority']
    assert run['packet']['fact_count']==1 and run['packet']['input_digest']==holder['digest']
    assert run['packet']['source_authenticity']=='unverified' and run['packet']['evidence_bodies_included'] is False
    assert run['result']['attack_status']=='unknown' and run['result']['execution']['provider'] is None
    assert cases.run_specialist(tenant.token,case['id'],request,role,input_evidence_id=holder['id'])==run
    assert CaseService(tenant.db.app,cases.store).get_specialist_run(tenant.token,case['id'],run['id'])==run
    raw=json.dumps(run)
    assert doc['facts'][0]['entity_id'] not in raw and doc['facts'][0]['id'] not in raw
    assert tenant.token not in raw
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==1


def test_same_request_concurrent_calls_converge_and_changed_input_is_denied(tenant,cases,case,evidence):
    _,holder=intake(tenant,cases,case,evidence)
    request=uuid4()
    def invoke(_): return cases.run_specialist(tenant.token,case['id'],request,'alert_triage',input_evidence_id=holder['id'])
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(invoke,range(3)))
    assert all(row==rows[0] for row in rows)
    _,other=intake(tenant,cases,case,evidence)
    with pytest.raises(AccessDenied,match='request_conflict'):
        cases.run_specialist(tenant.token,case['id'],request,'alert_triage',input_evidence_id=other['id'])


@pytest.mark.parametrize('attack',['foreign_source','foreign_input','digest','ciphertext','duplicate_json','unsupported_format','conflicting_source_digest'])
def test_bad_source_binding_never_persists_assessment(tenant,cases,case,evidence,attack):
    doc,holder=intake(tenant,cases,case,evidence)
    if attack in {'foreign_source','foreign_input'}:
        other=cases.create_case(tenant.token,'Generated unrelated specialist case')
        artifact=cases.acquire(tenant.token,other['id'],uuid4(),'Generated unrelated source','Generated source',approved=True)
        if attack=='foreign_input': holder=artifact
        else:
            doc['facts'][0].update(evidence_id=str(artifact['id']),evidence_digest=artifact['digest'])
    elif attack=='digest': doc['facts'][0]['evidence_digest']='0'*64
    elif attack=='ciphertext':
        _,path=row_and_file(tenant,cases,evidence);path.chmod(0o600);path.write_bytes(b'generated-corrupt-source')
    elif attack=='conflicting_source_digest': doc['facts'].append(dict(doc['facts'][0],id=str(uuid4()),evidence_digest='f'*64))
    if attack in {'foreign_source','digest','conflicting_source_digest'}:
        holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(doc),'Generated invalid facts',approved=True)
    elif attack=='duplicate_json':
        holder=cases.acquire(tenant.token,case['id'],uuid4(),'{"version":1,"version":2}','Generated ambiguous JSON',approved=True)
    elif attack=='unsupported_format': holder=evidence
    with pytest.raises((AccessDenied,InvalidIdentityInput,EvidenceError)):
        cases.run_specialist(tenant.token,case['id'],uuid4(),'alert_triage',input_evidence_id=holder['id'])
    assert not cases.list_specialist_runs(tenant.token,case['id'])['runs']


def test_viewer_reads_historical_summary_but_cannot_run_and_audit_failure_rolls_back(tenant,cases,case,evidence):
    _,holder=intake(tenant,cases,case,evidence)
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'alert_triage',input_evidence_id=holder['id'])
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'generated-specialist-viewer',password,'viewer')
    token=cases.login(tenant.org,'generated-specialist-viewer',password).token
    assert cases.get_specialist_run(token,case['id'],run['id'])==run
    with pytest.raises(AccessDenied): cases.run_specialist(token,case['id'],uuid4(),'alert_triage',input_evidence_id=holder['id'])
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.run_specialist(tenant.token,case['id'],uuid4(),'alert_triage',input_evidence_id=holder['id'])
    finally: audit_permission(tenant,True)
    assert len(cases.list_specialist_runs(tenant.token,case['id'])['runs'])==1


@pytest.mark.parametrize('attack',['authority','unknown_reference','invented_model','wrong_role','truth_claim','empty_uncertainty','invented_step','input_digest'])
def test_result_validation_rejects_unsafe_or_unbound_summaries(tenant,cases,case,evidence,attack):
    _,holder=intake(tenant,cases,case,evidence)
    run=cases.run_specialist(tenant.token,case['id'],uuid4(),'response_remediation',input_evidence_id=holder['id'])
    packet,result=deepcopy(run['packet']),deepcopy(run['result'])
    if attack=='authority': result['external_actions_authorized']=True
    elif attack=='unknown_reference': result['observations'][0]['references']=['evidence/'+str(uuid4())]
    elif attack=='invented_model': result['execution']['model']='invented'
    elif attack=='wrong_role': result['role']='alert_triage'
    elif attack=='truth_claim': result['observations'][0]['source_verified']=True
    elif attack=='empty_uncertainty': result['uncertainty']=[]
    elif attack=='invented_step': result['next_steps']=['isolate_host']
    else: packet['input_digest']='f'*64
    with pytest.raises(InvalidIdentityInput): validate_result(packet,result)


def test_v19_upgrade_is_atomic_and_retains_old_telemetry_history(tenant,cases,case,evidence,monkeypatch):
    old=cases.run_specialist(tenant.token,case['id'],uuid4(),'telemetry_health')
    with owner_connection(tenant.db) as conn: remove_v20(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v20.sql' else value
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_text',broken)
        with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==19
    assert cases.get_specialist_run(tenant.token,case['id'],old['id'])==old
    migrate(tenant.db.owner)
    _,holder=intake(tenant,cases,case,evidence)
    assert cases.run_specialist(tenant.token,case['id'],uuid4(),'alert_triage',input_evidence_id=holder['id'])['result']['urgency']=='urgent_review'
