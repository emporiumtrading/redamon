"""Generated candidate events bound to real encrypted case evidence and immutable review records."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import secrets
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.attack_pattern_runs import validate
from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,IdentityUnavailable,migrate
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,row_and_file,audit_permission
from testing.gabriel_identity.db_history import remove_v23

pytestmark=pytest.mark.integration


def event_document(case_id,source,count=10):
    source_id,actor,asset,origin=(str(uuid4()) for _ in range(4))
    return dict(version='security-events-v1',case_id=str(case_id),as_of='2026-10-20T12:10:00Z',
        missing_sources=['process','file','kernel','boot'],events=[dict(source_id=source_id,event_id='generated-failure-'+str(i),
            evidence_id=str(source['id']),evidence_digest=source['digest'],event_time='2026-10-20T12:09:'+str(i).zfill(2)+'Z',
            kind='auth_failure',actor_id=actor,asset_id=asset,source_asset_id=origin,process_sha256=None,object_id=None,
            authorization='approved') for i in range(count)])


def intake(tenant,cases,case,evidence,document=None):
    document=document or event_document(case['id'],evidence)
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(document),'Generated security event snapshot',approved=True)
    return document,holder


def test_review_binds_source_bytes_and_retains_hypotheses_not_authority(tenant,cases,case,evidence):
    document,holder=intake(tenant,cases,case,evidence)
    request=uuid4()
    run=cases.run_attack_review(tenant.token,case['id'],request,holder['id'])
    assert [row['family'] for row in run['result']['findings']]==['brute_force']
    finding=run['result']['findings'][0]
    assert finding['reported_approved_event_count']==10 and finding['references']==['evidence/'+str(evidence['id'])]
    assert finding['status']=='suspected_requires_review' and not finding['source_verified']
    assert not run['result']['quality_qualified'] and not run['result']['live_detection_accepted'] and not run['grants_authority']
    assert run['model_cost_usd']=='0' and run['packet']['input_digest']==holder['digest']
    assert all(row['content_integrity']=='verified_at_review' for row in run['packet']['references'])
    assert document['events'][0]['actor_id'] not in json.dumps(run) and document['events'][0]['event_id'] not in json.dumps(run)
    assert cases.run_attack_review(tenant.token,case['id'],request,holder['id'])==run
    assert CaseService(tenant.db.app,cases.store).get_attack_review(tenant.token,case['id'],run['id'])==run


def test_concurrent_replays_converge_and_changed_input_is_denied(tenant,cases,case,evidence):
    _,holder=intake(tenant,cases,case,evidence);request=uuid4()
    with ThreadPoolExecutor(max_workers=3) as pool:
        runs=list(pool.map(lambda _:cases.run_attack_review(tenant.token,case['id'],request,holder['id']),range(3)))
    assert all(run==runs[0] for run in runs) and len(cases.list_attack_reviews(tenant.token,case['id'])['runs'])==1
    _,other=intake(tenant,cases,case,evidence)
    with pytest.raises(AccessDenied,match='request_conflict'): cases.run_attack_review(tenant.token,case['id'],request,other['id'])


@pytest.mark.parametrize('attack',['foreign_source','foreign_input','digest','ciphertext','duplicate_json','model_source','conflicting_digest'])
def test_unverified_or_wrongly_bound_inputs_never_publish(tenant,cases,case,evidence,attack):
    document=event_document(case['id'],evidence)
    holder=None
    if attack in {'foreign_source','foreign_input'}:
        other=cases.create_case(tenant.token,'Generated other attack review case')
        foreign=cases.acquire(tenant.token,other['id'],uuid4(),'Generated other source','Generated other source',approved=True)
        if attack=='foreign_input': holder=foreign
        else:
            for event in document['events']: event.update(evidence_id=str(foreign['id']),evidence_digest=foreign['digest'])
    elif attack=='digest':
        for event in document['events']: event['evidence_digest']='0'*64
    elif attack=='ciphertext':
        _,path=row_and_file(tenant,cases,evidence);path.chmod(0o600);path.write_bytes(b'generated-corrupt-security-source')
    elif attack=='duplicate_json': holder=cases.acquire(tenant.token,case['id'],uuid4(),'{"version":1,"version":2}','Generated duplicate JSON',approved=True)
    elif attack=='model_source':
        generated=cases.acquire(tenant.token,case['id'],uuid4(),'Generated model answer','Generated model answer',approved=True,_model_generated=True)
        for event in document['events']: event.update(evidence_id=str(generated['id']),evidence_digest=generated['digest'])
    elif attack=='conflicting_digest': document['events'][1]['evidence_digest']='f'*64
    if holder is None: _,holder=intake(tenant,cases,case,evidence,document)
    with pytest.raises((AccessDenied,InvalidIdentityInput,EvidenceError)): cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    assert not cases.list_attack_reviews(tenant.token,case['id'])['runs']


def test_viewer_reads_history_but_cannot_run_and_audit_failure_rolls_back(tenant,cases,case,evidence):
    _,holder=intake(tenant,cases,case,evidence)
    run=cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'generated-attack-viewer',password,'viewer')
    viewer=cases.login(tenant.org,'generated-attack-viewer',password).token
    assert cases.get_attack_review(viewer,case['id'],run['id'])==run
    with pytest.raises(AccessDenied): cases.run_attack_review(viewer,case['id'],uuid4(),holder['id'])
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    finally: audit_permission(tenant,True)
    assert len(cases.list_attack_reviews(tenant.token,case['id'])['runs'])==1


@pytest.mark.parametrize('tamper',['authority','source_truth','quality','reference','alternative'])
def test_stored_claim_contract_rejects_invented_authority_or_support(tenant,cases,case,evidence,tamper):
    _,holder=intake(tenant,cases,case,evidence)
    run=cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id']);result=deepcopy(run['result'])
    if tamper=='authority': result['external_actions_authorized']=True
    elif tamper=='source_truth': result['findings'][0]['source_verified']=True
    elif tamper=='quality': result['quality_qualified']=True
    elif tamper=='reference': result['findings'][0]['references']=['evidence/'+str(uuid4())]
    else: result['findings'][0]['alternative']='Generated unsupported attribution'
    with pytest.raises(InvalidIdentityInput): validate(run['packet'],result)


def test_no_match_retains_unknown_quality_and_explicit_coverage_gaps(tenant,cases,case,evidence):
    _,holder=intake(tenant,cases,case,evidence,event_document(case['id'],evidence,1))
    run=cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    assert not run['result']['findings'] and run['result']['coverage']=='partial'
    assert run['result']['missing_sources']==['process','file','kernel','boot'] and not run['result']['live_detection_accepted']


def test_review_table_is_append_only_and_upgrade_is_atomic(tenant,cases,case,evidence,monkeypatch):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute('DELETE FROM gabriel_identity.attack_pattern_runs')
    with owner_connection(tenant.db) as conn: remove_v23(conn)
    read=Path.read_text
    def interrupted(path,*args,**kwargs):
        raw=read(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v23.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        assert cases.read_evidence(tenant.token,evidence['id']).reveal()
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.attack_pattern_runs') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==22
    finally: migrate(tenant.db.owner)
