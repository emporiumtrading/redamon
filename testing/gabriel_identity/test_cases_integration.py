"""Generated approved artifacts against real PostgreSQL and encrypted files."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.cases import CaseService
from gabriel.identity.actions import ActionService
from gabriel.identity.case_cli import ExportError,approved_file,export_file
from gabriel.identity.evidence_store import EvidenceError,EvidenceKeys,LocalEvidenceStore,MAX_BYTES
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import (AccessDenied,AuthenticationDenied,IdentityConfigurationError,
    IdentityUnavailable,InvalidIdentityInput,migrate,provision_organization)
from gabriel.identity.vault import ProviderKeyRing
from testing.gabriel_identity.db_history import remove_v5
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection

pytestmark = pytest.mark.integration
CONTENT = 'Generated approved evidence fixture — no live telemetry.'


@pytest.fixture
def cases(tenant,tmp_path):
    root = tmp_path/'objects'
    root.mkdir(mode=0o700)
    key_id = 'k_'+uuid4().hex
    return CaseService(tenant.db.app,LocalEvidenceStore(root,EvidenceKeys(key_id,{key_id:secrets.token_bytes(32)},1)))


@pytest.fixture
def case(tenant,cases):
    return cases.create_case(tenant.token,'Generated case fixture')


@pytest.fixture
def evidence(tenant,cases,case):
    return intake(tenant,cases,case)


def intake(tenant,cases,case,**kwargs):
    options = dict(approved=True,event_time='2026-01-01T00:00:00+00:00')
    options.update(kwargs)
    return cases.acquire(tenant.token,case['id'],uuid4(),CONTENT,'approved artifact fixture',**options)


def row_and_file(tenant,cases,evidence):
    with owner_connection(tenant.db) as conn:
        row = conn.execute('SELECT * FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND id=%s',
            (tenant.org,evidence['id'])).fetchone()
    return row,cases.store.root/(row['object_id'].hex+'.gbe')


def audit_permission(tenant,enabled):
    with owner_connection(tenant.db) as conn:
        conn.execute(('GRANT INSERT ON gabriel_identity.audit_events TO gabriel_identity_app' if enabled else
            'REVOKE INSERT ON gabriel_identity.audit_events FROM gabriel_identity_app'))


def test_encryption_provenance_and_custody_survive_new_service(tenant,cases,case,evidence):
    row,path = row_and_file(tenant,cases,evidence)
    assert CONTENT.encode() not in path.read_bytes()
    assert len(path.read_bytes())==len(CONTENT.encode())+28
    assert row['digest']==sha256(CONTENT.encode()).hexdigest()
    assert row['observed_at']>row['source_event_time']
    assert row['source_kind']=='user_supplied_text' and row['parser_version']=='supplied-utf8-v1'
    assert evidence['source_verified'] is False and evidence['normalization_status']=='unverified_user_supplied'
    fresh = CaseService(tenant.db.app,cases.store)
    bundle = fresh.read_evidence(tenant.token,evidence['id'])
    assert bundle.reveal()==CONTENT.encode() and CONTENT not in repr(bundle)
    chain = fresh.custody(tenant.token,evidence['id'])
    assert [r['event'] for r in chain]==['acquisition_intent','acquired','accessed']
    assert [r['sequence'] for r in chain]==[1,2,3]
    assert all(r['actor_id']==tenant.owner for r in chain)
    assert fresh.verify_case(tenant.token,case['id'])['complete']
    assert CONTENT not in repr(fresh.get_case(tenant.token,case['id']))


def test_redacted_child_keeps_separate_original(tenant,cases,case,evidence):
    child = cases.acquire(tenant.token,case['id'],uuid4(),'Redacted generated fixture','redacted fixture',
        approved=True,redaction_state='user_declared_redacted',parent_id=evidence['id'])
    assert child['parent_id']==evidence['id'] and child['digest']!=evidence['digest']
    assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    assert len(cases.get_case(tenant.token,case['id'])['evidence'])==2


def test_concurrent_intake_retry_has_one_object_and_acquisition(tenant,cases,case):
    ingestion = uuid4()
    def acquire(_):
        return cases.acquire(tenant.token,case['id'],ingestion,CONTENT,'retry fixture',approved=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(acquire,range(4)))
    assert len({row['id'] for row in rows})==1
    assert len(list(cases.store.root.iterdir()))==1
    assert [r['event'] for r in cases.custody(tenant.token,rows[0]['id'])]==['acquisition_intent','acquired']
    for content,label in [('changed','retry fixture'),(CONTENT,'changed label')]:
        with pytest.raises(AccessDenied,match='evidence_intake_conflict'):
            cases.acquire(tenant.token,case['id'],ingestion,content,label,approved=True)


def test_real_task_links_and_closed_case_intake_gate(tenant,cases,case,evidence):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'case task',['evidence.hash'])
    cases.link_task(tenant.token,case['id'],task['id'])
    cases.link_task(tenant.token,case['id'],task['id'])
    assert cases.get_case(tenant.token,case['id'])['task_ids']==[task['id']]
    with pytest.raises(AccessDenied):
        cases.link_task(tenant.token,case['id'],uuid4())
    actions = ActionService(tenant.db.app,cases.store)
    actions.set_policy(tenant.token,distinct_approver=False)
    request = actions.propose_close(tenant.token,case['id'],uuid4(),'Approved local closure')
    actions.submit(tenant.token,request['id'])
    actions.approve(tenant.token,request['id'],request['digest'])
    cases.close_case(tenant.token,case['id'],approval_id=request['id'])
    assert cases.get_case(tenant.token,case['id'])['case']['state']=='closed'
    with pytest.raises(AccessDenied,match='case_not_open'):
        intake(tenant,cases,case)
    assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()


def test_cross_tenant_case_evidence_parent_and_task_access_denied(tenant,cases,case,evidence):
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Other generated tenant','owner',password)
    token = cases.login(org,'owner',password).token
    other = cases.create_case(token,'Other generated case')
    task = ServiceIdentityService(tenant.db.app).create_task(token,'other task',['evidence.hash'])
    assert len(cases.list_cases(token))==1
    for call in (lambda:cases.get_case(token,case['id']),lambda:cases.read_evidence(token,evidence['id']),
        lambda:cases.custody(token,evidence['id']),lambda:cases.close_case(token,case['id']),
        lambda:cases.link_task(tenant.token,case['id'],task['id']),
        lambda:cases.acquire(token,other['id'],uuid4(),CONTENT,'fixture',approved=True,parent_id=evidence['id'])):
        with pytest.raises(AccessDenied):
            call()
    same_tenant_other = cases.create_case(tenant.token,'Other local case')
    with pytest.raises(AccessDenied):
        intake(tenant,cases,same_tenant_other,parent_id=evidence['id'])


@pytest.mark.parametrize('role',['viewer','analyst'])
def test_current_role_controls_content_and_writes(tenant,cases,case,evidence,role):
    password = secrets.token_urlsafe(24)
    member = cases.create_member(tenant.token,'case-member',password,role)
    token = cases.login(tenant.org,'case-member',password).token
    assert cases.get_case(token,case['id'])['evidence'][0]['id']==evidence['id']
    assert cases.verify_case(token,case['id'])['complete']
    if role=='viewer':
        for call in (lambda:cases.read_evidence(token,evidence['id']),lambda:cases.prepare_export(token,evidence['id']),
            lambda:cases.create_case(token,'denied'),lambda:cases.close_case(token,case['id'])):
            with pytest.raises(AccessDenied):
                call()
    else:
        assert cases.read_evidence(token,evidence['id']).reveal()==CONTENT.encode()
    cases.set_membership(tenant.token,member,role,False)
    with pytest.raises(AuthenticationDenied):
        cases.get_case(token,case['id'])


def test_worker_cannot_access_cases_or_content(tenant,cases,case,evidence):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'worker task',['evidence.hash'])
    worker = service.issue_service(tenant.token,'worker',task['id'],['evidence.hash'])
    for call in (lambda:cases.get_case(worker.token,case['id']),lambda:cases.read_evidence(worker.token,evidence['id']),
        lambda:cases.create_case(worker.token,'denied')):
        with pytest.raises(AuthenticationDenied):
            call()


@pytest.mark.parametrize('damage',['missing','ciphertext','metadata','gap','custody_hash','symlink','oversize'])
def test_tamper_or_missing_data_blocks_read_export_and_closure(tenant,cases,case,evidence,damage,tmp_path):
    row,path = row_and_file(tenant,cases,evidence)
    if damage in {'missing','symlink'}:
        path.unlink()
        if damage=='symlink':
            target = tmp_path/'outside'
            target.write_text(CONTENT)
            path.symlink_to(target)
    elif damage in {'ciphertext','oversize'}:
        path.chmod(0o600)
        value = bytearray(path.read_bytes())
        value[-1] ^= 1
        path.write_bytes(value if damage=='ciphertext' else b'x'*(MAX_BYTES+29))
    else:
        with owner_connection(tenant.db) as conn:
            if damage=='metadata':
                conn.execute("UPDATE gabriel_identity.evidence_objects SET source_label='tampered' WHERE id=%s",(row['id'],))
            elif damage=='gap':
                conn.execute('DELETE FROM gabriel_identity.custody_events WHERE evidence_id=%s AND sequence=1',(row['id'],))
            else:
                conn.execute("UPDATE gabriel_identity.custody_events SET event_hash=repeat('0',64) WHERE evidence_id=%s AND sequence=2",(row['id'],))
    assert not cases.verify_case(tenant.token,case['id'])['complete']
    for call in (lambda:cases.read_evidence(tenant.token,row['id']),lambda:cases.prepare_export(tenant.token,row['id']),
        lambda:cases.close_case(tenant.token,case['id'])):
        with pytest.raises(EvidenceError):
            call()
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE target_id=%s AND event='case.closure_blocked'",(case['id'],)).fetchone()['n']==1
    assert cases.get_case(tenant.token,case['id'])['case']['state']=='open'


@pytest.mark.parametrize('mode',['missing','wrong'])
def test_key_loss_or_identity_reuse_fails_closed(tenant,cases,case,evidence,mode):
    key_id = cases.store.keys.active if mode=='wrong' else 'k_'+uuid4().hex
    bad = CaseService(tenant.db.app,LocalEvidenceStore(cases.store.root,EvidenceKeys(key_id,{key_id:secrets.token_bytes(32)},1)))
    assert not bad.verify_case(tenant.token,case['id'])['complete']
    with pytest.raises(EvidenceError):
        bad.read_evidence(tenant.token,evidence['id'])
    assert cases.verify_case(tenant.token,case['id'])['complete']


def test_audit_failure_before_intake_creates_no_file_or_metadata(tenant,cases,case):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable):
            intake(tenant,cases,case)
    finally:
        audit_permission(tenant,True)
    assert cases.get_case(tenant.token,case['id'])['evidence']==[]
    assert list(cases.store.root.iterdir())==[]


def test_file_written_then_audit_failure_remains_pending_and_retry_recovers(tenant,cases,case,monkeypatch):
    original = cases.store.write
    def interrupted(*args):
        original(*args)
        audit_permission(tenant,False)
    ingestion = uuid4()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(cases.store,'write',interrupted)
            with pytest.raises(IdentityUnavailable):
                cases.acquire(tenant.token,case['id'],ingestion,CONTENT,'recovery fixture',approved=True)
    finally:
        audit_permission(tenant,True)
    pending = cases.get_case(tenant.token,case['id'])['evidence'][0]
    assert pending['state']=='pending' and len(list(cases.store.root.iterdir()))==1
    with pytest.raises(EvidenceError):
        cases.close_case(tenant.token,case['id'])
    done = cases.acquire(tenant.token,case['id'],ingestion,CONTENT,'recovery fixture',approved=True)
    assert done['id']==pending['id'] and done['state']=='ready'
    assert cases.read_evidence(tenant.token,done['id']).reveal()==CONTENT.encode()


def test_failed_object_creation_is_visible_and_recoverable(tenant,cases,case,monkeypatch):
    ingestion = uuid4()
    def unavailable(*args):
        raise EvidenceError('evidence_object_write_failed')
    with monkeypatch.context() as patch:
        patch.setattr(cases.store,'write',unavailable)
        with pytest.raises(EvidenceError):
            cases.acquire(tenant.token,case['id'],ingestion,CONTENT,'recoverable fixture',approved=True)
    row = cases.get_case(tenant.token,case['id'])['evidence'][0]
    assert row['state']=='quarantined' and row['failure_code']=='evidence_object_write_failed'
    assert not cases.verify_case(tenant.token,case['id'])['complete']
    done = cases.acquire(tenant.token,case['id'],ingestion,CONTENT,'recoverable fixture',approved=True)
    assert done['id']==row['id'] and done['state']=='ready'


def test_export_intent_precedes_plaintext_and_no_overwrite(tenant,cases,evidence,tmp_path):
    output = tmp_path/'export.txt'
    result = export_file(cases,tenant.token,evidence['id'],output)
    assert output.read_bytes()==CONTENT.encode() and output.stat().st_mode & 0o777==0o600
    assert result['digest']==evidence['digest']
    assert cases.list_exports(tenant.token)[0]['state']=='completed'
    events = [r['event'] for r in cases.custody(tenant.token,evidence['id'])]
    assert events[-2:]==['export_prepared','export_completed']
    with pytest.raises(ExportError,match='export_file_write_failed'):
        export_file(cases,tenant.token,evidence['id'],output)
    assert output.read_bytes()==CONTENT.encode()
    assert any(r['state']=='file_write_failed' for r in cases.list_exports(tenant.token))


def test_export_completion_audit_failure_keeps_receipt_prepared(tenant,cases,evidence,tmp_path,monkeypatch):
    original = cases.finish_export
    def interrupted(*args,**kwargs):
        audit_permission(tenant,False)
        return original(*args,**kwargs)
    output = tmp_path/'written.txt'
    try:
        with monkeypatch.context() as patch:
            patch.setattr(cases,'finish_export',interrupted)
            with pytest.raises(ExportError,match='export_completion_unrecorded') as error:
                export_file(cases,tenant.token,evidence['id'],output)
    finally:
        audit_permission(tenant,True)
    assert output.read_bytes()==CONTENT.encode()
    receipt = cases.list_exports(tenant.token)[0]
    assert receipt['state']=='prepared' and str(receipt['id'])==error.value.export_id
    cases.finish_export(tenant.token,receipt['id'],completed=True,written_digest=sha256(output.read_bytes()).hexdigest())
    assert cases.list_exports(tenant.token)[0]['state']=='completed'


def test_export_same_actor_digest_and_finalization_gates(tenant,cases,evidence):
    bundle = cases.prepare_export(tenant.token,evidence['id'])
    with pytest.raises(EvidenceError,match='export_digest_mismatch'):
        cases.finish_export(tenant.token,bundle.export_id,completed=True,written_digest='0'*64)
    password = secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'other-analyst',password,'analyst')
    token = cases.login(tenant.org,'other-analyst',password).token
    with pytest.raises(AccessDenied):
        cases.finish_export(token,bundle.export_id,completed=True,written_digest=evidence['digest'])
    cases.finish_export(tenant.token,bundle.export_id,completed=False)
    cases.finish_export(tenant.token,bundle.export_id,completed=False)
    with pytest.raises(AccessDenied):
        cases.finish_export(tenant.token,bundle.export_id,completed=True,written_digest=evidence['digest'])


@pytest.mark.parametrize('query',[
    "UPDATE gabriel_identity.evidence_objects SET digest=repeat('0',64)",
    'DELETE FROM gabriel_identity.evidence_objects',
    'TRUNCATE gabriel_identity.evidence_objects CASCADE',
    "UPDATE gabriel_identity.custody_events SET event_hash=repeat('0',64)",
    'DELETE FROM gabriel_identity.custody_events','TRUNCATE gabriel_identity.custody_events',
    "UPDATE gabriel_identity.evidence_key_registry SET fingerprint=repeat('0',64)",
    'DELETE FROM gabriel_identity.evidence_key_registry'])
def test_runtime_cannot_erase_or_rewrite_integrity_records(tenant,query):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query)
        conn.rollback()


@pytest.mark.parametrize('options',[{'approved':False},{'approved':1},{'event_time':'2026-01-01'},
    {'redaction_state':'verified'},{'parent_id':'not-a-uuid'}])
def test_invalid_intake_denied_without_object(tenant,cases,case,options):
    with pytest.raises((InvalidIdentityInput,AccessDenied)):
        intake(tenant,cases,case,**options)
    assert cases.get_case(tenant.token,case['id'])['evidence']==[]
    assert not list(cases.store.root.iterdir())


def test_empty_case_and_quota_require_actual_evidence(tenant,cases,case):
    assert not cases.verify_case(tenant.token,case['id'])['complete']
    with pytest.raises(EvidenceError):
        cases.close_case(tenant.token,case['id'])
    for _ in range(64):
        intake(tenant,cases,case)
    with pytest.raises(AccessDenied,match='case_evidence_limit'):
        intake(tenant,cases,case)
    assert len(cases.get_case(tenant.token,case['id'])['evidence'])==64


def test_intake_path_confinement_and_bounds(tmp_path):
    root = tmp_path/'intake'
    root.mkdir()
    approved = root/'approved.txt'
    approved.write_text(CONTENT)
    assert approved_file(approved,root)==CONTENT
    outside = tmp_path/'secret'
    outside.write_text('generated credential fixture')
    link = root/'link'
    link.symlink_to(outside)
    for path in (outside,link,Path('relative.txt')):
        with pytest.raises(InvalidIdentityInput):
            approved_file(path,root)
    approved.write_bytes(b'x'*(MAX_BYTES+1))
    with pytest.raises(InvalidIdentityInput):
        approved_file(approved,root)


def test_real_cli_intake_verify_export_and_close(tenant,tmp_path):
    keydir = tmp_path/'evidence-keys'
    result = subprocess.run([sys.executable,'tooling/scripts/gabriel_evidence_keys.py',str(keydir)],capture_output=True,text=True,timeout=10)
    assert result.returncode==0 and not result.stderr
    keys = EvidenceKeys.from_file(keydir/'keyring.json')
    with pytest.raises(IdentityConfigurationError):
        ProviderKeyRing.from_file(keydir/'keyring.json')
    provider = tmp_path/'provider-keys'
    assert subprocess.run([sys.executable,'tooling/scripts/gabriel_provider_keys.py',str(provider)],capture_output=True,timeout=10).returncode==0
    with pytest.raises(IdentityConfigurationError):
        EvidenceKeys.from_file(provider/'keyring.json')
    original = (keydir/'keyring.json').read_bytes()
    assert subprocess.run([sys.executable,'tooling/scripts/gabriel_evidence_keys.py',str(keydir)],capture_output=True,timeout=10).returncode!=0
    assert (keydir/'keyring.json').read_bytes()==original
    root = tmp_path/'objects'
    root.mkdir(mode=0o700)
    intake_root = tmp_path/'intake'
    intake_root.mkdir()
    source = intake_root/'source.txt'
    source.write_text(CONTENT)
    token = tmp_path/'session'
    token.write_text(tenant.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(keydir/'keyring.json'),
        GABRIEL_EVIDENCE_ROOT=str(root),GABRIEL_CASE_INTAKE_ROOT=str(intake_root))
    def cli(*args):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.case_cli',*args,'--token-file',str(token)],
            env=env,capture_output=True,text=True,timeout=10)
        assert not result.stderr and CONTENT not in result.stdout and tenant.token not in result.stdout
        assert tenant.db.app not in result.stdout and original.decode() not in result.stdout
        return result.returncode,json.loads(result.stdout)
    code,created = cli('create','--title','CLI generated fixture')
    assert code==0
    case_id = created['result']['id']
    code,acquired = cli('acquire','--case-id',case_id,'--ingestion-id',str(uuid4()),
        '--content-file',str(source),'--source-label','CLI artifact','--approved-content')
    assert code==0
    evidence_id = acquired['result']['id']
    assert cli('get','--case-id',case_id)[0]==0
    code,reported = cli('report','--case-id',case_id)
    assert code==0 and reported['result']['snapshot']['case']['id']==case_id
    assert reported['result']['snapshot']['evidence'][0]['id']==evidence_id
    assert reported['result']['snapshot']['content_integrity']=='not_checked'
    code,projected=cli('graph','--case-id',case_id)
    assert code==0 and projected['result']['projection']['case_id']==case_id
    assert {node['kind'] for node in projected['result']['projection']['nodes']}=={'case','evidence'}
    assert projected['result']['projection']['assessment']=='not_performed'
    code,assessed=cli('specialist-run','--case-id',case_id,'--request-id',str(uuid4()))
    assert code==0 and assessed['result']['result']['attack_status']=='unknown'
    assert cli('specialist-get','--case-id',case_id,'--run-id',assessed['result']['id'])[1]['result']['result_digest']==assessed['result']['result_digest']
    assert len(cli('specialist-list','--case-id',case_id)[1]['result']['runs'])==1
    code,remembered=cli('memory-propose','--case-id',case_id,'--evidence-id',evidence_id,'--request-id',str(uuid4()),'--topic','generated.cli-memory')
    assert code==0 and remembered['result']['status']=='proposed'
    memory=remembered['result']
    assert cli('memory-review','--memory-id',memory['id'],'--decision','approved','--expected-digest',memory['source_digest'],'--acknowledged-source')[0]==0
    assert cli('memory-check','--case-id',case_id)[1]['result']['records'][0]['id']==memory['id']
    assert cli('memory-forget','--memory-id',memory['id'])[1]['result']['retrieval_removed']
    assert cli('memory-check','--case-id',case_id)[1]['result']['records']==[]
    assert cli('memory-reset','--epoch','0')[1]['result']['epoch']==1
    assert cli('custody','--evidence-id',evidence_id)[0]==0
    assert cli('verify','--case-id',case_id)[1]['result']['complete']
    assert cli('assign','--case-id',case_id,'--request-id',str(uuid4()),'--member-id',str(tenant.owner))[0]==0
    code,question=cli('question-add','--case-id',case_id,'--request-id',str(uuid4()),'--question','Generated CLI investigation question')
    assert code==0
    assert cli('question-answer','--case-id',case_id,'--question-id',question['result']['question_id'],
        '--evidence-id',evidence_id,'--answer','Generated CLI analyst interpretation')[0]==0
    code,workflow=cli('workflow-get','--case-id',case_id)
    assert code==0 and workflow['result']['assignment']['assigned_to']==str(tenant.owner)
    assert workflow['result']['questions'][0]['state']=='human_answer_supplied'
    output = tmp_path/'export.txt'
    assert cli('export','--evidence-id',evidence_id,'--output',str(output))[0]==0
    assert output.read_text()==CONTENT
    assert cli('close','--case-id',case_id)[0]==1
    assert cli('policy-set','--distinct-approver','no')[0]==0
    code,proposed = cli('propose-close','--case-id',case_id,'--request-id',str(uuid4()),'--rationale','Reviewed CLI closure')
    assert code==0
    action_id = proposed['result']['id']
    assert cli('action-submit','--approval-id',action_id)[0]==0
    assert cli('action-approve','--approval-id',action_id,'--expected-digest',proposed['result']['digest'])[0]==0
    assert cli('close','--case-id',case_id,'--approval-id',action_id)[0]==0
    assert cli('list')[0]==0 and cli('exports')[0]==0


def test_v4_upgrade_preserves_real_identity_task_and_receipt(tenant):
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'upgrade fixture',['evidence.hash'])
    grant = service.issue_service(tenant.token,'upgrade worker',task['id'],['evidence.hash'])
    request_id = uuid4()
    request = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'generated upgrade fixture'}}
    response = service.execute_service(grant.token,task['id'],request,request_id)
    with owner_connection(tenant.db) as conn:
        remove_v5(conn)
    migrate(tenant.db.owner)
    assert service.whoami(tenant.token).user_id==tenant.owner
    assert service.get_task(tenant.token,task['id'])['used_steps']==1
    assert service.execute_service(grant.token,task['id'],request,request_id)==response


def test_interrupted_v5_ddl_rolls_back_without_partial_schema(tenant,monkeypatch):
    original = Path.read_text
    with owner_connection(tenant.db) as conn:
        remove_v5(conn)
    def interrupted(path,*args,**kwargs):
        value = original(path,*args,**kwargs)
        return value+'\nSELECT 1/0;' if path.name=='schema_v5.sql' else value
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable):
                migrate(tenant.db.owner)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.cases') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.migrations').fetchone()['n']==4
        assert tenant.service.whoami(tenant.token).user_id==tenant.owner
    finally:
        migrate(tenant.db.owner)
