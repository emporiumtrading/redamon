"""Real tenant SQL and independently signed fixtures detect privileged custody rewriting."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
import secrets
import subprocess
import sys
from uuid import uuid4

import pytest

from gabriel.identity.checkpoint_service import CheckpointService
from gabriel.identity.checkpoints import canonical,fingerprint,new_keypair,read_document,seal,write_document
from gabriel.identity.cases import custody_hash
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,provision_organization
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,audit_permission,CONTENT
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_retention_integration import retention,aged,approved_purge,prepared

pytestmark = pytest.mark.integration


@pytest.fixture
def checkpoints(tenant,cases):
    return CheckpointService(tenant.db.app,cases.store)


def anchored(service,token,case_id):
    private,public = new_keypair()
    snapshot = service.capture_checkpoint(token,case_id)
    envelope = seal(snapshot,private)
    return envelope,public,fingerprint(canonical(envelope))


def test_checkpoint_allows_append_but_does_not_claim_content_or_new_evidence(tenant,checkpoints,case,evidence):
    bound = anchored(checkpoints,tenant.token,case['id'])
    checkpoints.read_evidence(tenant.token,evidence['id'])
    checkpoints.acquire(tenant.token,case['id'],uuid4(),'Generated later fixture','later fixture',approved=True)
    result = checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)
    assert result['custody_prefixes_match'] and result['anchored_evidence_count']==1
    assert result['content_integrity']=='not_checked' and result['source_authenticity']=='unverified'
    assert result['new_evidence']=='not_covered' and result['governance_history']=='not_covered'


def test_privileged_valid_tail_deletion_is_detected_even_when_local_chain_passes(tenant,checkpoints,case,evidence):
    checkpoints.read_evidence(tenant.token,evidence['id'])
    bound = anchored(checkpoints,tenant.token,case['id'])
    sequence = bound[0]['body']['snapshot']['evidence'][0]['sequence']
    with owner_connection(tenant.db) as conn:
        conn.execute('DELETE FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s AND sequence=%s',
            (tenant.org,evidence['id'],sequence))
    assert len(checkpoints.custody(tenant.token,evidence['id']))==sequence-1
    with pytest.raises(EvidenceError,match='checkpoint_custody_changed'):
        checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)


def test_privileged_valid_rehash_of_existing_history_is_detected(tenant,checkpoints,case,evidence):
    checkpoints.read_evidence(tenant.token,evidence['id'])
    bound = anchored(checkpoints,tenant.token,case['id'])
    with owner_connection(tenant.db) as conn:
        event = conn.execute('SELECT * FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s ORDER BY sequence DESC LIMIT 1',
            (tenant.org,evidence['id'])).fetchone()
        changed = event['created_at']+timedelta(microseconds=1)
        head = custody_hash(tenant.org,evidence['id'],event['sequence'],event['actor_id'],event['event'],event['previous_hash'],changed)
        conn.execute('UPDATE gabriel_identity.custody_events SET created_at=%s,event_hash=%s WHERE organization_id=%s AND evidence_id=%s AND sequence=%s',
            (changed,head,tenant.org,evidence['id'],event['sequence']))
    assert checkpoints.custody(tenant.token,evidence['id'])[-1]['event_hash']==head
    assert checkpoints.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    with pytest.raises(EvidenceError,match='checkpoint_custody_changed'):
        checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)


def test_removed_evidence_and_rewritten_metadata_are_detected(tenant,checkpoints,case,evidence):
    bound = anchored(checkpoints,tenant.token,case['id'])
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.evidence_objects SET source_label='Privileged rewrite' WHERE organization_id=%s AND id=%s",(tenant.org,evidence['id']))
    with pytest.raises(EvidenceError,match='checkpoint_context_changed'):
        checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)
    with owner_connection(tenant.db) as conn:
        conn.execute('DELETE FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s',(tenant.org,evidence['id']))
        conn.execute('DELETE FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND id=%s',(tenant.org,evidence['id']))
    with pytest.raises(EvidenceError,match='checkpoint_evidence_missing'):
        checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)


def test_rewritten_case_and_corrupt_chain_deny(tenant,checkpoints,case,evidence):
    bound = anchored(checkpoints,tenant.token,case['id'])
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.cases SET title='Privileged rewrite' WHERE organization_id=%s AND id=%s",(tenant.org,case['id']))
    with pytest.raises(EvidenceError,match='checkpoint_case_changed'):
        checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.custody_events SET event_hash=repeat('0',64) WHERE organization_id=%s AND evidence_id=%s AND sequence=2",(tenant.org,evidence['id']))
    with pytest.raises(EvidenceError,match='evidence_custody_invalid'):
        checkpoints.capture_checkpoint(tenant.token,case['id'])


def test_checkpoint_survives_approved_primary_purge_and_process_recreation(tenant,checkpoints,aged,prepared):
    bound = anchored(checkpoints,tenant.token,aged.case['id'])
    checkpoints.execute_purge(tenant.token,prepared['id'])
    fresh = CheckpointService(tenant.db.app,checkpoints.store)
    assert fresh.verify_checkpoint(tenant.token,aged.case['id'],*bound)['custody_prefixes_match']
    with pytest.raises(EvidenceError,match='evidence_purged'):
        fresh.read_evidence(tenant.token,aged.evidence['id'])


def test_other_case_and_tenant_cannot_reuse_checkpoint(tenant,checkpoints,case,evidence):
    bound = anchored(checkpoints,tenant.token,case['id'])
    other = checkpoints.create_case(tenant.token,'Other generated checkpoint case')
    with pytest.raises(AccessDenied,match='checkpoint_scope_mismatch'):
        checkpoints.verify_checkpoint(tenant.token,other['id'],*bound)
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Other generated tenant','owner',password)
    token = checkpoints.login(org,'owner',password).token
    foreign = checkpoints.create_case(token,'Other tenant case')
    with pytest.raises(AccessDenied):
        checkpoints.capture_checkpoint(token,case['id'])
    with pytest.raises(AccessDenied,match='checkpoint_scope_mismatch'):
        checkpoints.verify_checkpoint(token,foreign['id'],*bound)


@pytest.mark.parametrize('role',['viewer','analyst'])
def test_current_human_roles_and_revocation_apply(tenant,checkpoints,case,evidence,role):
    bound = anchored(checkpoints,tenant.token,case['id'])
    password = secrets.token_urlsafe(24)
    checkpoints.create_member(tenant.token,'checkpoint-reader',password,role)
    token = checkpoints.login(tenant.org,'checkpoint-reader',password).token
    assert checkpoints.verify_checkpoint(token,case['id'],*bound)['custody_prefixes_match']
    if role=='viewer':
        with pytest.raises(AccessDenied): checkpoints.capture_checkpoint(token,case['id'])
    else:
        assert checkpoints.capture_checkpoint(token,case['id'])['case_id']==str(case['id'])
    checkpoints.logout(token)
    with pytest.raises(AuthenticationDenied): checkpoints.verify_checkpoint(token,case['id'],*bound)


def test_worker_token_cannot_capture_or_verify(tenant,checkpoints,case,evidence):
    from gabriel.identity.machine import ServiceIdentityService
    service = ServiceIdentityService(tenant.db.app)
    task = service.create_task(tenant.token,'Checkpoint worker fixture',['evidence.hash'])
    worker = service.issue_service(tenant.token,'checkpoint worker',task['id'],['evidence.hash'])
    bound = anchored(checkpoints,tenant.token,case['id'])
    with pytest.raises(AuthenticationDenied): checkpoints.capture_checkpoint(worker.token,case['id'])
    with pytest.raises(AuthenticationDenied): checkpoints.verify_checkpoint(worker.token,case['id'],*bound)


def test_audit_unavailable_never_reports_checkpoint_success(tenant,checkpoints,case,evidence):
    bound = anchored(checkpoints,tenant.token,case['id'])
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): checkpoints.capture_checkpoint(tenant.token,case['id'])
        with pytest.raises(IdentityUnavailable): checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)
    finally:
        audit_permission(tenant,True)


def test_concurrent_access_and_capture_have_valid_prefixes(tenant,checkpoints,case,evidence):
    with ThreadPoolExecutor(max_workers=2) as pool:
        read = pool.submit(checkpoints.read_evidence,tenant.token,evidence['id'])
        bound = anchored(checkpoints,tenant.token,case['id'])
        assert read.result().reveal()==CONTENT.encode()
    assert checkpoints.verify_checkpoint(tenant.token,case['id'],*bound)['custody_prefixes_match']


def test_real_case_cli_capture_offline_seal_and_database_verification(tenant,checkpoints,case,evidence,tmp_path):
    import base64
    ring = checkpoints.store.keys
    keys = tmp_path/'evidence-keys.json'
    write_document(keys,{'schema_version':1,'purpose':'evidence-v1','generation':ring.generation,'active':ring.active,
        'keys':{k:base64.b64encode(v).decode() for k,v in ring._keys.items()}})
    token = tmp_path/'human-session'
    token.write_text(tenant.token)
    env = dict(os.environ,GABRIEL_EVIDENCE_KEYRING_FILE=str(keys),GABRIEL_EVIDENCE_ROOT=str(checkpoints.store.root))
    source,output,public_path = tmp_path/'snapshot.json',tmp_path/'checkpoint.json',tmp_path/'public.json'
    def cli(*args):
        run = subprocess.run([sys.executable,'-m','gabriel.identity.case_cli',*args,'--token-file',str(token)],
            env=env,text=True,capture_output=True,timeout=10)
        assert not run.stderr and CONTENT not in run.stdout and tenant.token not in run.stdout and tenant.db.app not in run.stdout
        return run.returncode,json.loads(run.stdout)
    code,result = cli('checkpoint-capture','--case-id',str(case['id']),'--output',str(source))
    assert code==0 and result['result']['sealed'] is False
    assert cli('checkpoint-capture','--case-id',str(case['id']),'--output',str(source))[0]==1
    private,public = new_keypair()
    envelope = seal(read_document(source),private)
    write_document(output,envelope)
    write_document(public_path,public)
    expected = fingerprint(canonical(envelope))
    args = ('checkpoint-verify','--case-id',str(case['id']),'--checkpoint-file',str(output),'--trusted-public-key',str(public_path))
    assert cli(*args,'--expected-digest',expected)[1]['result']['custody_prefixes_match']
    assert cli(*args,'--expected-digest','0'*64)[0]==1
