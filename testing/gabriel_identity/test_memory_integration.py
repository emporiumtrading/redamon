"""Real encrypted evidence and database review/correction/expiry/reset boundaries."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import secrets
import time
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.retention import RetentionService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,migrate,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,CONTENT,intake
from testing.gabriel_identity.db_history import remove_v15

pytestmark=pytest.mark.integration


def propose(tenant,cases,case,evidence,**options):
    return cases.propose_memory(tenant.token,case['id'],evidence['id'],options.pop('request_id',uuid4()),
        options.pop('kind','fact'),options.pop('scope','case'),options.pop('topic','generated.baseline'),**options)


def approve(tenant,cases,record,token=None):
    return cases.review_memory(token or tenant.token,record['id'],'approved',record['source_digest'],True)


def test_proposal_is_not_retrieved_until_explicit_review_and_content_stays_encrypted(tenant,cases,case,evidence):
    request=uuid4()
    record=propose(tenant,cases,case,evidence,request_id=request)
    assert record['status']=='proposed' and not record['grants_authority'] and not record['source_verified']
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert propose(tenant,cases,case,evidence,request_id=request)['id']==record['id']
    with pytest.raises(InvalidIdentityInput): cases.review_memory(tenant.token,record['id'],'approved',record['source_digest'])
    with pytest.raises(AccessDenied): cases.review_memory(tenant.token,record['id'],'approved','0'*64,True)
    approved=approve(tenant,cases,record)
    assert approved['self_review'] and approved['status']=='eligible_pending_content_check'
    value,=cases.retrieve_memory(tenant.token,case['id'])
    assert value.reveal()==CONTENT.encode() and CONTENT not in repr(value)
    assert value.metadata['status']=='analyst_validated_reference' and not value.metadata['grants_authority']
    assert value.metadata['content_integrity']=='verified_on_this_read' and not value.metadata['source_verified']
    with owner_connection(tenant.db) as conn:
        raw=conn.execute('SELECT row_to_json(m)::text AS raw FROM gabriel_identity.memory_records m WHERE id=%s',(record['id'],)).fetchone()['raw']
    assert CONTENT not in raw and tenant.token not in raw
    assert CONTENT not in json.dumps(cases.list_memory(tenant.token,case['id']))


def test_concurrent_proposal_replay_converges_and_payload_conflicts_deny(tenant,cases,case,evidence):
    request=uuid4()
    with ThreadPoolExecutor(max_workers=3) as pool:
        values=list(pool.map(lambda _:propose(tenant,cases,case,evidence,request_id=request),range(3)))
    assert len({row['id'] for row in values})==1
    with pytest.raises(AccessDenied,match='memory_request_conflict'): propose(tenant,cases,case,evidence,request_id=request,kind='preference')
    with pytest.raises(AccessDenied,match='memory_topic_requires_correction'): propose(tenant,cases,case,evidence)


def test_correction_suspends_previous_reference_until_new_review(tenant,cases,case,evidence):
    first=propose(tenant,cases,case,evidence)
    approve(tenant,cases,first)
    revised=cases.acquire(tenant.token,case['id'],uuid4(),'Generated corrected baseline text','Generated correction',approved=True)
    second=propose(tenant,cases,case,revised,supersedes=first['id'])
    assert not cases.retrieve_memory(tenant.token,case['id'])
    states={row['id']:row['status'] for row in cases.list_memory(tenant.token,case['id'])['records']}
    assert states[first['id']]=='superseded' and states[second['id']]=='proposed'
    with pytest.raises(AccessDenied): propose(tenant,cases,case,revised,supersedes=first['id'])
    approve(tenant,cases,second)
    assert [row.reveal() for row in cases.retrieve_memory(tenant.token,case['id'])]==[b'Generated corrected baseline text']


def test_expired_reference_never_reaches_retrieval(tenant,cases,case,evidence):
    record=propose(tenant,cases,case,evidence,ttl_seconds=60)
    approve(tenant,cases,record)
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.memory_records SET created_at=created_at-interval '1 hour',expires_at=expires_at-interval '1 hour' WHERE id=%s",(record['id'],))
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert cases.list_memory(tenant.token,case['id'])['records'][0]['status']=='expired'


def test_reference_expiring_during_actual_content_read_is_not_returned(tenant,cases,case,evidence,monkeypatch):
    import gabriel.identity.memory as module
    record=propose(tenant,cases,case,evidence)
    approve(tenant,cases,record)
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.memory_records SET created_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()+interval '3 seconds' WHERE id=%s",(record['id'],))
    original=module._read_source
    reads=[]
    def delayed(*args,**kwargs):
        value=original(*args,**kwargs)
        reads.append(True)
        time.sleep(3.1)
        return value
    monkeypatch.setattr(module,'_read_source',delayed)
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert reads==[True]


def test_organization_reference_scope_and_viewer_content_denial(tenant,cases,case,evidence):
    other=cases.create_case(tenant.token,'Generated memory second case')
    record=propose(tenant,cases,case,evidence,scope='organization')
    approve(tenant,cases,record)
    assert cases.retrieve_memory(tenant.token,other['id'])[0].metadata['id']==record['id']
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'memory-analyst',password,'analyst')
    analyst=cases.login(tenant.org,'memory-analyst',password).token
    with pytest.raises(AccessDenied): cases.propose_memory(analyst,case['id'],evidence['id'],uuid4(),'fact','organization','denied.topic')
    with pytest.raises(AccessDenied): cases.review_memory(analyst,record['id'],'approved',record['source_digest'],True)
    with pytest.raises(AccessDenied): cases.reset_memory(analyst,0)
    cases.create_member(tenant.token,'memory-viewer',password,'viewer')
    viewer=cases.login(tenant.org,'memory-viewer',password).token
    assert cases.list_memory(viewer,other['id'])['records'][0]['id']==record['id']
    with pytest.raises(AccessDenied): cases.retrieve_memory(viewer,other['id'])
    with pytest.raises(AccessDenied): cases.forget_memory(viewer,record['id'])


def test_case_references_and_foreign_tenants_do_not_leak(tenant,cases,case,evidence):
    record=propose(tenant,cases,case,evidence)
    approve(tenant,cases,record)
    other=cases.create_case(tenant.token,'Generated memory unrelated case')
    assert cases.list_memory(tenant.token,other['id'])['records']==[]
    assert not cases.retrieve_memory(tenant.token,other['id'])
    with pytest.raises(AccessDenied): cases.propose_memory(tenant.token,other['id'],evidence['id'],uuid4(),'fact','case','wrong.source')
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated memory foreign','owner',password)
    token=cases.login(org,'owner',password).token
    for operation in (lambda:cases.list_memory(token,case['id']),lambda:cases.retrieve_memory(token,case['id']),
            lambda:cases.review_memory(token,record['id'],'approved',record['source_digest'],True),lambda:cases.forget_memory(token,record['id'])):
        with pytest.raises(AccessDenied): operation()


def test_reviewer_revocation_excludes_previously_approved_reference(tenant,cases,case,evidence):
    record=propose(tenant,cases,case,evidence)
    password=secrets.token_urlsafe(24)
    reviewer=cases.create_member(tenant.token,'memory-reviewer',password,'analyst')
    token=cases.login(tenant.org,'memory-reviewer',password).token
    approve(tenant,cases,record,token)
    assert cases.retrieve_memory(tenant.token,case['id'])
    cases.set_membership(tenant.token,reviewer,'analyst',False)
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert cases.list_memory(tenant.token,case['id'])['records'][0]['status']=='authority_unavailable'
    with pytest.raises(AuthenticationDenied): cases.retrieve_memory(token,case['id'])


def test_forget_discloses_legal_hold_and_keeps_source_under_existing_policy(tenant,cases,case,evidence):
    record=propose(tenant,cases,case,evidence)
    approve(tenant,cases,record)
    retention=RetentionService(tenant.db.app,cases.store)
    retention.place_hold(tenant.token,case['id'],'Generated retained memory source hold')
    forgotten=cases.forget_memory(tenant.token,record['id'])
    assert forgotten['retrieval_removed'] and not forgotten['source_erased'] and forgotten['legal_hold_present']
    assert cases.forget_memory(tenant.token,record['id'])==forgotten
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert cases.read_evidence(tenant.token,evidence['id']).reveal()==CONTENT.encode()
    assert cases.list_memory(tenant.token,case['id'])['records'][0]['status']=='forgotten'


def test_reset_uses_epoch_cas_and_excludes_all_old_references(tenant,cases,case,evidence):
    record=propose(tenant,cases,case,evidence)
    approve(tenant,cases,record)
    value=cases.reset_memory(tenant.token,0)
    assert value['epoch']==1 and not value['source_erased'] and not value['derived_index_present']
    assert not cases.retrieve_memory(tenant.token,case['id'])
    assert cases.list_memory(tenant.token,case['id'])['records'][0]['status']=='reset'
    with pytest.raises(AccessDenied): cases.reset_memory(tenant.token,0)
    new=propose(tenant,cases,case,evidence)
    assert new['epoch']==1
    approve(tenant,cases,new)
    assert [row.metadata['id'] for row in cases.retrieve_memory(tenant.token,case['id'])]==[new['id']]


def test_corrupt_source_is_not_retrieved_and_can_be_rejected(tenant,cases,case,evidence):
    record=propose(tenant,cases,case,evidence)
    approve(tenant,cases,record)
    with owner_connection(tenant.db) as conn:
        object_id=conn.execute('SELECT object_id FROM gabriel_identity.evidence_objects WHERE id=%s',(evidence['id'],)).fetchone()['object_id']
    (cases.store.root/(object_id.hex+'.gbe')).unlink()
    with pytest.raises(EvidenceError): cases.retrieve_memory(tenant.token,case['id'])
    cases.forget_memory(tenant.token,record['id'],'source_invalid')
    assert not cases.retrieve_memory(tenant.token,case['id'])


@pytest.mark.parametrize('event',['memory.proposed','memory.reviewed','memory.forgotten','memory.reset'])
def test_transactional_audit_failure_rolls_back_memory_change(tenant,cases,case,evidence,monkeypatch,event):
    import gabriel.identity.memory as module
    record=propose(tenant,cases,case,evidence) if event!='memory.proposed' else None
    original=module._audit
    def fail(conn,name,*args,**kwargs):
        if name==event: raise IdentityUnavailable('injected_memory_audit_failure')
        return original(conn,name,*args,**kwargs)
    monkeypatch.setattr(module,'_audit',fail)
    operation={'memory.proposed':lambda:propose(tenant,cases,case,evidence),'memory.reviewed':lambda:approve(tenant,cases,record),
        'memory.forgotten':lambda:cases.forget_memory(tenant.token,record['id']),'memory.reset':lambda:cases.reset_memory(tenant.token,0)}[event]
    with pytest.raises(IdentityUnavailable): operation()
    values=cases.list_memory(tenant.token,case['id'])
    assert values['current_epoch']==0
    if record: assert values['records'][0]['status']=='proposed'
    else: assert values['records']==[]


@pytest.mark.parametrize('table',['memory_records','memory_reviews','memory_invalidations','memory_resets'])
@pytest.mark.parametrize('operation',['UPDATE','DELETE'])
def test_runtime_has_no_history_edit_or_delete_grant(tenant,cases,case,evidence,table,operation):
    record=propose(tenant,cases,case,evidence)
    approve(tenant,cases,record)
    cases.forget_memory(tenant.token,record['id'])
    cases.reset_memory(tenant.token,0)
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            if operation=='DELETE': conn.execute('DELETE FROM gabriel_identity.'+table+' WHERE organization_id=%s',(tenant.org,))
            else: conn.execute('UPDATE gabriel_identity.'+table+' SET organization_id=organization_id WHERE organization_id=%s',(tenant.org,))


@pytest.mark.parametrize('ttl',[True,0,-1,2592001])
def test_ttl_bounds_are_real_admission_rules(tenant,cases,case,evidence,ttl):
    with pytest.raises(InvalidIdentityInput): propose(tenant,cases,case,evidence,ttl_seconds=ttl)


def test_v14_upgrade_and_interrupted_ddl_preserve_prior_case(tenant,cases,case,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v15(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        text=original(path,*args,**kwargs)
        return text+'\nSELECT 1/0;' if path.name=='schema_v15.sql' else text
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_text',broken)
        with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT to_regclass('gabriel_identity.memory_records') AS t").fetchone()['t'] is None
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==14
    migrate(tenant.db.owner)
    assert cases.get_case(tenant.token,case['id'])['case']['title']==case['title']
