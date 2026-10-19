"""Actual PostgreSQL append-only case ownership and evidence-linked analyst comments."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.cases import CaseService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,InvalidIdentityInput,migrate,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,intake,audit_permission
from testing.gabriel_identity.db_history import remove_v13

pytestmark=pytest.mark.integration


def member(tenant,cases,role='analyst'):
    password=secrets.token_urlsafe(24)
    user=cases.create_member(tenant.token,'workflow-'+uuid4().hex,password,role)
    with owner_connection(tenant.db) as conn:
        name=conn.execute('SELECT username FROM gabriel_identity.users WHERE id=%s',(user,)).fetchone()['username']
    return user,cases.login(tenant.org,name,password).token


def test_assignment_replay_history_and_live_assignee_state(tenant,cases,case):
    user,token=member(tenant,cases)
    request=uuid4()
    first=cases.assign_case(tenant.token,case['id'],request,user)
    assert cases.assign_case(tenant.token,case['id'],request,user)==first
    assert first['sequence']==1
    with pytest.raises(AccessDenied): cases.assign_case(tenant.token,case['id'],request,None)
    data=CaseService(tenant.db.app,cases.store).case_workflow(token,case['id'])
    assert data['assignment']['assignee_active'] and not data['assignment_grants_authority']
    cases.set_membership(tenant.token,user,'analyst',False)
    assert not cases.case_workflow(tenant.token,case['id'])['assignment']['assignee_active']
    cases.assign_case(tenant.token,case['id'],uuid4(),None)
    assert len(cases.case_workflow(tenant.token,case['id'])['assignment_history'])==2


def test_analyst_can_claim_unassigned_but_not_take_another_assignment(tenant,cases,case):
    user,token=member(tenant,cases)
    cases.assign_case(token,case['id'],uuid4(),user)
    with pytest.raises(AccessDenied): cases.assign_case(token,case['id'],uuid4(),tenant.owner)
    cases.assign_case(tenant.token,case['id'],uuid4(),tenant.owner)
    with pytest.raises(AccessDenied): cases.assign_case(token,case['id'],uuid4(),user)
    with pytest.raises(AccessDenied): cases.assign_case(token,case['id'],uuid4(),None)


def test_concurrent_question_replay_and_answer_preserve_one_record(tenant,cases,case,evidence):
    request=uuid4()
    with ThreadPoolExecutor(max_workers=3) as pool:
        ids=list(pool.map(lambda _:cases.add_question(tenant.token,case['id'],request,'Generated investigation question'),range(3)))
    assert len(set(ids))==1
    question=ids[0]
    with pytest.raises(AccessDenied): cases.add_question(tenant.token,case['id'],request,'Changed question')
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda _:cases.answer_question(tenant.token,case['id'],question,evidence['id'],'Generated analyst explanation'),range(3)))
    assert all(row['state']=='human_answer_supplied' and not row['source_verified'] for row in results)
    with pytest.raises(AccessDenied): cases.answer_question(tenant.token,case['id'],question,evidence['id'],'Changed answer')
    row=cases.case_workflow(tenant.token,case['id'])['questions'][0]
    assert row['answer']=='Generated analyst explanation' and row['evidence_id']==str(evidence['id'])
    assert cases.case_workflow(tenant.token,case['id'])['knowledge_status']=='analyst_comments_not_validated_memory'


def test_wrong_case_evidence_and_corrupted_content_cannot_support_answer(tenant,cases,case,evidence):
    question=cases.add_question(tenant.token,case['id'],uuid4(),'Generated question')
    other=cases.create_case(tenant.token,'Other generated workflow case')
    artifact=intake(tenant,cases,other)
    with pytest.raises(AccessDenied): cases.answer_question(tenant.token,case['id'],question,artifact['id'],'Unsupported')
    with owner_connection(tenant.db) as conn:
        row=conn.execute('SELECT object_id FROM gabriel_identity.evidence_objects WHERE id=%s',(evidence['id'],)).fetchone()
    (cases.store.root/(row['object_id'].hex+'.gbe')).unlink()
    from gabriel.identity.evidence_store import EvidenceError
    with pytest.raises(EvidenceError): cases.answer_question(tenant.token,case['id'],question,evidence['id'],'Missing evidence')
    assert cases.case_workflow(tenant.token,case['id'])['questions'][0]['state']=='open'


def test_viewer_cannot_mutate_or_read_comments_and_foreign_assignee_denied(tenant,cases,case):
    user,viewer=member(tenant,cases,'viewer')
    question=cases.add_question(tenant.token,case['id'],uuid4(),'Generated restricted analyst note')
    for call in (lambda:cases.assign_case(viewer,case['id'],uuid4(),user),lambda:cases.add_question(viewer,case['id'],uuid4(),'Denied')):
        with pytest.raises(AccessDenied): call()
    data=cases.case_workflow(viewer,case['id'])
    assert data['questions']==[] and data['questions_restricted']
    assert question not in repr(data)
    password=secrets.token_urlsafe(24)
    org,foreign_user=provision_organization(tenant.db.owner,'Generated workflow foreign','owner',password)
    foreign=cases.login(org,'owner',password).token
    with pytest.raises(AccessDenied): cases.assign_case(tenant.token,case['id'],uuid4(),foreign_user)
    with pytest.raises(AccessDenied): cases.case_workflow(foreign,case['id'])


@pytest.mark.parametrize('operation',['assignment','question','answer'])
def test_audit_failure_rolls_back_workflow(tenant,cases,case,evidence,operation):
    question=cases.add_question(tenant.token,case['id'],uuid4(),'Existing generated question')
    before=cases.case_workflow(tenant.token,case['id'])
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable):
            if operation=='assignment': cases.assign_case(tenant.token,case['id'],uuid4(),tenant.owner)
            elif operation=='question': cases.add_question(tenant.token,case['id'],uuid4(),'Blocked generated question')
            else: cases.answer_question(tenant.token,case['id'],question,evidence['id'],'Blocked answer')
    finally: audit_permission(tenant,True)
    assert cases.case_workflow(tenant.token,case['id'])==before


@pytest.mark.parametrize('table',['case_assignments','case_questions','case_question_answers'])
def test_runtime_cannot_rewrite_workflow_history(tenant,table):
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute('DELETE FROM gabriel_identity.'+table)


def test_v12_upgrade_and_interrupted_upgrade_preserve_cases(tenant,cases,case,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v13(conn)
    original=Path.read_text
    def broken(path,*args,**kwargs):
        raw=original(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v13.sql' else raw
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_text',broken)
        with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT to_regclass('gabriel_identity.case_assignments') AS t").fetchone()['t'] is None
        assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==12
    migrate(tenant.db.owner)
    assert cases.get_case(tenant.token,case['id'])['case']['title']==case['title']
    cases.assign_case(tenant.token,case['id'],uuid4(),tenant.owner)
    assert cases.case_workflow(tenant.token,case['id'])['assignment']['assigned_to']==str(tenant.owner)


def test_closed_case_retains_comments_but_denies_workflow_changes(tenant,cases,case,evidence):
    from gabriel.identity.actions import ActionService
    cases.assign_case(tenant.token,case['id'],uuid4(),tenant.owner)
    question=cases.add_question(tenant.token,case['id'],uuid4(),'Generated unresolved question')
    actions=ActionService(tenant.db.app,cases.store)
    actions.set_policy(tenant.token,distinct_approver=False)
    action=actions.propose_close(tenant.token,case['id'],uuid4(),'Generated reviewed local closure')
    actions.submit(tenant.token,action['id'])
    actions.approve(tenant.token,action['id'],action['digest'])
    cases.close_case(tenant.token,case['id'],approval_id=action['id'])
    assert cases.case_workflow(tenant.token,case['id'])['questions'][0]['state']=='open'
    for call in (lambda:cases.assign_case(tenant.token,case['id'],uuid4(),None),
            lambda:cases.add_question(tenant.token,case['id'],uuid4(),'Denied'),
            lambda:cases.answer_question(tenant.token,case['id'],question,evidence['id'],'Denied')):
        with pytest.raises(AccessDenied,match='case_not_open'): call()
