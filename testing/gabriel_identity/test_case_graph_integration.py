"""Actual case provenance rebuilds, isolation, audit and corruption boundaries."""
from hashlib import sha256
import json
import secrets
from uuid import uuid4

import pytest

from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceError,canonical
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,CONTENT,intake,audit_permission
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_observations_integration import browser,task,grant,payload,submit

pytestmark=pytest.mark.integration


def test_graph_rebuild_is_stable_scoped_and_excludes_bodies_and_secrets(tenant,cases,case,evidence):
    first=cases.case_graph(tenant.token,case['id'])
    second=CaseService(tenant.db.app,cases.store).case_graph(tenant.token,case['id'])
    assert first['projection']==second['projection'] and first['digest']==second['digest']
    assert first['digest']==sha256(canonical(first['projection'])).hexdigest()
    assert first['source_report_digest']!=second['source_report_digest']
    graph=first['projection']
    assert {node['kind'] for node in graph['nodes']}=={'case','evidence'}
    assert len(graph['edges'])==1 and graph['edges'][0]['kind']=='contains_evidence'
    scope='organization/'+str(tenant.org)+'/case/'+str(case['id'])+'/'
    assert all(node['id'].startswith(scope) for node in graph['nodes'])
    ids={node['id'] for node in graph['nodes']}
    assert all(edge['source'] in ids and edge['target'] in ids and not edge['source_verified'] for edge in graph['edges'])
    assert graph['assessment']=='not_performed' and graph['coverage']=='partial' and graph['content_integrity']=='not_checked'
    raw=json.dumps(first)
    assert all(secret not in raw for secret in (CONTENT,tenant.token,tenant.db.app,str(cases.store.root),cases.store.keys.active))
    assert 'object_id' not in raw and 'key_id' not in raw
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE organization_id=%s AND event='case.graph_generated'",(tenant.org,)).fetchone()['n']==2


def test_lineage_and_identical_bytes_preserve_separate_records(tenant,cases,case,evidence):
    child=cases.acquire(tenant.token,case['id'],uuid4(),CONTENT,'Generated child',approved=True,parent_id=evidence['id'])
    graph=cases.case_graph(tenant.token,case['id'])['projection']
    assert len([node for node in graph['nodes'] if node['kind']=='evidence'])==2
    group,=[node for node in graph['nodes'] if node['kind']=='identical_bytes']
    assert group['properties']['meaning']=='identical_bytes_not_independent_corroboration'
    parent_link,=[edge for edge in graph['edges'] if edge['kind']=='derived_from']
    assert parent_link['source'].endswith('/'+str(child['id'])) and parent_link['target'].endswith('/'+str(evidence['id']))
    assert len([edge for edge in graph['edges'] if edge['kind']=='has_identical_bytes'])==2


def test_actual_browser_lineage_and_task_links(tenant,browser,case,task,grant,payload):
    receipt=submit(tenant,browser,grant,payload)
    graph=browser.case_graph(tenant.token,case['id'])['projection']
    observation,=[node for node in graph['nodes'] if node['kind']=='browser_observation']
    assert observation['record_id']==str(receipt['observation_id'])
    assert observation['properties']['coverage']=='partial' and not observation['properties']['source_verified']
    assert {'has_browser_lease','received_observation','captured_as'}<={edge['kind'] for edge in graph['edges']}
    lease,=[node for node in graph['nodes'] if node['kind']=='browser_lease']
    assert lease['properties']['current_authority']=='not_assessed'
    assert {node['record_id'] for node in graph['nodes'] if node['kind']=='task'}=={str(task['id'])}
    assert len([edge for edge in graph['edges'] if edge['kind']=='linked_task'])==1
    service=ServiceIdentityService(tenant.db.app)
    task_id=service.create_task(tenant.token,'Generated graph task',['evidence.hash'])['id']
    browser.link_task(tenant.token,case['id'],task_id)
    result=browser.case_graph(tenant.token,case['id'])
    linked=result['projection']
    expected={str(task['id']),str(task_id)}
    task_nodes={node['id']:node['record_id'] for node in linked['nodes'] if node['kind']=='task'}
    assert set(task_nodes.values())==expected
    links=[edge for edge in linked['edges'] if edge['kind']=='linked_task']
    assert len(links)==len(expected) and {task_nodes[edge['target']] for edge in links}==expected
    assert all(edge['source'].endswith('/case/'+str(case['id'])) for edge in links)
    browser.link_task(tenant.token,case['id'],task_id)
    assert browser.case_graph(tenant.token,case['id'])['digest']==result['digest']


def test_empty_graph_and_case_change_rebuild(tenant,cases,case):
    before=cases.case_graph(tenant.token,case['id'])
    assert len(before['projection']['nodes'])==1 and not before['projection']['edges']
    intake(tenant,cases,case)
    after=cases.case_graph(tenant.token,case['id'])
    assert before['digest']!=after['digest'] and len(after['projection']['nodes'])==2


def test_foreign_tenant_and_machine_denied(tenant,cases,case,evidence):
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated graph outsider','owner',password)
    token=cases.login(org,'owner',password).token
    with pytest.raises(AccessDenied): cases.case_graph(token,case['id'])
    service=ServiceIdentityService(tenant.db.app)
    task=service.create_task(tenant.token,'Generated graph denied',['evidence.hash'])
    worker=service.issue_service(tenant.token,'Generated graph worker',task['id'],['evidence.hash'])
    with pytest.raises(AuthenticationDenied): cases.case_graph(worker.token,case['id'])


def test_viewer_metadata_then_revocation(tenant,cases,case,evidence):
    password=secrets.token_urlsafe(24)
    member=cases.create_member(tenant.token,'graph-viewer',password,'viewer')
    token=cases.login(tenant.org,'graph-viewer',password).token
    assert len(cases.case_graph(token,case['id'])['projection']['nodes'])==2
    cases.set_membership(tenant.token,member,'viewer',False)
    with pytest.raises(AuthenticationDenied): cases.case_graph(token,case['id'])


def test_audit_failure_and_corrupt_custody_never_return_graph(tenant,cases,case,evidence):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.case_graph(tenant.token,case['id'])
    finally: audit_permission(tenant,True)
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.custody_events SET event_hash=repeat('0',64) WHERE organization_id=%s AND evidence_id=%s AND sequence=2",(tenant.org,evidence['id']))
    with pytest.raises(EvidenceError,match='custody_invalid'): cases.case_graph(tenant.token,case['id'])


@pytest.mark.parametrize('limit',['MAX_NODES','MAX_EDGES'])
def test_projection_bounds_fail_instead_of_truncating(tenant,cases,case,evidence,monkeypatch,limit):
    monkeypatch.setattr('gabriel.identity.case_graph.'+limit,0)
    with pytest.raises(AccessDenied,match='case_graph_limit'): cases.case_graph(tenant.token,case['id'])
