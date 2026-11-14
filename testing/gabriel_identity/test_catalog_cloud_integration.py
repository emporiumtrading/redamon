"""Exercise the authorized local cloud storage posture tool and report."""

import json
from uuid import uuid4

import pytest

from gabriel.identity import investigation_tools, specialist_agents
from gabriel.identity.service import AccessDenied
from testing.gabriel_identity.test_cases_integration import case, cases, evidence
from testing.gabriel_identity.test_catalog_cloud import NAME, packet, report
from testing.gabriel_identity.test_identity_integration import database, tenant


pytestmark = pytest.mark.integration
ROLE = 'cloud_supply_chain'


def test_normal_entrypoint_assesses_path_without_exposing_identifiers(tenant, cases, case, evidence):
    fact = report(path='delegated_link', audience='bearer_link', write='allow')
    fact.update(evidence_id=str(evidence['id']), evidence_digest=evidence['digest'])
    value = dict(packet(fact), case_id=str(case['id']))
    holder = cases.acquire(tenant.token, case['id'], uuid4(), json.dumps(value), 'Generated storage posture facts', approved=True)

    outcome = investigation_tools.inspect(cases, tenant.token, case['id'], holder['id'], ROLE, NAME, uuid4())
    result = outcome['result']['result']
    projected = specialist_agents.project(value, ROLE, uuid4(), [outcome['result']])['packet']

    assert outcome['state'] == 'local_tool_report_ready_requires_review'
    assert result['path_status_counts'] == {'reported_write_exposure': 1}
    assert result['access_paths'][0]['refs'] == ['o1']
    assert projected['observations'][0]['entity'] == 'e1'
    encoded = json.dumps(projected)
    for raw in (fact['data']['path_id'], fact['data']['policy_digest'], fact['entity_id'], fact['evidence_id']):
        assert raw not in encoded
    persisted = json.loads(cases.read_evidence(tenant.token, outcome['report_evidence_id']).reveal())
    assert persisted['tool_result'] == outcome['result']


def test_cross_case_storage_source_and_wrong_role_are_denied(tenant, cases, case, evidence):
    unrelated = cases.create_case(tenant.token, 'Generated unrelated case')
    fact = report()
    fact.update(evidence_id=str(evidence['id']), evidence_digest=evidence['digest'])
    value = dict(packet(fact), case_id=str(unrelated['id']))
    holder = cases.acquire(tenant.token, unrelated['id'], uuid4(), json.dumps(value), 'Generated foreign-source facts', approved=True)

    with pytest.raises(AccessDenied, match='specialist_tool_not_admitted'):
        investigation_tools.inspect(cases, tenant.token, unrelated['id'], holder['id'], 'dfir_evidence', NAME, uuid4())
    with pytest.raises(AccessDenied, match='specialist_source_case_mismatch'):
        investigation_tools.inspect(cases, tenant.token, unrelated['id'], holder['id'], ROLE, NAME, uuid4())
