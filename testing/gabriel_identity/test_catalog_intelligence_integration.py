"""Exercise indicator lifecycle review through the role-bound tool entrypoint."""

import json
from uuid import uuid4

import pytest

from gabriel.identity import investigation_tools, specialist_agents
from gabriel.identity.service import AccessDenied
from testing.gabriel_identity.test_cases_integration import case, cases, evidence
from testing.gabriel_identity.test_catalog_intelligence import NAME, packet, record
from testing.gabriel_identity.test_identity_integration import database, tenant


pytestmark = pytest.mark.integration
ROLE = 'threat_intelligence'


def test_lifecycle_normal_entrypoint_and_model_projection_use_case_local_aliases(tenant, cases, case, evidence):
    value = packet(record(1, 'revoked'))
    value['case_id'] = str(case['id'])
    fact = value['facts'][0]
    fact.update(evidence_id=str(evidence['id']), evidence_digest=evidence['digest'])
    holder = cases.acquire(tenant.token, case['id'], uuid4(), json.dumps(value), 'Generated lifecycle facts', approved=True)

    report = investigation_tools.inspect(cases, tenant.token, case['id'], holder['id'], ROLE, NAME, uuid4())
    result = report['result']['result']
    projected = specialist_agents.project(value, ROLE, uuid4(), [report['result']])['packet']

    assert report['state'] == 'local_tool_report_ready_requires_review'
    assert result['track_status_counts'] == {'reported_revoked': 1}
    assert result['queue'][0]['refs'] == ['o1']
    assert projected['observations'][0]['entity'] == 'e1'
    encoded = json.dumps(projected)
    for raw in (fact['data']['feed_id'], fact['entity_id'], fact['evidence_id'], fact['evidence_digest']):
        assert raw not in encoded
    assert json.loads(cases.read_evidence(tenant.token, report['report_evidence_id']).reveal())['tool_result'] == report['result']


def test_lifecycle_denies_wrong_role_and_cross_case_source(tenant, cases, case, evidence):
    unrelated = cases.create_case(tenant.token, 'Generated unrelated lifecycle case')
    value = packet(record(1))
    value['case_id'] = str(unrelated['id'])
    value['facts'][0].update(evidence_id=str(evidence['id']), evidence_digest=evidence['digest'])
    holder = cases.acquire(tenant.token, unrelated['id'], uuid4(), json.dumps(value), 'Generated foreign-source facts', approved=True)

    with pytest.raises(AccessDenied, match='specialist_tool_not_admitted'):
        investigation_tools.inspect(cases, tenant.token, unrelated['id'], holder['id'], 'dfir_evidence', NAME, uuid4())
    with pytest.raises(AccessDenied, match='specialist_source_case_mismatch'):
        investigation_tools.inspect(cases, tenant.token, unrelated['id'], holder['id'], ROLE, NAME, uuid4())
