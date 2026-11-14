"""Verify the DFIR catalog skill through the admitted case-tool entrypoint."""

import json
from uuid import uuid4

import pytest

from gabriel.identity import investigation_tools
from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied
from testing.gabriel_identity.test_cases_integration import case, cases, evidence, row_and_file
from testing.gabriel_identity.test_identity_integration import database, tenant
from testing.gabriel_identity.test_specialist_analysis_integration import intake


pytestmark = pytest.mark.integration
NAME = 'validate_evidence_provenance'
ROLE = 'dfir_evidence'


def test_admitted_dfir_tool_verifies_local_provenance_and_persists_report(tenant, cases, case, evidence):
    packet, holder = intake(tenant, cases, case, evidence, 'artifact', dict(integrity='mismatch', custody='gap'))

    report = investigation_tools.inspect(cases, tenant.token, case['id'], holder['id'], ROLE, NAME, uuid4())
    result = report['result']['result']

    assert report['state'] == 'local_tool_report_ready_requires_review'
    assert result['local_provenance_verified_count'] == 1
    assert result['reported_discrepancy_source_count'] == 1
    assert result['source_details'][0]['references'] == ['o1']
    assert result['source_authenticity'] == 'unverified'
    assert result['external_actions_authorized'] is False
    assert packet['facts'][0]['evidence_id'] not in json.dumps(result)
    stored = json.loads(cases.read_evidence(tenant.token, report['report_evidence_id']).reveal())
    assert stored['tool_result'] == report['result']


def test_wrong_role_and_case_are_denied_before_provenance_review(tenant, cases, case, evidence):
    _, holder = intake(tenant, cases, case, evidence, 'artifact', dict(integrity='match', custody='complete'))
    unrelated = cases.create_case(tenant.token, 'Generated unrelated case')

    with pytest.raises(AccessDenied, match='specialist_tool_not_admitted'):
        investigation_tools.inspect(cases, tenant.token, case['id'], holder['id'], 'alert_triage', NAME, uuid4())
    with pytest.raises(AccessDenied, match='specialist_source_case_mismatch'):
        investigation_tools.inspect(cases, tenant.token, unrelated['id'], holder['id'], ROLE, NAME, uuid4())


def test_corrupt_local_artifact_does_not_produce_provenance_report(tenant, cases, case, evidence):
    _, holder = intake(tenant, cases, case, evidence, 'artifact', dict(integrity='match', custody='complete'))
    _, path = row_and_file(tenant, cases, evidence)
    path.chmod(0o600)
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))

    with pytest.raises(EvidenceError):
        investigation_tools.inspect(cases, tenant.token, case['id'], holder['id'], ROLE, NAME, uuid4())
    assert len(cases.get_case(tenant.token, case['id'])['evidence']) == 2
