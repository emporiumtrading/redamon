"""PostgreSQL/custody exercise for role-bound grounded skills using generated facts."""
import json
from uuid import uuid4

import pytest

from gabriel.identity import investigation_tools as tools
from gabriel.identity.service import AccessDenied
from testing.gabriel_identity.test_identity_integration import tenant
from testing.gabriel_identity.test_browser_monitoring_integration import database
from testing.gabriel_identity.test_cases_integration import cases, case, evidence
from testing.gabriel_identity.test_specialist_analysis_integration import intake

pytestmark = pytest.mark.integration


@pytest.mark.parametrize('role,name,kind,data,expected', [
    ('dfir_evidence', 'audit_provenance', 'artifact',
        dict(integrity='mismatch', custody='gap'), 'reported_custody_gap_count'),
    ('alert_triage', 'find_duplicate_facts', 'alert',
        dict(severity='high', state='open'), 'repeated_fact_candidate_count'),
    ('incident_scoping', 'cross_check_timeline', 'activity',
        dict(category='network', outcome='observed', count=1), 'reported_event_span_seconds'),
    ('telemetry_health', 'assess_visibility_gaps', 'coverage',
        dict(state='missing'), 'reported_missing_count'),
    ('detection_engineering', 'review_detection_regression', 'detection',
        dict(cohort='malicious', matched=False, expected_match=True), 'expected_matches_missed'),
])
def test_grounded_skill_stays_in_authorized_case_and_encrypted_report(
        tenant, cases, case, evidence, role, name, kind, data, expected):
    doc, holder = intake(tenant, cases, case, evidence, kind, data)
    report = tools.inspect(cases, tenant.token, case['id'], holder['id'], role, name, uuid4())
    assert report['state'] == 'local_tool_report_ready_requires_review'
    assert report['model_used'] is False
    assert report['result']['tool'] == name
    result = report['result']['result']
    assert expected in result
    assert result['source_authenticity'] == 'unverified'
    assert result['external_actions_authorized'] is False
    assert result['attack_status'] == 'unknown'
    encoded = json.dumps(report['result'])
    assert doc['facts'][0]['id'] not in encoded
    assert doc['facts'][0]['entity_id'] not in encoded
    assert doc['facts'][0]['evidence_id'] not in encoded
    stored = json.loads(cases.read_evidence(tenant.token, report['report_evidence_id']).reveal())
    assert stored['tool_result'] == report['result']
    assert stored['requires_review'] is True


def test_cross_case_or_disallowed_role_tool_never_produces_a_report(tenant, cases, case, evidence):
    _, holder = intake(tenant, cases, case, evidence, 'coverage', dict(state='stale'))
    with pytest.raises(AccessDenied, match='not_admitted'):
        tools.inspect(cases, tenant.token, case['id'], holder['id'],
                      'response_remediation', 'assess_visibility_gaps', uuid4())
    other = cases.create_case(tenant.token, 'Generated unrelated case')
    with pytest.raises(AccessDenied):
        tools.inspect(cases, tenant.token, other['id'], holder['id'],
                      'telemetry_health', 'assess_visibility_gaps', uuid4())
