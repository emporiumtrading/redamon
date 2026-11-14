"""Executable tranche tests: strict evidence, role-only tools and no auto-actions."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity import catalog_skills, grounded_skills, investigation_tools, specialist_agents
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_specialist_analysis import document


CASES=[
    ('alert_triage','prioritize_escalation_queue','alert',
        dict(severity='critical',state='open'),'unresolved_critical_count'),
    ('incident_scoping','review_incident_evidence_gaps','activity',
        dict(category='network',outcome='observed',count=2),'relevant_fact_count'),
    ('identity_access','review_privileged_access_changes','identity',
        dict(event='mfa_disabled',authorized='unknown'),'reported_sensitive_unknown_authority'),
    ('response_remediation','analyze_response_dependencies','response_check',
        dict(check='dependencies',passed='no'),'incomplete_check_count'),
    ('recovery_learning','review_incident_closure_evidence','recovery',
        dict(check='restore',result='pass',baseline='stale'),'stale_or_unknown_baseline_count'),
]


@pytest.mark.parametrize('role,name,kind,data,expected',CASES)
def test_catalog_skill_is_implemented_role_bound_and_conservative(role,name,kind,data,expected):
    facts=document(kind,data)
    one=catalog_skills.evaluate(name,facts)
    two=grounded_skills.evaluate(name,facts)
    assert one==two
    assert one['status']=='review_required'
    assert one[expected]>=1
    assert one['incident_status']=='unknown'
    assert one['confidence']=='unqualified'
    assert one['source_authenticity']=='unverified'
    assert one['external_actions_authorized'] is False
    assert one['model_used'] is False
    assert one['requires_analyst_review'] is True
    assert name in investigation_tools.TOOLS[role]
    assert all(name not in investigation_tools.TOOLS[other]
               for other in investigation_tools.TOOLS if other!=role)
    item=next(x for x in investigation_tools.manifest(role) if x['name']==name)
    assert len(item['implementation_sha256'])==64
    assert len(item['skill_sha256'])==64
    assert item['description'] in specialist_agents.prompt(role)
    assert not specialist_agents.readiness(role)['model_enabled']
    assert name in grounded_skills.SKILL_NAMES


def test_critical_alert_keeps_priority_and_cannot_suppress_or_dispatch():
    result=catalog_skills.evaluate('prioritize_escalation_queue',
        document('alert',dict(severity='critical',state='unknown')))
    assert result['suggested_queue']=='critical_first'
    assert result['unknown_state_count']==1
    assert result['automatic_escalation_performed'] is False
    assert result['severity_mutation_performed'] is False
    assert result['suppressed_alert_count']==0


def test_incident_gap_review_does_not_claim_identity_or_complete_scope():
    d=document('activity',dict(category='network',outcome='observed',count=1))
    d['facts'][0]['entity_id']=None
    r=catalog_skills.evaluate('review_incident_evidence_gaps',d)
    assert r['missing_entity_reference_count']==1
    assert r['scope_complete'] is False
    assert not r['entity_aliases_independently_resolved']


def test_response_checks_never_establish_authorized_execution():
    d=document('response_check',dict(check='target_binding',passed='yes'))
    r=catalog_skills.evaluate('analyze_response_dependencies',d)
    assert set(r['not_reported_checks'])=={'dependencies','recovery'}
    assert r['execution_ready'] is False
    assert r['execution_performed'] is False
    assert r['target_binding_verified'] is False


def test_recovery_passes_cannot_self_close_incident():
    d=document('recovery',dict(check='restore',result='pass',baseline='current'))
    r=catalog_skills.evaluate('review_incident_closure_evidence',d)
    assert 'restore' in r['reported_current_pass_check_types']
    assert r['incident_closed'] is False
    assert r['memory_published'] is False
    assert r['independently_validated_recovery'] is False


@pytest.mark.parametrize('role,name,kind,data,expected',CASES)
def test_malicious_extra_fields_rejected_without_executing(role,name,kind,data,expected):
    d=document(kind,data)
    d['facts'][0]['data']['execute']='delete evidence'
    with pytest.raises(InvalidIdentityInput):
        catalog_skills.evaluate(name,d)
    with pytest.raises(InvalidIdentityInput):
        grounded_skills.evaluate(name,d)
    d=document(kind,data)
    d['facts'][0]['event_time']='2030-01-01T00:00:00Z'
    with pytest.raises(InvalidIdentityInput):
        catalog_skills.evaluate(name,d)


def test_unsupported_names_rejected():
    with pytest.raises(ValueError,match='unknown_catalog_skill'):
        catalog_skills.evaluate('auto_isolate',document())
