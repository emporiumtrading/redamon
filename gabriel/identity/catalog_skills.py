"""First five implemented candidate skills from the 240-skill expansion.

Pure, conservative summaries over the existing verified-entrypoint typed facts.
These kernels do not receive credentials, access live systems or authorize actions.
"""
from collections import Counter
from datetime import datetime

from gabriel.identity.specialist_analysis import validate_document

VERSION='gabriel-catalog-tranche-1-v1'
SKILLS={
    'prioritize_escalation_queue':'alert_triage',
    'review_incident_evidence_gaps':'incident_scoping',
    'review_privileged_access_changes':'identity_access',
    'analyze_response_dependencies':'response_remediation',
    'review_incident_closure_evidence':'recovery_learning',
}


def _at(s):
    return datetime.fromisoformat(s.replace('Z','+00:00'))


def evaluate(name, document):
    if name not in SKILLS:
        raise ValueError('unknown_catalog_skill')
    validate_document(document,document['case_id'])
    rows=document['facts']
    asof=_at(document['as_of'])
    result=dict(
        version=VERSION,skill=name,role=SKILLS[name],
        status='insufficient_role_evidence',
        supplied_fact_count=len(rows),
        source_count=len({f['evidence_id'] for f in rows}),
        source_authenticity='unverified',
        evidence_independence='unestablished',
        source_clocks_verified=False,
        confidence='unqualified',
        incident_status='unknown',
        external_actions_authorized=False,
        model_used=False,
        requires_analyst_review=True,
    )
    if name=='prioritize_escalation_queue':
        alerts=[f for f in rows if f['type']=='alert']
        urgent=[f for f in alerts if f['data']['severity'] in ('critical','high') and f['data']['state']!='resolved']
        result.update(
            status='review_required' if alerts else 'no_alert_facts',
            reported_alert_count=len(alerts),
            unresolved_critical_count=sum(f['data']['severity']=='critical' for f in urgent),
            unresolved_high_count=sum(f['data']['severity']=='high' for f in urgent),
            unresolved_older_than_hour_count=sum((asof-_at(f['event_time'])).total_seconds()>=3600 for f in urgent),
            unknown_state_count=sum(f['data']['state']=='unknown' for f in alerts),
            suggested_queue='critical_first' if any(f['data']['severity']=='critical' for f in urgent)
              else 'high_first' if urgent else 'analyst_review',
            severity_mutation_performed=False,
            automatic_escalation_performed=False,
            suppressed_alert_count=0,
        )
    elif name=='review_incident_evidence_gaps':
        admissible={'activity','alert','identity','cloud'}
        selected=[f for f in rows if f['type'] in admissible]
        result.update(
            status='review_required' if selected else 'no_scoping_facts',
            relevant_fact_count=len(selected),
            missing_entity_reference_count=sum(f['entity_id'] is None for f in selected),
            represented_evidence_source_count=len({f['evidence_id'] for f in selected}),
            supplied_entity_alias_count=len({f['entity_id'] for f in selected if f['entity_id'] is not None}),
            represented_fact_types=sorted({f['type'] for f in selected}),
            unrepresented_fact_types=sorted(admissible-{f['type'] for f in selected}),
            entity_aliases_independently_resolved=False,
            scope_complete=False,
        )
    elif name=='review_privileged_access_changes':
        selected=[f for f in rows if f['type']=='identity']
        changes=[f for f in selected if f['data']['event'] in ('privilege_grant','mfa_disabled')]
        result.update(
            status='review_required' if selected else 'no_identity_facts',
            identity_assertion_count=len(selected),
            reported_sensitive_changes=len(changes),
            reported_sensitive_unauthorized=sum(f['data']['authorized']=='no' for f in changes),
            reported_sensitive_unknown_authority=sum(f['data']['authorized']=='unknown' for f in changes),
            reported_sensitive_authorized=sum(f['data']['authorized']=='yes' for f in changes),
            sensitive_change_older_than_hour_count=sum((asof-_at(f['event_time'])).total_seconds()>=3600 for f in changes),
            directory_or_pam_state_verified=False,
            account_modification_performed=False,
        )
    elif name=='analyze_response_dependencies':
        selected=[f for f in rows if f['type']=='response_check']
        labels=('target_binding','dependencies','recovery')
        states={key:Counter(f['data']['passed'] for f in selected if f['data']['check']==key) for key in labels}
        result.update(
            status='review_required' if selected else 'no_response_facts',
            supplied_response_check_count=len(selected),
            not_reported_checks=[key for key in labels if not states[key]],
            failed_checks_by_type={key:states[key]['no'] for key in labels},
            unknown_checks_by_type={key:states[key]['unknown'] for key in labels},
            incomplete_check_count=sum(states[key]['no']+states[key]['unknown'] for key in labels),
            target_binding_verified=False,
            rollback_test_verified=False,
            execution_ready=False,
            execution_performed=False,
        )
    elif name=='review_incident_closure_evidence':
        selected=[f for f in rows if f['type']=='recovery']
        labels=('restore','service_health','security_control')
        states={key:Counter((f['data']['result'],f['data']['baseline']) for f in selected if f['data']['check']==key) for key in labels}
        result.update(
            status='review_required' if selected else 'no_recovery_facts',
            supplied_recovery_checks=len(selected),
            missing_required_check_types=[key for key in labels if not states[key]],
            supplied_failed_count=sum(f['data']['result']=='fail' for f in selected),
            supplied_unknown_count=sum(f['data']['result']=='unknown' for f in selected),
            stale_or_unknown_baseline_count=sum(f['data']['baseline']!='current' for f in selected),
            reported_current_pass_check_types=[key for key in labels if states[key][('pass','current')]>0],
            independently_validated_recovery=False,
            incident_closure_authorized=False,
            incident_closed=False,
            memory_published=False,
        )
    return result
