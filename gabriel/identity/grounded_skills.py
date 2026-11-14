"""Bounded knowledge-grounded reviews of verified specialist-facts-v1 packets.

Pure analysis only. Caller verifies human/case authority and source custody/bytes
before entry, then rechecks both before publishing a result.
"""
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations

from gabriel.identity.evidence_store import canonical
from gabriel.identity.specialist_analysis import validate_document
from gabriel.identity.catalog_skills import SKILLS as CATALOG_SKILLS, evaluate as catalog_evaluate

VERSION = 'gabriel-grounded-skills-v1'
SKILL_NAMES = frozenset({
    'audit_provenance',
    'find_duplicate_facts',
    'cross_check_timeline',
    'assess_visibility_gaps',
    'review_detection_regression',
    'review_indicator_freshness',
    'summarize_hunt_hypotheses',
    'review_exposure_context',
    'review_cloud_change_assertions',
    'review_response_dependencies',
    'review_recovery_baselines',
    *CATALOG_SKILLS,
})


def _instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _base(facts):
    return dict(
        source_count=len({f['evidence_id'] for f in facts}),
        fact_count=len(facts),
        source_integrity_contract='verified_by_entrypoint_not_by_pure_kernel',
        source_authenticity='unverified',
        asserted_semantics='unverified',
        source_independence='unestablished',
        attack_status='unknown',
        external_actions_authorized=False,
        model_used=False,
        scope='current_case_supplied_facts_only',
        implementation_version=VERSION,
    )


def evaluate(name, document, *, verified_refs=None):
    """Return de-identified counters and explicit limits, never raw evidence/IDs."""
    if name not in SKILL_NAMES:
        raise ValueError('unknown_grounded_skill')
    if name in CATALOG_SKILLS:
        return catalog_evaluate(name, document, verified_refs=verified_refs)
    validate_document(document, document['case_id'])
    facts = document['facts']
    result = _base(facts)

    if name == 'audit_provenance':
        artifacts = [f for f in facts if f['type'] == 'artifact']
        grouped = Counter(f['evidence_id'] for f in facts)
        result.update(
            status='analyzed' if artifacts else 'insufficient_artifact_facts',
            artifact_assertion_count=len(artifacts),
            reported_integrity_mismatch_count=sum(f['data']['integrity'] == 'mismatch' for f in artifacts),
            reported_custody_gap_count=sum(f['data']['custody'] == 'gap' for f in artifacts),
            sources_with_multiple_fact_assertions=sum(n > 1 for n in grouped.values()),
            evidence_integrity='stored_source_bytes_checked_not_source_attested',
            custody_history='current_verified_input_only_not_external_collection_authenticity',
        )
    elif name == 'find_duplicate_facts':
        # Fact UUIDs are different for repeated assertions. A matching source,
        # type, entity, time and payload is only a repeat candidate, not a
        # validated event duplicate across vendor systems.
        signature_counts = Counter(canonical({
            'type': f['type'],
            'evidence_id': f['evidence_id'],
            'evidence_digest': f['evidence_digest'],
            'entity_id': f['entity_id'],
            'event_time': f['event_time'],
            'data': f['data'],
        }) for f in facts)
        result.update(
            status='analyzed',
            repeated_fact_candidate_count=sum(n - 1 for n in signature_counts.values()),
            repeated_signature_group_count=sum(n > 1 for n in signature_counts.values()),
            distinct_fact_signature_count=len(signature_counts),
            event_identity_available=False,
            cross_source_event_deduplication_performed=False,
            counts_may_overlap=True,
        )
    elif name == 'cross_check_timeline':
        windows = defaultdict(list)
        for f in facts:
            windows[f['evidence_id']].append(_instant(f['event_time']))
        bounds = [(min(ts), max(ts)) for ts in windows.values()]
        overlaps = sum(a_start <= b_end and b_start <= a_end
                       for (a_start, a_end), (b_start, b_end) in combinations(bounds, 2))
        times = [_instant(f['event_time']) for f in facts]
        pairs = len(bounds) * (len(bounds) - 1) // 2
        result.update(
            status='analyzed',
            reported_event_span_seconds=int((max(times) - min(times)).total_seconds()),
            evidence_source_window_pairs=pairs,
            overlapping_source_window_pairs=overlaps,
            nonoverlapping_source_window_pairs=pairs - overlaps,
            cross_source_clock_sync_verified=False,
            cross_source_causality_established=False,
            timeline_consistency='bounded_by_snapshot_not_independently_clock_validated',
        )
    elif name == 'assess_visibility_gaps':
        states = Counter(f['data']['state'] for f in facts if f['type'] == 'coverage')
        observed = sum(states.values())
        result.update(
            status='analyzed' if observed else 'no_coverage_facts',
            coverage_assertion_count=observed,
            reported_available_count=states['available'],
            reported_stale_count=states['stale'],
            reported_missing_count=states['missing'],
            reported_gap_present=bool(states['stale'] or states['missing']),
            continuous_visibility_verified=False,
            absence_of_attacks_established=False,
            visibility_status='reported_gaps' if states['stale'] or states['missing'] else 'unverified',
        )
    elif name == 'review_detection_regression':
        rows = [f['data'] for f in facts if f['type'] == 'detection']
        cohorts = Counter(r['cohort'] for r in rows)
        missed = sum(r['expected_match'] and not r['matched'] for r in rows)
        unexpected = sum(not r['expected_match'] and r['matched'] for r in rows)
        result.update(
            status='analyzed' if rows else 'no_detection_test_facts',
            supplied_test_count=len(rows),
            cohort_counts={name: cohorts[name] for name in ('malicious', 'benign', 'adversarial')},
            missing_cohorts=[name for name in ('malicious', 'benign', 'adversarial') if not cohorts[name]],
            expected_matches_missed=missed,
            unexpected_matches=unexpected,
            matched_expected_outcomes=len(rows) - missed - unexpected,
            versioned_rule_baseline_supplied=False,
            regression_established=False,
            deployment_authorized=False,
            test_truth='supplied_assertions_only',
        )
    elif name == 'review_indicator_freshness':
        rows = [f['data'] for f in facts if f['type'] == 'intelligence']
        at = _instant(document['as_of'])
        current = sum(r['match'] and _instant(r['valid_until']) >= at for r in rows)
        expired = sum(r['match'] and _instant(r['valid_until']) < at for r in rows)
        result.update(
            status='analyzed' if rows else 'no_intelligence_facts',
            reported_indicator_count=len(rows),
            reported_matched_unexpired_count=current,
            reported_matched_expired_count=expired,
            reported_unmatched_count=sum(not r['match'] for r in rows),
            external_enrichment_performed=False,
            feed_source_reliability_verified=False,
            threat_actor_attribution='unknown',
            indicator_validity='supplied_expiry_only',
        )
    elif name == 'summarize_hunt_hypotheses':
        activities = [f['data'] for f in facts if f['type'] == 'activity']
        identities = [f['data'] for f in facts if f['type'] == 'identity']
        clouds = [f['data'] for f in facts if f['type'] == 'cloud']
        result.update(
            status='analyzed' if (activities or identities or clouds) else 'no_hunt_facts',
            reported_activity_count=len(activities),
            reported_failed_activity_count=sum(r['outcome'] == 'failure' for r in activities),
            reported_authentication_activity_count=sum(r['category'] == 'authentication' for r in activities),
            reported_sensitive_identity_change_count=sum(r['event'] in ('privilege_grant', 'mfa_disabled') for r in identities),
            reported_present_cloud_change_count=sum(r['state'] == 'present' for r in clouds),
            hunt_hypotheses_require_analyst_scope=True,
            benign_admin_explanation_unresolved=True,
            authorized_live_search_performed=False,
            compromise_established=False,
        )
    elif name == 'review_exposure_context':
        rows = [f['data'] for f in facts if f['type'] == 'exposure']
        urgent = [r for r in rows if r['severity'] in ('high', 'critical') and r['reachable'] == 'yes' and r['mitigated'] == 'no']
        result.update(
            status='analyzed' if rows else 'no_exposure_facts',
            reported_exposure_count=len(rows),
            urgent_review_count=len(urgent),
            uncertain_reachability_count=sum(r['reachable'] == 'unknown' for r in rows),
            unknown_mitigation_count=sum(r['mitigated'] == 'unknown' for r in rows),
            lower_severity_count=sum(r['severity'] not in ('critical', 'high') for r in rows),
            exploitation_established=False,
            inventory_freshness_verified=False,
            remediation_authorized=False,
        )
    elif name == 'review_cloud_change_assertions':
        rows = [f['data'] for f in facts if f['type'] == 'cloud']
        types = ('public_access', 'privileged_workload', 'unsigned_component', 'policy_drift')
        present = Counter(r['finding'] for r in rows if r['state'] == 'present')
        result.update(
            status='analyzed' if rows else 'no_cloud_facts',
            reported_cloud_finding_count=len(rows),
            reported_present_by_type={t: present[t] for t in types},
            reported_present_unauthorized_count=sum(r['state'] == 'present' and r['authorized'] == 'no' for r in rows),
            authorization_unknown_count=sum(r['authorized'] == 'unknown' for r in rows),
            baseline_provenance_verified=False,
            component_signature_independently_verified=False,
            cloud_mutation_performed=False,
        )
    elif name == 'review_response_dependencies':
        rows = [f['data'] for f in facts if f['type'] == 'response_check']
        types = ('target_binding', 'dependencies', 'recovery')
        fail = Counter(r['check'] for r in rows if r['passed'] == 'no')
        unknown = Counter(r['check'] for r in rows if r['passed'] == 'unknown')
        result.update(
            status='analyzed' if rows else 'no_response_checks',
            reported_check_count=len(rows),
            failed_by_check={t: fail[t] for t in types},
            unknown_by_check={t: unknown[t] for t in types},
            unmet_dependency_count=sum(fail.values()) + sum(unknown.values()),
            action_request='human_review_required',
            target_identity_independently_verified=False,
            containment_performed=False,
            rollback_performed=False,
        )
    elif name == 'review_recovery_baselines':
        rows = [f['data'] for f in facts if f['type'] == 'recovery']
        types = ('restore', 'service_health', 'security_control')
        failed = Counter(r['check'] for r in rows if r['result'] == 'fail')
        result.update(
            status='analyzed' if rows else 'no_recovery_facts',
            reported_recovery_check_count=len(rows),
            reported_failed_by_type={t: failed[t] for t in types},
            stale_or_unknown_baselines=sum(r['baseline'] != 'current' for r in rows),
            unknown_check_results=sum(r['result'] == 'unknown' for r in rows),
            reported_pass_with_current_baseline=sum(r['result'] == 'pass' and r['baseline'] == 'current' for r in rows),
            end_to_end_recovery_independently_verified=False,
            recovery_complete_established=False,
            lesson_published=False,
        )
    return result
