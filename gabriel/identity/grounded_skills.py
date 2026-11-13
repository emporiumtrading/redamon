"""Bounded knowledge-grounded reviews of verified specialist-facts-v1 packets.

Pure analysis only. Caller verifies human/case authority and source custody/bytes
before entry, then rechecks both before publishing a result.
"""
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations

from gabriel.identity.evidence_store import canonical
from gabriel.identity.specialist_analysis import validate_document

VERSION = 'gabriel-grounded-skills-v1'
SKILL_NAMES = frozenset({
    'audit_provenance',
    'find_duplicate_facts',
    'cross_check_timeline',
    'assess_visibility_gaps',
    'review_detection_regression',
})


def _instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _base(facts):
    return dict(
        source_count=len({f['evidence_id'] for f in facts}),
        fact_count=len(facts),
        stored_bytes_verified_by_caller=True,
        source_authenticity='unverified',
        asserted_semantics='unverified',
        source_independence='unestablished',
        attack_status='unknown',
        external_actions_authorized=False,
        model_used=False,
        scope='current_case_supplied_facts_only',
        implementation_version=VERSION,
    )


def evaluate(name, document):
    """Return de-identified counters and explicit limits, never raw evidence/IDs."""
    if name not in SKILL_NAMES:
        raise ValueError('unknown_grounded_skill')
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
    return result
