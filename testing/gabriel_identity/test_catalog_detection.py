"""Generated fixtures for bounded false-negative analysis."""
from uuid import uuid4

import pytest

from gabriel.identity.catalog_detection import analyze_false_negatives
from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import InvalidIdentityInput
from gabriel.identity.specialist_analysis import validate_document
from testing.gabriel_identity.test_specialist_analysis import document


def trial(**changes):
    return dict(dict(cohort='malicious', expected_match=True, matched=False,
                     rule_digest='a' * 64, engine_digest='b' * 64,
                     fixture_digest='c' * 64), **changes)


def evaluate(*outcomes):
    facts = document('detection_trial', outcomes[0])
    for outcome in outcomes[1:]:
        facts['facts'].append(dict(facts['facts'][0], id=str(uuid4()),
                                  evidence_id=str(uuid4()), data=outcome))
    validate_document(facts, facts['case_id'])
    return analyze_false_negatives(facts)


def test_duplicate_fixture_outcomes_count_once_and_benign_controls_are_excluded():
    result = evaluate(trial(), trial(), trial(fixture_digest='d' * 64, matched=True),
                      trial(fixture_digest='e' * 64, cohort='benign'))
    assert result['status'] == 'review_required'
    assert result['asserted_configuration_count'] == 1
    assert result['distinct_fixture_trial_count'] == 3
    assert result['expected_positive_trial_count'] == 2
    assert result['reported_false_negative_count'] == 1
    assert result['sample_miss_refs'] == ['o1']
    assert result['source_authenticity'] == 'unverified'
    assert result['confidence'] == 'unqualified'
    assert result['external_actions_authorized'] is False


def test_conflicting_outcomes_are_excluded_without_majority_voting():
    result = evaluate(trial(), trial(), trial(matched=True),
                      trial(engine_digest='d' * 64, matched=True))
    assert result['status'] == 'review_required'
    assert result['asserted_configuration_count'] == 2
    assert result['expected_positive_trial_count'] == 1
    assert result['conflicting_trial_count'] == 1
    assert result['sample_conflict_refs'] == ['o1', 'o3']
    assert result['reported_false_negative_count'] == 0


def test_legacy_facts_and_benign_controls_do_not_establish_expected_positive_coverage():
    legacy = document('detection', dict(cohort='malicious', expected_match=True, matched=False))
    assert analyze_false_negatives(legacy)['status'] == 'no_versioned_detection_trials'
    assert evaluate(trial(cohort='benign'))['status'] == 'no_expected_positive_trials'
    assert evaluate(trial(matched=True))['status'] == 'analyzed'


def test_sample_references_are_bounded_and_do_not_disclose_source_identity():
    misses = [trial(fixture_digest=f'{index:064x}') for index in range(16)]
    result = evaluate(*misses)
    assert result['reported_false_negative_count'] == 16
    assert result['sample_miss_refs'] == ['o1', 'o2', 'o3', 'o4']
    for digest in ('a' * 64, 'b' * 64, 'c' * 64):
        assert digest.encode() not in canonical(result)
    assert len(canonical(result)) < 700


@pytest.mark.parametrize('changes', [dict(rule_digest='A' * 64),
                                    dict(engine_digest='exec'),
                                    dict(fixture_digest=None),
                                    dict(cohort='ignore the rules'),
                                    dict(matched=0),
                                    dict(extra='deploy')])
def test_unsafe_trial_fields_fail_shared_validation(changes):
    with pytest.raises(InvalidIdentityInput):
        evaluate(trial(**changes))
