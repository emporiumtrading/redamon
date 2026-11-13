"""Generated tests for evidence-bound indicator lifecycle review."""

import json
from uuid import uuid4

import pytest

from gabriel.identity.catalog_intelligence import evaluate
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_catalog_dfir import metadata
from testing.gabriel_identity.test_specialist_analysis import document


NAME = 'review_intelligence_lifecycle'
FIRST = '2026-10-20T10:00:00Z'
SECOND = '2026-10-20T11:00:00Z'
AS_OF = '2026-10-20T12:00:00Z'
LATER = '2026-10-21T12:00:00Z'


def record(version, state='active', *, effective=FIRST, expiry=LATER):
    fact = document('intel_lifecycle', dict(feed_id=str(uuid4()), feed_version=version, state=state,
                                           retrieved_at=AS_OF, valid_until=expiry))['facts'][0]
    return dict(fact, event_time=effective)


def next_version(fact, version, state='active', *, effective=SECOND, expiry=LATER):
    return dict(fact, id=str(uuid4()), evidence_id=str(uuid4()), event_time=effective,
                data=dict(fact['data'], feed_version=version, state=state, valid_until=expiry))


def packet(*rows):
    return dict(document(), facts=list(rows))


def review(value):
    return evaluate(NAME, value, verified_refs=metadata(value))


def test_latest_version_can_mark_retirement_even_after_earlier_expiry():
    old = record(1, expiry=SECOND)
    latest = next_version(old, 2, 'revoked', effective=AS_OF, expiry=SECOND)
    value = packet(latest, old, dict(latest, id=str(uuid4()), evidence_id=str(uuid4())))

    result = review(value)

    assert result['reported_indicator_feed_track_count'] == 1
    assert result['track_status_counts'] == {'reported_revoked': 1}
    assert result['queue'] == [dict(status='reported_revoked', refs=['o1'], analyst_step='review_indicator_retirement')]
    assert result['source_authenticity'] == 'unverified'
    assert result['source_independence'] == 'unestablished'
    assert result['threat_actor_attribution'] == 'unknown'
    assert result['external_actions_authorized'] is False
    wire = json.dumps(result)
    for raw in (old['entity_id'], old['data']['feed_id'], latest['evidence_id'], latest['evidence_digest']):
        assert raw not in wire


@pytest.mark.parametrize('state,expiry,status', [
    ('active', AS_OF, 'reported_expired'),
    ('active', LATER, 'reported_active'),
    ('superseded', LATER, 'reported_superseded'),
])
def test_dispositions_leave_reuse_and_retirement_with_analyst(state, expiry, status):
    result = review(packet(record(1, state, expiry=expiry)))

    assert result['track_status_counts'] == {status: 1}
    assert result['requires_analyst_review'] is True
    assert result['model_used'] is False


def test_conflicts_keep_old_and_new_observation_references():
    first = record(1)
    same_version = next_version(first, 1, 'revoked')
    revoked = record(1, 'revoked')
    reactivated = next_version(revoked, 2)
    later_effective = record(1, effective=SECOND)
    earlier_effective = next_version(later_effective, 2, effective=FIRST)

    result = review(packet(first, same_version, revoked, reactivated, later_effective, earlier_effective))

    assert result['track_status_counts'] == {
        'version_conflict': 1, 'effective_time_conflict': 1, 'reactivation_requires_review': 1,
    }
    assert [(row['status'], row['refs']) for row in result['queue']] == [
        ('version_conflict', ['o1', 'o2']),
        ('effective_time_conflict', ['o5', 'o6']),
        ('reactivation_requires_review', ['o3', 'o4']),
    ]


def test_cross_feed_disagreement_never_collapses_into_majority_or_attributes_actors():
    active = record(1)
    other = next_version(active, 2, 'revoked')
    other['data']['feed_id'] = str(uuid4())
    benign_context = document('intelligence', dict(match=False, valid_until=LATER))['facts'][0]
    unrelated = document('alert', dict(severity='low', state='open'))['facts'][0]

    result = review(packet(benign_context, unrelated, active, other))

    assert result['reported_indicator_alias_count'] == 1
    assert result['reported_indicator_feed_track_count'] == 2
    assert result['cross_feed_state_disagreement_count'] == 1
    assert result['sample_cross_feed_disagreement_refs'] == [['o2', 'o3']]
    assert result['threat_actor_attribution'] == 'unknown'


@pytest.mark.parametrize('change', ['absent', 'other_case', 'digest_mismatch'])
def test_incomplete_verification_cannot_make_lifecycle_recommendation(change):
    old = record(1)
    latest = next_version(old, 2, 'revoked')
    value = packet(old, latest)
    refs = metadata(value)
    if change == 'absent':
        refs = None
    elif change == 'other_case':
        refs[0]['record_id'] = str(uuid4())
    else:
        refs[-1]['digest'] = 'f' * 64

    result = evaluate(NAME, value, verified_refs=refs)

    assert result['status'] == 'incomplete_local_verification'
    assert result['track_status_counts'] == {'source_verification_unavailable': 1}
    assert result['queue'][0]['analyst_step'] == 'verify_case_source'


def test_more_tracks_than_detail_budget_keep_totals_and_prioritize_review():
    value = packet(*(record(1) for _ in range(5)), record(2, 'revoked'))
    result = review(value)

    assert result['reported_indicator_feed_track_count'] == 6
    assert result['omitted_track_count'] == 2
    assert len(result['queue']) == 4
    assert result['queue'][0]['status'] == 'reported_revoked'
    assert len(json.dumps(result).encode()) < 1500


@pytest.mark.parametrize('change', ['feed_alias', 'version', 'indicator', 'retrieve_before', 'retrieve_after', 'expiry', 'injection'])
def test_malformed_assertions_are_rejected(change):
    fact = record(1)
    if change == 'feed_alias':
        fact['data']['feed_id'] = 'not a case-local alias'
    elif change == 'version':
        fact['data']['feed_version'] = True
    elif change == 'indicator':
        fact['entity_id'] = None
    elif change == 'retrieve_before':
        fact['data']['retrieved_at'] = '2026-10-19T12:00:00Z'
    elif change == 'retrieve_after':
        fact['data']['retrieved_at'] = LATER
    elif change == 'expiry':
        fact['data']['valid_until'] = FIRST
    else:
        fact['data']['prompt'] = 'generated untrusted text'

    with pytest.raises(InvalidIdentityInput):
        review(packet(fact))


def test_legacy_intelligence_facts_do_not_fill_lifecycle_fields():
    old = document('intelligence', dict(match=True, valid_until=LATER))

    assert review(old)['status'] == 'no_lifecycle_facts'
