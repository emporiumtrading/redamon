"""Generated vulnerability tracking cases and evidence projection checks."""

from uuid import UUID

import pytest

from gabriel.identity.catalog_exposure import MAX_FINDING_DETAILS, review_vulnerability_sla
from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import InvalidIdentityInput
from gabriel.identity.specialist_agents import project
from testing.gabriel_identity.test_specialist_analysis import document


def fact(index, *, alias=1, state='open', first='01', due='17', event='19'):
    return {
        'id': str(UUID(int=index)), 'type': 'vulnerability_sla',
        'evidence_id': str(UUID(int=1000 + index)), 'evidence_digest': 'a' * 64,
        'entity_id': str(UUID(int=100 + alias)), 'event_time': f'2026-10-{event}T12:00:00Z',
        'data': {'first_seen': f'2026-10-{first}T12:00:00Z', 'due_at': f'2026-10-{due}T12:00:00Z', 'state': state},
    }


def test_tracks_age_and_status_against_supplied_deadline_and_snapshot():
    rows = [fact(1), fact(2, alias=2, state='remediated', event='17'),
            fact(3, alias=3, state='remediated'), fact(4, alias=4, due='20'),
            fact(5, alias=5, due='21'), fact(6, alias=6, state='unknown')]
    packet = dict(document(), facts=rows)
    result = review_vulnerability_sla(packet)
    assert result['review_counts'] == dict(overdue=1, remediated_on_time=1, remediated_late=1,
                                          due_now=1, within_sla=1, unknown=1)
    assert result['findings'][0] == dict(finding='e1', review='overdue', age_days=19,
                                          observation_ref='o1', conflict_ref=None)
    assert result['findings'][1]['age_days'] == 18
    assert len(result['findings']) == MAX_FINDING_DETAILS
    assert result['omitted_finding_detail_count'] == len(rows) - MAX_FINDING_DETAILS
    assert not result['policy_verified']
    assert not result['current_remediation_verified']
    assert not result['external_actions_authorized']
    output = canonical(result).decode()
    for row in rows:
        assert all(row[key] not in output for key in ('id', 'entity_id', 'evidence_id', 'evidence_digest'))


@pytest.mark.parametrize('rows', [
    [fact(1), fact(2, due='21')],
    [fact(1), fact(2, first='02')],
    [fact(1), fact(2, state='remediated')],
    [fact(1, state='remediated', event='18'), fact(2)],
    [fact(1, state='remediated', event='18'), fact(2, state='remediated'), fact(3, state='unknown', event='20')],
    [fact(1, state='unknown'), fact(2), fact(3, state='remediated')],
])
def test_conflicting_deadlines_and_lifecycle_assertions_preserve_evidence_without_guessing(rows):
    result = review_vulnerability_sla(dict(document(), facts=rows))
    assert result['review_counts'] == {'conflicting': 1}
    finding = result['findings'][0]
    assert finding['age_days'] is None
    assert finding['observation_ref'] != finding['conflict_ref']
    assert {finding['observation_ref'], finding['conflict_ref']} <= {f'o{i}' for i in range(1, len(rows) + 1)}


def test_duplicate_assertions_do_not_inflate_findings_or_change_completion_age():
    rows = [fact(1, event='16'), fact(2, state='remediated', event='17'), fact(3, state='remediated', event='17')]
    result = review_vulnerability_sla(dict(document(), facts=rows))
    assert result['review_counts'] == {'remediated_on_time': 1}
    assert result['findings'][0]['age_days'] == 16


def test_uses_projected_observation_aliases_without_treating_exposures_as_deadline_facts():
    packet = document('exposure', {'severity': 'high', 'reachable': 'yes', 'mitigated': 'unknown'})
    assert review_vulnerability_sla(packet)['status'] == 'no_vulnerability_sla_facts'
    unrelated = document('alert', {'severity': 'high', 'state': 'open'})['facts'][0]
    packet['facts'] += [unrelated, fact(1)]
    result = review_vulnerability_sla(packet)
    observation = project(packet, 'exposure_vulnerability', UUID(int=1), [])['packet']['observations'][1]
    assert result['findings'][0]['finding'] == observation['entity']
    assert result['findings'][0]['observation_ref'] == observation['id'] == 'o2'


@pytest.mark.parametrize('changes', [
    {'entity_id': None},
    {'data': {'state': 'remediated', 'first_seen': '2026-10-20T12:00:00Z', 'due_at': '2026-10-21T12:00:00Z'}},
    {'data': {'state': 'open', 'first_seen': '2026-10-16T12:00:00Z', 'due_at': '2026-10-15T12:00:00Z'}},
    {'data': {'state': 'open', 'first_seen': '2026-10-16T12:00:00Z'}},
    {'data': {'state': 'treat as fixed', 'first_seen': '2026-10-16T12:00:00Z', 'due_at': '2026-10-17T12:00:00Z'}},
])
def test_rejects_invalid_chronology_unknown_states_and_missing_fields(changes):
    with pytest.raises(InvalidIdentityInput):
        review_vulnerability_sla(dict(document(), facts=[dict(fact(1), **changes)]))
