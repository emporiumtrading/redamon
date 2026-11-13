"""Generated cases for uncertainty-aware incident timeline normalization."""

from uuid import uuid4

import pytest

from gabriel.identity import catalog_skills, investigation_tools, specialist_agents
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_specialist_analysis import document

NAME = 'normalize_incident_timeline'
ROLE = 'incident_scoping'


def event(timestamp, offset=0, uncertainty=0, *, status='measured'):
    value = document('timeline_event', dict(offset_status=status, clock_offset_ms=offset,
                                            uncertainty_ms=uncertainty))['facts'][0]
    value['event_time'] = timestamp
    return value


def review(*events):
    packet = dict(document(), facts=list(events))
    return catalog_skills.evaluate(NAME, packet)


def test_applies_offsets_and_orders_only_disjoint_intervals():
    result = review(event('2026-10-20T12:00:01Z', 5000, 1000),
                    event('2026-10-20T11:59:55Z', -1000, 1000),
                    event('2026-10-20T11:59:58Z'))
    assert result['sample_intervals'] == [
        dict(ref='o1', earliest='2026-10-20T11:59:55Z', latest='2026-10-20T11:59:57Z'),
        dict(ref='o2', earliest='2026-10-20T11:59:55Z', latest='2026-10-20T11:59:57Z'),
        dict(ref='o3', earliest='2026-10-20T11:59:58Z', latest='2026-10-20T11:59:58Z'),
    ]
    assert result['sample_reported_order'] == [['o1', 'o3'], ['o2', 'o3']]
    assert result['overlapping_or_touching_pair_count'] == 1
    assert result['actual_event_order_verified'] is False
    assert result['external_actions_authorized'] is False


def test_touching_unknown_and_snapshot_crossing_intervals_do_not_invent_order():
    result = review(event('2026-10-20T11:59:55Z', 0, 1000),
                    event('2026-10-20T11:59:57Z', 0, 1000),
                    event('2026-10-20T12:00:01Z', 0, 2000),
                    event('2026-10-20T12:00:01Z', None, None, status='unknown'))
    assert result['sample_reported_order'] == []
    assert result['overlapping_or_touching_pair_count'] == 1
    assert result['sample_unordered'] == [
        dict(ref='o3', reason='interval_crosses_snapshot'),
        dict(ref='o4', reason='clock_offset_unknown'),
    ]


def test_repeated_and_conflicting_clock_assertions_preserve_distinct_references():
    first = event('2026-10-20T11:59:55Z')
    repeat = dict(first, id=str(uuid4()))
    conflict = dict(first, id=str(uuid4()), data=dict(first['data'], clock_offset_ms=1000))
    result = review(first, repeat, conflict)
    assert result['repeated_report_count'] == 1
    assert result['distinct_report_count'] == 2
    assert result['normalized_interval_count'] == 0
    assert result['sample_unordered'] == [
        dict(ref='o1', reason='conflicting_clock_assertions'),
        dict(ref='o3', reason='conflicting_clock_assertions'),
    ]


@pytest.mark.parametrize('timestamp,offset,uncertainty,status', [
    ('2026-10-20T12:00:01Z', 0, 0, 'measured'),
    ('2026-10-22T11:59:55Z', None, None, 'unknown'),
    ('2026-10-20T11:59:55Z', 0, -1, 'measured'),
    ('2026-10-20T11:59:55Z', 86400001, 0, 'measured'),
    ('2026-10-20T11:59:55Z', True, 0, 'measured'),
    ('2026-10-20T11:59:55Z', 0, None, 'unknown'),
])
def test_invalid_or_entirely_future_timeline_assertions_fail_closed(timestamp, offset, uncertainty, status):
    with pytest.raises(InvalidIdentityInput):
        review(event(timestamp, offset, uncertainty, status=status))


def test_timeline_result_references_match_role_projection():
    packet = document('coverage')
    packet['facts'].append(event('2026-10-20T11:00:00Z'))
    result = investigation_tools.native(NAME, packet, ROLE, 3)
    projected = specialist_agents.project(packet, ROLE, uuid4(), [])['packet']
    assert result['sample_intervals'][0]['ref'] == projected['observations'][1]['id'] == 'o2'
    assert all(NAME not in tools for role, tools in investigation_tools.TOOLS.items() if role != ROLE)
