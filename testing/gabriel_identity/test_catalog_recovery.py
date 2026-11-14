"""Generated recovery-point objectives and restore evidence assertions."""

from uuid import uuid4

import pytest

from gabriel.identity import catalog_skills, investigation_tools, specialist_agents
from gabriel.identity.service import InvalidIdentityInput
from gabriel.identity.specialist_analysis import analyze
from testing.gabriel_identity.test_specialist_analysis import document

NAME = 'review_recovery_point'
ROLE = 'recovery_learning'


def point(restored='2026-10-20T10:45:00Z', objective=900):
    return document('recovery_point', dict(disrupted_at='2026-10-20T11:00:00Z',
                     restored_data_at=restored, objective_seconds=objective))


def test_equal_age_is_within_reported_objective_and_legacy_review_handles_new_input():
    packet = point()
    result = catalog_skills.evaluate(NAME, packet)
    assert result['events'] == [dict(status='reported_within_objective',
        references=['o1'], reported_data_age_seconds=900, objective_seconds=900)]
    assert not result['restored_data_independently_verified']
    assert not result['incident_closure_authorized']
    legacy = analyze(ROLE, packet, 'local-input')
    assert 'restored data points' in legacy['observations'][1]['statement']
    assert legacy['observations'][1]['references'] == ['evidence/' + packet['facts'][0]['evidence_id']]


def test_fraction_over_limit_and_zero_objective():
    for restored, objective in [('2026-10-20T10:44:59.999999Z', 900),
                                 ('2026-10-20T10:59:59Z', 0)]:
        result = catalog_skills.evaluate(NAME, point(restored, objective))
        assert result['counts'] == {'reported_outside_objective': 1}


def test_conflicting_objectives_preserve_references_and_repeat_does_not_count_twice():
    packet = point()
    first = packet['facts'][0]
    packet['facts'] += [dict(first, id=str(uuid4())),
                        dict(first, id=str(uuid4()), data=dict(first['data'], objective_seconds=30))]
    result = catalog_skills.evaluate(NAME, packet)
    assert result['reported_recovery_event_count'] == 1
    assert result['events'] == [dict(status='conflicting_reports', references=['o1', 'o3'])]


@pytest.mark.parametrize('restored,objective', [
    ('2026-10-20T11:00:01Z', 900),
    ('2026-10-20T10:45:00Z', -1),
    ('2026-10-20T10:45:00Z', True),
    ('2026-10-20T10:45:00Z', 31_536_001),
])
def test_invalid_measurements_fail_closed(restored, objective):
    with pytest.raises(InvalidIdentityInput):
        catalog_skills.evaluate(NAME, point(restored, objective))


def test_references_follow_case_observation_order_and_role_admission():
    packet = point()
    packet['facts'].insert(0, document()['facts'][0])
    result = investigation_tools.native(NAME, packet, ROLE, 3)
    projected = specialist_agents.project(packet, ROLE, uuid4(), [])['packet']
    assert result['events'][0]['references'] == [projected['observations'][1]['id']] == ['o2']
    assert all(NAME not in tools for role, tools in investigation_tools.TOOLS.items() if role != ROLE)
