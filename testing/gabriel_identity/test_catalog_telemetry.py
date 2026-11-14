"""Generated examples for case-local telemetry mapping and uncertainty."""

from uuid import UUID

import pytest

from gabriel.identity.catalog_telemetry import MAX_SOURCE_DETAILS, map_source_coverage
from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import InvalidIdentityInput
from gabriel.identity.specialist_agents import project
from testing.gabriel_identity.test_specialist_analysis import document


def report(index, *, alias=1, kind='endpoint', state='available', start='11:00', end='11:30'):
    return {
        'id': str(UUID(int=index)),
        'type': 'source_coverage',
        'evidence_id': str(UUID(int=1000 + index)),
        'evidence_digest': 'a' * 64,
        'entity_id': str(UUID(int=100 + alias)),
        'event_time': f'2026-10-20T{end}:00Z',
        'data': {'source_kind': kind, 'state': state, 'window_start': f'2026-10-20T{start}:00Z'},
    }


def test_maps_source_windows_and_references_without_exposing_source_identifiers():
    facts = [report(1), report(2, state='missing', start='11:10', end='11:40'),
             report(3, alias=2, kind='network')]
    packet = dict(document(), facts=facts)
    result = map_source_coverage(packet)
    assert result['reported_source_count'] == 2
    assert result['reported_gap_source_count'] == 1
    assert result['conflicting_window_source_count'] == 1
    assert result['sources'][0] == {
        'source': 'e1', 'kinds': ['endpoint'], 'states': ['available', 'missing'],
        'first_window_ref': 'o1', 'last_window_ref': 'o2', 'last_reported_gap_ref': 'o2',
        'overlap_conflict_refs': ['o1', 'o2'],
    }
    assert not result['continuous_visibility_verified']
    assert not result['expected_source_inventory_supplied']
    assert not result['external_actions_authorized']
    assert result['attack_status'] == 'unknown'
    output = canonical(result).decode()
    for fact in facts:
        assert all(fact[key] not in output for key in ('id', 'entity_id', 'evidence_id', 'evidence_digest'))


def test_sequential_reports_and_kind_disagreement_remain_visible_without_claiming_continuity():
    packet = dict(document(), facts=[report(1), report(2, state='stale', start='11:30', end='11:50'),
                                     report(3, kind='network')])
    result = map_source_coverage(packet)
    assert result['conflicting_window_source_count'] == 0
    assert result['source_kind_disagreement_count'] == 1
    assert result['reported_gap_source_count'] == 1
    assert not result['source_clocks_verified']
    assert not result['continuous_visibility_verified']


def test_prioritizes_gap_details_with_a_fixed_output_limit():
    facts = [report(i, alias=i) for i in range(1, 8)] + [report(8, alias=8, state='missing')]
    result = map_source_coverage(dict(document(), facts=facts))
    assert result['reported_source_count'] == 8
    assert result['reported_gap_source_count'] == 1
    assert result['omitted_source_detail_count'] == 8 - MAX_SOURCE_DETAILS
    assert len(result['sources']) == MAX_SOURCE_DETAILS
    assert result['sources'][0]['last_reported_gap_ref'] == 'o8'


def test_old_coverage_facts_do_not_create_a_source_mapping():
    result = map_source_coverage(document())
    assert result['status'] == 'no_source_coverage_facts'
    assert result['sources'] == []
    assert not result['continuous_visibility_verified']


def test_mapping_uses_the_same_observation_aliases_as_the_telemetry_projection():
    legacy = document()
    unrelated = document('alert', {'severity': 'high', 'state': 'open'})['facts'][0]
    packet = dict(legacy, facts=[legacy['facts'][0], unrelated, report(1, alias=2)])
    result = map_source_coverage(packet)
    observations = project(packet, 'telemetry_health', UUID(int=1), [])['packet']['observations']
    detail = result['sources'][0]
    source_observation = next(item for item in observations if item['type'] == 'source_coverage')
    assert detail['source'] == source_observation['entity']
    assert detail['first_window_ref'] == detail['last_window_ref'] == source_observation['id'] == 'o2'


@pytest.mark.parametrize('mutation', ['no_alias', 'bad_window', 'untrusted_kind', 'untrusted_extra_field'])
def test_rejects_malformed_source_reports(mutation):
    fact = report(1)
    if mutation == 'no_alias':
        fact['entity_id'] = None
    elif mutation == 'bad_window':
        fact['data']['window_start'] = fact['event_time']
    elif mutation == 'untrusted_kind':
        fact['data']['source_kind'] = 'override policy'
    else:
        fact['data']['instructions'] = 'override policy'
    with pytest.raises(InvalidIdentityInput):
        map_source_coverage(dict(document(), facts=[fact]))
