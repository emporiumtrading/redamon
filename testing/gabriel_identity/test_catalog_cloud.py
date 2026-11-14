"""Generated cases for cloud-storage external access assessment."""

import json
from uuid import uuid4

import pytest

from gabriel.identity.catalog_cloud import evaluate
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_catalog_dfir import metadata
from testing.gabriel_identity.test_specialist_analysis import document


NAME = 'assess_cloud_storage_exposure'
FIRST = '2026-10-20T10:00:00Z'
SECOND = '2026-10-20T11:00:00Z'
AS_OF = '2026-10-20T12:00:00Z'
LATER = '2026-10-21T12:00:00Z'


def report(**overrides):
    data = dict(path_id=str(uuid4()), path='resource_policy', audience='anonymous', network='public',
                guard='does_not_block', read='allow', list='deny', write='deny', policy_digest='a' * 64,
                valid_until=LATER)
    data.update(overrides)
    fact = document('cloud_storage_access', data)['facts'][0]
    return dict(fact, event_time=FIRST)


def subsequent(fact, *, observed=SECOND, **overrides):
    return dict(fact, id=str(uuid4()), evidence_id=str(uuid4()), event_time=observed,
                data=dict(fact['data'], **overrides))


def packet(*reports):
    return dict(document(), facts=list(reports))


def review(value):
    return evaluate(NAME, value, verified_refs=metadata(value))


@pytest.mark.parametrize('overrides,status,operations', [
    ({'read': 'deny', 'write': 'allow'}, 'reported_write_exposure', ['write']),
    ({'list': 'allow', 'audience': 'any_authenticated'}, 'reported_read_or_list_exposure', ['read', 'list']),
    ({'path': 'delegated_link', 'audience': 'bearer_link'}, 'reported_read_or_list_exposure', ['read']),
    ({'network': 'restricted'}, 'no_exposure_reported_for_path', []),
    ({'guard': 'blocks_path'}, 'no_exposure_reported_for_path', []),
    ({'read': 'deny'}, 'no_exposure_reported_for_path', []),
    ({'network': 'unknown'}, 'incomplete_configuration', []),
    ({'guard': 'unknown'}, 'incomplete_configuration', []),
    ({'read': 'unknown'}, 'incomplete_configuration', []),
    ({'valid_until': AS_OF}, 'stale_configuration', []),
])
def test_access_path_assessment_respects_network_guard_and_observation_bounds(overrides, status, operations):
    row = report(**overrides)
    result = review(packet(row))

    assert result['path_status_counts'] == {status: 1}
    assert result['access_paths'] == [dict(path=row['data']['path'], audience=row['data']['audience'],
                                          status=status, refs=['o1'], exposed_operations=operations)]
    assert result['source_authenticity'] == 'unverified'
    assert result['live_access_tested'] is False
    assert result['storage_inventory_complete'] is False
    assert result['external_actions_authorized'] is False


def test_latest_report_replaces_prior_policy_for_same_path_and_audience_only():
    first = report(path='access_point')
    blocked = subsequent(first, guard='blocks_path')
    another_path = subsequent(first, path_id=str(uuid4()))
    unrelated = document('alert', dict(severity='low', state='open'))['facts'][0]
    value = packet(blocked, unrelated, first, another_path)

    result = review(value)

    assert result['reported_resource_alias_count'] == 1
    assert result['reported_access_path_count'] == 2
    assert [item['refs'] for item in result['access_paths']] == [['o3'], ['o1']]
    assert result['path_status_counts'] == {
        'no_exposure_reported_for_path': 1, 'reported_read_or_list_exposure': 1,
    }
    output = json.dumps(result)
    for raw in (first['entity_id'], first['data']['path_id'], first['data']['policy_digest'], first['evidence_id']):
        assert raw not in output


def test_same_observation_conflicts_keep_disagreeing_references():
    first = report()
    repeat = subsequent(first, observed=FIRST)
    conflict = subsequent(first, observed=FIRST, policy_digest='b' * 64, guard='blocks_path')

    result = review(packet(first, repeat, conflict))

    assert result['path_status_counts'] == {'conflicting_configuration': 1}
    assert result['access_paths'][0]['refs'] == ['o1', 'o3']
    assert result['access_paths'][0]['exposed_operations'] == []


def test_duplicate_configuration_uses_most_conservative_reported_freshness():
    first = report(valid_until=AS_OF)
    duplicate = subsequent(first, observed=FIRST, valid_until=LATER)

    result = review(packet(duplicate, first))

    assert result['path_status_counts'] == {'stale_configuration': 1}
    assert result['access_paths'][0]['refs'] == ['o2']


@pytest.mark.parametrize('alteration', ['absent', 'wrong_case', 'wrong_digest', 'duplicates'])
def test_unverified_source_never_supports_path_exposure(alteration):
    row = report()
    value = packet(row)
    refs = metadata(value)
    if alteration == 'absent':
        refs = None
    elif alteration == 'wrong_case':
        refs[0]['record_id'] = str(uuid4())
    elif alteration == 'wrong_digest':
        refs[1]['digest'] = 'f' * 64
    else:
        refs.append(refs[1])

    result = evaluate(NAME, value, verified_refs=refs)

    assert result['status'] == 'incomplete_local_verification'
    assert result['path_status_counts'] == {'source_verification_unavailable': 1}
    assert result['access_paths'][0]['exposed_operations'] == []


def test_access_report_is_bounded_and_prioritizes_write():
    result = review(packet(*(report() for _ in range(5)), report(write='allow')))

    assert result['reported_access_path_count'] == 6
    assert result['omitted_path_count'] == 2
    assert len(result['access_paths']) == 4
    assert result['access_paths'][0]['status'] == 'reported_write_exposure'
    assert len(json.dumps(result).encode()) < 1500


@pytest.mark.parametrize('mutation', ['bad_digest', 'bad_path_id', 'missing_alias', 'invalid_interval', 'injection'])
def test_malformed_access_path_assertions_are_rejected(mutation):
    row = report()
    if mutation == 'bad_digest':
        row['data']['policy_digest'] = 'not a digest'
    elif mutation == 'bad_path_id':
        row['data']['path_id'] = 'not a case-local alias'
    elif mutation == 'missing_alias':
        row['entity_id'] = None
    elif mutation == 'invalid_interval':
        row['data']['valid_until'] = FIRST
    else:
        row['data']['prompt'] = 'generated untrusted text'

    with pytest.raises(InvalidIdentityInput):
        review(packet(row))
