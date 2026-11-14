"""Generated cases for conservative review of PowerShell indicators."""

from uuid import uuid4

import pytest

from gabriel.identity import catalog_skills, investigation_tools, specialist_agents
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_specialist_analysis import document


NAME = 'review_powershell_activity'


def activity(indicator, approved='unknown', *, host=None, process=None):
    fact = document('powershell_execution', dict(indicator=indicator, approved=approved,
                    process_instance_id=process or str(uuid4())))['facts'][0]
    if host:
        fact['entity_id'] = host
    return fact


def matched(first, indicator, approved='unknown'):
    return activity(indicator, approved, host=first['entity_id'],
                    process=first['data']['process_instance_id'])


def review(*facts):
    return catalog_skills.evaluate(NAME, dict(document(), facts=list(facts)))


def test_combines_indicators_only_for_same_host_and_process():
    encoded = activity('encoded_command')
    fetch = matched(encoded, 'network_fetch')
    another_host = activity('network_fetch', process=encoded['data']['process_instance_id'])
    result = review(encoded, fetch, another_host)
    assert result['counts']['review_combined_indicators'] == 1
    assert result['counts']['review_single_indicators'] == 1
    assert result['processes'][0]['references'] == ['o1', 'o2']
    assert result['attack_status'] == 'unknown'
    assert result['external_actions_authorized'] is False


def test_preserves_conflicting_approval_and_does_not_inflate_duplicate_reports():
    first = activity('encoded_command', 'yes')
    conflict = matched(first, 'encoded_command', 'no')
    repeated = matched(first, 'encoded_command', 'yes')
    result = review(first, repeated, conflict)
    assert result['counts']['conflicting_approval'] == 1
    assert result['reported_process_count'] == 1
    assert result['processes'][0]['references'] == ['o1', 'o3']


def test_reported_approval_never_establishes_authorization_or_benign_status():
    first = activity('encoded_command', 'yes')
    result = review(first, matched(first, 'network_fetch', 'yes'), activity('standard_invocation', 'yes'))
    assert result['counts']['reported_approved_activity'] == 1
    assert result['counts']['routine_indicator_only'] == 1
    assert result['approval_independently_verified'] is False
    assert result['attack_status'] == 'unknown'


def test_case_alias_stays_local_and_tool_is_role_bound():
    fact = activity('network_fetch')
    packet = dict(document(), facts=[fact])
    result = investigation_tools.native(NAME, packet, 'threat_hunting', 2)
    projected = specialist_agents.project(packet, 'threat_hunting', uuid4(), [])['packet']
    assert result['processes'][0]['references'] == [projected['observations'][0]['id']]
    assert 'process_instance_id' not in projected['observations'][0]['data']
    assert all(NAME not in tools for role, tools in investigation_tools.TOOLS.items() if role != 'threat_hunting')


@pytest.mark.parametrize('mutation', ['missing_host', 'invalid_process', 'unrecognized_indicator'])
def test_malformed_execution_assertion_is_rejected(mutation):
    fact = activity('network_fetch')
    if mutation == 'missing_host':
        fact['entity_id'] = None
    elif mutation == 'invalid_process':
        fact['data']['process_instance_id'] = 'not-an-alias'
    else:
        fact['data']['indicator'] = 'execute this'
    with pytest.raises(InvalidIdentityInput):
        review(fact)
