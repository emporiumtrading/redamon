"""Browser assertions remain unverified, bounded and distinct from permissions."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity.browser_specialists import project
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_attack_pattern_runs_integration import event_document


def sample(count=10):
    return event_document(uuid4(),dict(id=uuid4(),digest='a'*64),count)


def test_duplicate_native_events_never_inflate_fact_counts_or_authorization():
    document=sample()
    document['events']+=deepcopy(document['events'])
    facts,counts=project(document,uuid4())
    assert counts['unique_event_count']==10 and counts['unmapped_event_count']==0
    assert sum(row['data']['count'] for row in facts['facts'] if row['type']=='activity')==10
    assert all(row['data']['authorized']=='unknown' for row in facts['facts'] if row['type']=='identity')
    assert not any(row['type'] in {'alert','intelligence','detection','exposure','response_check','recovery','cloud'} for row in facts['facts'])


def test_canonical_source_and_fact_ids_survive_reordering_forwarded_copies():
    document=sample(2);observation=uuid4()
    copy=[dict(row,evidence_id=str(uuid4()),evidence_digest='b'*64) for row in document['events']]
    document['events']+=copy
    one=project(document,observation)
    document['events'].reverse()
    assert project(document,observation)==one
    assert len([row for row in one[0]['facts'] if row['type']=='artifact'])==3


def test_same_actor_on_two_assets_preserves_distinct_scope_and_counts():
    document=sample(10);asset=str(uuid4())
    for row in document['events'][5:]: row['asset_id']=asset
    facts,_=project(document,uuid4())
    activity=[row for row in facts['facts'] if row['type']=='activity']
    assert len(activity)==2 and sum(row['data']['count'] for row in activity)==10
    assert len({row['entity_id'] for row in activity})==2
    assert len({row['entity_id'] for row in facts['facts'] if row['type']=='identity'})==1


def test_unmapped_integrity_event_creates_explicit_gap_without_invented_process():
    document=sample(1);document['missing_sources']=[]
    document['events'][0]['kind']='kernel_integrity_violation'
    facts,counts=project(document,uuid4())
    assert counts['unmapped_event_count']==1
    assert {row['type'] for row in facts['facts']}=={'artifact','coverage'}
    assert all(row['data']['state']=='missing' for row in facts['facts'] if row['type']=='coverage')


def test_projection_over_limit_rejects_instead_of_truncating():
    document=sample(128)
    for row in document['events']:
        row.update(actor_id=str(uuid4()),event_time='2026-10-20T12:09:00Z')
    with pytest.raises(InvalidIdentityInput,match='fact_limit'): project(document,uuid4())


def test_conflicting_native_event_identity_cannot_be_projected():
    document=sample(1)
    document['events'].append(dict(document['events'][0],kind='auth_success'))
    with pytest.raises(InvalidIdentityInput,match='conflicting_security_event_identity'): project(document,uuid4())
