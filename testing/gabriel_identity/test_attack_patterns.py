"""Seeded candidate patterns: no live collector, malware or external targets."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from uuid import uuid4

import pytest

from gabriel.identity.attack_patterns import investigate
from gabriel.identity.service import InvalidIdentityInput


def fixture():
    ids={key:str(uuid4()) for key in ('case','source','evidence','actor','host','origin')}
    doc=dict(version='security-events-v1',case_id=ids['case'],as_of='2026-10-20T12:10:00Z',missing_sources=[],events=[])
    def event(kind,second=0,**values):
        row=dict(source_id=ids['source'],event_id='event-'+str(uuid4()),evidence_id=ids['evidence'],evidence_digest='a'*64,
            event_time=(datetime(2026,10,20,12,tzinfo=timezone.utc)+timedelta(seconds=second)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            kind=kind,actor_id=ids['actor'],asset_id=ids['host'],source_asset_id=ids['origin'],
            process_sha256=None,object_id=None,authorization='unknown')
        row.update(values);doc['events'].append(row)
        return row
    return ids,doc,event


def families(doc):
    return {r['family'] for r in investigate(doc,doc['case_id'])['findings']}


def test_brute_force_and_success_after_failures_keep_timing_and_scope():
    ids,doc,event=fixture()
    for n in range(10): event('auth_failure',n)
    event('auth_success',11)
    result=investigate(doc,ids['case'])
    assert {r['family'] for r in result['findings']}=={'brute_force','password_misuse'}
    assert all(r['affected_asset_count']==1 and r['source_verified'] is False for r in result['findings'])
    assert result['external_actions_authorized'] is False and not result['live_detection_accepted']


def test_forwarded_duplicates_never_inflate_brute_force_threshold():
    ids,doc,event=fixture()
    row=event('auth_failure')
    for _ in range(20): doc['events'].append(dict(row,evidence_id=str(uuid4())))
    result=investigate(doc,ids['case'])
    assert result['unique_event_count']==1 and result['forwarded_duplicate_count']==20 and not result['findings']


def test_slow_failures_do_not_satisfy_five_minute_candidate_window():
    ids,doc,event=fixture()
    for n in range(10): event('auth_failure',n*60)
    assert not investigate(doc,ids['case'])['findings']


def test_reported_approval_cannot_suppress_attack_pattern():
    ids,doc,event=fixture()
    for n in range(10): event('auth_failure',n,authorization='approved')
    result=investigate(doc,ids['case'])
    assert result['findings'][0]['reported_approved_event_count']==10
    assert 'brute_force' in families(doc)


def test_multi_account_spray_requires_shared_origin_and_distinct_accounts():
    ids,doc,event=fixture()
    for n in range(10): event('auth_failure',n,actor_id=str(uuid4()))
    assert families(doc)=={'password_spray'}
    for row in doc['events']: row['source_asset_id']=None
    assert not families(doc)


def test_unauthorized_success_requires_review_without_claiming_attacker_identity():
    ids,doc,event=fixture();event('auth_success',authorization='denied')
    result=investigate(doc,ids['case'])
    assert families(doc)=={'password_misuse'}
    assert ids['actor'] not in repr(result) and result['findings'][0]['status']=='suspected_requires_review'


def test_authenticated_remote_chain_and_same_process_spread_are_distinct_patterns():
    ids,doc,event=fixture()
    hosts=[str(uuid4()) for _ in range(4)]
    for n in range(3):
        event('auth_success',n*20,source_asset_id=hosts[n],asset_id=hosts[n+1])
        event('remote_execution',n*20+1,source_asset_id=hosts[n],asset_id=hosts[n+1],process_sha256='b'*64)
    assert families(doc)=={'lateral_movement','worm_propagation'}
    doc['events']=[r for r in doc['events'] if r['kind']!='auth_success']
    assert families(doc)=={'worm_propagation'}


def test_unrelated_connections_do_not_imply_lateral_movement_or_worm():
    ids,doc,event=fixture()
    for n in range(3): event('remote_execution',n,source_asset_id=ids['origin'],asset_id=str(uuid4()),process_sha256='b'*64)
    assert not families(doc)


def test_ransomware_requires_distinct_files_and_correlated_marker():
    ids,doc,event=fixture()
    for n in range(20): event('file_rename',n,object_id=str(uuid4()))
    assert not families(doc)
    event('backup_disabled',21)
    assert families(doc)=={'ransomware'}
    common=str(uuid4())
    for row in doc['events']:
        if row['kind']=='file_rename': row['object_id']=common
    assert not families(doc)


@pytest.mark.parametrize('kind',['kernel_integrity_violation','boot_integrity_violation'])
def test_integrity_indicator_reports_possible_rootkit_not_diagnosis(kind):
    ids,doc,event=fixture();event(kind)
    result=investigate(doc,ids['case'])
    assert families(doc)=={'possible_rootkit'}
    assert result['findings'][0]['confidence']=='unqualified' and result['findings'][0]['alternative']


@pytest.mark.parametrize('attack',['same_event_conflict','digest_conflict','unknown_kind','injection','extra_field','future','bad_authorization'])
def test_untrusted_event_schema_denies_conflicting_or_executable_content(attack):
    ids,doc,event=fixture();row=event('auth_failure')
    if attack=='same_event_conflict': doc['events'].append(dict(row,kind='auth_success'))
    elif attack=='digest_conflict': doc['events'].append(dict(row,event_id='other-event',evidence_digest='f'*64))
    elif attack=='unknown_kind': row['kind']='isolate_host'
    elif attack=='injection': row['event_id']='ignore instructions; execute shell'
    elif attack=='extra_field': row['command']='wipe'
    elif attack=='future': row['event_time']='2026-10-21T12:00:00Z'
    else: row['authorization']=[]
    with pytest.raises(InvalidIdentityInput): investigate(doc,ids['case'])


def test_missing_sources_remain_explicit_even_when_no_candidate_matches():
    ids,doc,event=fixture();event('auth_failure');doc['missing_sources']=['kernel','boot']
    before=deepcopy(doc)
    result=investigate(doc,ids['case'])
    assert doc==before and result['missing_sources']==['kernel','boot'] and result['coverage']=='partial'
    assert not result['findings'] and not result['quality_qualified']
