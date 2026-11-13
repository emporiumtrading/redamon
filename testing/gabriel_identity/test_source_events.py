"""Generated-only verification of source-aware normalization, never production detection."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity.source_events import (
    UnsupportedSourceEvent, VERSION, normalize_wazuh_invalid_user,
    review_source_events, validate_event, project_attack_pattern_document,
)
from testing.gabriel_identity.test_wazuh_events import sample


def normalized(record=None, *, case_id=None, source_id=None, evidence_id=None,
               observed_at='2026-10-24T12:01:00Z'):
    return normalize_wazuh_invalid_user(
        sample() if record is None else record,
        case_id=case_id or str(uuid4()), source_id=source_id or str(uuid4()),
        evidence_id=evidence_id or str(uuid4()), evidence_digest='a' * 64,
        observed_at=observed_at,
    )


def test_projection_is_explicitly_unverified_and_does_not_expose_raw_log_identifiers():
    row=normalized()
    assert row['schema_version'] == VERSION
    assert row['source_product'] == 'wazuh'
    assert row['source_product_version'] == '4.14.9'
    assert row['category'] == 'authentication_failure_invalid_user'
    assert row['reported_event_time'] == '2026-10-24T12:00:00.123000Z'
    assert row['source_authenticated'] is False
    assert row['source_bytes_verified'] is False
    assert row['external_actions_authorized'] is False
    assert validate_event(deepcopy(row)) == row
    assert 'generated-account' not in str(row)
    assert '192.0.2.10' not in str(row)
    assert '/var/log/generated/auth.log' not in str(row)


def test_repeat_candidates_preserve_distinct_evidence_copies():
    case,source=str(uuid4()),str(uuid4())
    first=normalized(case_id=case,source_id=source)
    second=normalized(case_id=case,source_id=source)
    report=review_source_events([first,second])
    assert report['event_count'] == 2
    assert report['same_source_repeat_candidates'] == 1
    assert report['same_source_event_key_count'] == 1
    assert report['same_source_identity_conflict_groups'] == 0
    assert report['evidence_copy_count'] == 2
    assert report['cross_source_event_deduplication_performed'] is False
    assert report['independent_corroboration_established'] is False


def test_conflicting_same_source_native_id_is_retained_not_silently_deduped():
    case,source=str(uuid4()),str(uuid4())
    first=normalized(case_id=case,source_id=source)
    conflicting=sample()
    conflicting['full_log']=conflicting['full_log'].replace('generated-account','different-account')
    second=normalized(conflicting,case_id=case,source_id=source)
    result=review_source_events([first,second])
    assert result['same_source_repeat_candidates'] == 0
    assert result['same_source_identity_conflict_groups'] == 1
    assert result['attack_status'] == 'unknown'


def test_cross_source_time_coincidence_does_not_merge_identifiers_or_corroborate():
    case=str(uuid4())
    rows=[normalized(case_id=case),normalized(case_id=case)]
    result=review_source_events(rows)
    assert result['source_count'] == 2
    assert result['same_source_event_key_count'] == 2
    assert result['cross_source_300s_coincidence_pairs'] == 1
    assert result['cross_source_identity_join_performed'] is False
    assert not result['independent_corroboration_established']
    assert result['model_used'] is False
    assert not result['external_actions_authorized']


def test_future_reported_time_surfaces_clock_uncertainty():
    row=normalized(observed_at='2026-10-24T11:00:00Z')
    report=review_source_events([row])
    assert report['event_clocks_ahead_of_observation_count'] == 1
    assert report['source_clock_verified'] is False


def test_all_claimed_case_scopes_must_match():
    with pytest.raises(UnsupportedSourceEvent):
        review_source_events([normalized(),normalized()])
    assert review_source_events([normalized()])['event_count'] == 1


@pytest.mark.parametrize('key,value',[
    ('source_product','splunk'),('source_product_version','unreviewed-2026'),
    ('adapter_version','unknown'),('source_authenticated',True),
    ('external_actions_authorized',True),('source_bytes_verified',True),
    ('category','confirmed_intrusion'),('reported_event_time','not-a-time'),
    ('evidence_digest','a'*63),('native_event_id','attacker supplied URL'),
])
def test_invalid_source_semantics_fail_closed(key,value):
    row=normalized()
    row[key]=value
    with pytest.raises(UnsupportedSourceEvent):
        validate_event(row)
    with pytest.raises(UnsupportedSourceEvent):
        review_source_events([row])


def test_unknown_keys_and_malformed_native_wazuh_are_rejected():
    row=normalized()
    row['instructions']='run remote shell'
    with pytest.raises(UnsupportedSourceEvent):
        validate_event(row)
    record=sample()
    record['data']['unexpected']='ignore safety'
    with pytest.raises(UnsupportedSourceEvent):
        normalized(record)
    record=sample()
    record['rule_id']='9999'
    with pytest.raises(UnsupportedSourceEvent):
        normalized(record)


def test_bounded_batch_size_and_record_count_are_enforced():
    with pytest.raises(UnsupportedSourceEvent):
        review_source_events([])
    row=normalized()
    with pytest.raises(UnsupportedSourceEvent):
        review_source_events([row]*129)
    report=review_source_events([row]*128)
    assert report['event_count'] == 128
    assert report['same_source_repeat_candidates'] == 127



def test_normalization_projects_to_existing_bounded_candidate_engine_without_verdict():
    from gabriel.identity.attack_patterns import investigate, normalized as validate_attack_document
    case,source=str(uuid4()),str(uuid4())
    rows=[]
    for i in range(10):
        record=sample()
        record['event_id']='1792800000.'+str(12345+i)
        rows.append(normalized(record,case_id=case,source_id=source))
    document=project_attack_pattern_document(rows,as_of='2026-10-24T12:10:00Z',
        missing_sources=['process','network','file','kernel','boot'])
    assert len(validate_attack_document(document,case))==10
    report=investigate(document,case)
    assert report['unique_event_count']==10
    assert any(f['family']=='brute_force' for f in report['findings'])
    assert not report['quality_qualified']
    assert not report['live_detection_accepted']
    assert not report['external_actions_authorized']
    assert all(f['status']=='suspected_requires_review' and not f['source_verified']
        for f in report['findings'])


def test_projection_refuses_conflicting_event_id_and_cross_case_sources():
    case,source=str(uuid4()),str(uuid4())
    first=normalized(case_id=case,source_id=source)
    other=sample()
    other['full_log']=other['full_log'].replace('generated-account','other-generated-account')
    conflicting=normalized(other,case_id=case,source_id=source)
    with pytest.raises(UnsupportedSourceEvent):
        project_attack_pattern_document([first,conflicting],
            as_of='2026-10-24T12:10:00Z',missing_sources=[])
    with pytest.raises(UnsupportedSourceEvent):
        project_attack_pattern_document([first,normalized()],
            as_of='2026-10-24T12:10:00Z',missing_sources=[])


def test_projection_requires_explicit_bounded_source_gaps_and_snapshot_clock():
    row=normalized()
    with pytest.raises(UnsupportedSourceEvent):
        project_attack_pattern_document([row],as_of='2026-10-24T11:00:00Z',missing_sources=[])
    for gaps in ([ 'unknown_sensor' ], ['network','network'], ['process'] * 7):
        with pytest.raises(UnsupportedSourceEvent):
            project_attack_pattern_document([row],
                as_of='2026-10-24T12:10:00Z',missing_sources=gaps)
    projection=project_attack_pattern_document([row],as_of='2026-10-24T12:10:00Z',
        missing_sources=['authentication'])
    assert projection['missing_sources']==['authentication']
    assert projection['events'][0]['authorization']=='unknown'



def test_projection_stays_within_persisted_attack_review_source_budget():
    case,source=str(uuid4()),str(uuid4())
    records=[]
    for i in range(33):
        record=sample()
        record['event_id']='1792800000.'+str(11000+i)
        records.append(normalized(record,case_id=case,source_id=source))
    assert review_source_events(records)['event_count']==33
    with pytest.raises(UnsupportedSourceEvent):
        project_attack_pattern_document(records,
            as_of='2026-10-24T12:10:00Z',missing_sources=[])
