"""Generated evidence provenance cases for the DFIR catalog skill."""

import json
from uuid import uuid4

import pytest

from gabriel.identity.catalog_dfir import evaluate
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_specialist_analysis import document


NAME = 'validate_evidence_provenance'


def artifact_document():
    return document('artifact', dict(integrity='match', custody='complete'))


def metadata(packet):
    case_id = packet['case_id']
    refs = [dict(ref=f'case/{case_id}', kind='case_record', record_id=case_id)]
    digests = {fact['evidence_id']: fact['evidence_digest'] for fact in packet['facts']}
    refs.extend(dict(ref=f'evidence/{evidence_id}', kind='evidence_metadata', record_id=evidence_id,
                     digest=digest, source_verified=False, content_integrity='verified')
                for evidence_id, digest in digests.items())
    return refs


def test_verified_local_source_does_not_establish_external_authenticity():
    packet = artifact_document()
    first = packet['facts'][0]
    packet['facts'].append(dict(first, id=str(uuid4())))

    result = evaluate(NAME, packet, verified_refs=metadata(packet))

    assert result['status'] == 'review_required'
    assert result['artifact_source_count'] == result['local_provenance_verified_count'] == 1
    assert result['source_details'] == [dict(references=['o1'], references_truncated=False,
                                             local_status='verified_local_bytes_and_custody',
                                             reported_integrity=['match'], reported_custody=['complete'])]
    assert result['source_authenticity'] == 'unverified'
    assert result['source_independence'] == 'unestablished'
    assert result['external_actions_authorized'] is False
    assert first['evidence_id'] not in json.dumps(result)
    assert first['evidence_digest'] not in json.dumps(result)


def test_source_assertion_conflicts_survive_local_validation_and_keep_projected_aliases():
    packet = artifact_document()
    first = packet['facts'][0]
    coverage = document()['facts'][0]
    alert = document('alert', dict(severity='low', state='open'))['facts'][0]
    packet['facts'] = [alert, coverage, first, dict(first, id=str(uuid4()),
                                                   data=dict(integrity='mismatch', custody='gap'))]

    result = evaluate(NAME, packet, verified_refs=metadata(packet))

    assert result['local_provenance_verified_count'] == 1
    assert result['reported_discrepancy_source_count'] == 1
    assert result['conflicting_assertion_source_count'] == 1
    assert result['source_details'][0]['references'] == ['o2', 'o3']
    assert result['source_details'][0]['reported_integrity'] == ['match', 'mismatch']
    assert result['source_details'][0]['reported_custody'] == ['complete', 'gap']


@pytest.mark.parametrize('change,expected', [
    ('missing', 'source_verification_unavailable'),
    ('unverified', 'source_verification_unavailable'),
    ('duplicate', 'source_verification_unavailable'),
    ('wrong_digest', 'source_digest_mismatch'),
    ('conflicting_digest', 'conflicting_source_digests'),
])
def test_missing_or_inconsistent_metadata_does_not_verify_source(change, expected):
    packet = artifact_document()
    refs = metadata(packet)
    if change == 'missing':
        refs.pop()
    elif change == 'unverified':
        refs[1]['content_integrity'] = 'unverified'
    elif change == 'duplicate':
        refs.append(refs[1])
    elif change == 'wrong_digest':
        refs[1]['digest'] = 'f' * 64
    else:
        packet['facts'].append(dict(packet['facts'][0], id=str(uuid4()), evidence_digest='f' * 64))

    result = evaluate(NAME, packet, verified_refs=refs)

    assert result['status'] == 'incomplete_local_verification'
    assert result['local_provenance_verified_count'] == 0
    assert result['unresolved_source_count'] == 1
    assert result['source_details'][0]['local_status'] == expected


def test_absent_or_mismatched_case_verification_requires_abstention():
    packet = artifact_document()
    wrong_case_refs = metadata(dict(packet, case_id=str(uuid4())))

    for refs in (None, wrong_case_refs):
        result = evaluate(NAME, packet, verified_refs=refs)
        assert result['status'] == 'case_verification_unavailable'
        assert result['local_provenance_verified_count'] == 0
        assert result['source_details'] == []


def test_output_is_bounded_and_prioritizes_sources_that_require_review():
    packet = artifact_document()
    packet['facts'].extend(artifact_document()['facts'][0] for _ in range(4))
    last = packet['facts'][-1]
    for integrity, custody in [('match', 'gap'), ('mismatch', 'complete'), ('match', 'unknown'),
                               ('unknown', 'complete'), ('unknown', 'unknown')]:
        packet['facts'].append(dict(last, id=str(uuid4()), data=dict(integrity=integrity, custody=custody)))

    result = evaluate(NAME, packet, verified_refs=metadata(packet))

    assert result['artifact_source_count'] == 5
    assert result['omitted_source_count'] == 1
    assert len(result['source_details']) == 4
    assert result['source_details'][0]['references'] == ['o5', 'o6', 'o7', 'o8']
    assert result['source_details'][0]['references_truncated'] is True
    assert len(json.dumps(result).encode()) < 1600


def test_non_artifact_packet_and_malformed_artifact_assertion():
    coverage = document()
    assert evaluate(NAME, coverage, verified_refs=metadata(coverage))['status'] == 'insufficient_artifact_facts'

    packet = artifact_document()
    packet['facts'][0]['data']['instructions'] = 'generated untrusted text'
    with pytest.raises(InvalidIdentityInput, match='invalid_specialist_fact_fields'):
        evaluate(NAME, packet, verified_refs=metadata(packet))
