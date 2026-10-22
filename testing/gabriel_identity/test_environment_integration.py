"""Source-backed historical environment views with explicit content authority."""
from copy import deepcopy
import json
import secrets
from uuid import uuid4

import pytest

from gabriel.identity.evidence_store import EvidenceError
from gabriel.identity.service import AccessDenied,IdentityUnavailable,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,row_and_file,audit_permission
from testing.gabriel_identity.test_attack_pattern_runs_integration import intake

pytestmark=pytest.mark.integration


@pytest.fixture
def reviewed(tenant,cases,case,evidence):
    document,holder=intake(tenant,cases,case,evidence)
    run=cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    return document,holder,run


def test_empty_profile_preserves_security_and_compliance_unknowns(tenant,cases,case):
    result=cases.environment_profile(tenant.token,case['id'])['profile']
    assert result['status']=='no_supported_snapshot' and result['snapshot'] is None
    assert result['assets']==result['identities']==result['controls']==[]
    assert not result['security_effectiveness_validated'] and not result['compliance_assessed']
    assert not result['live_coverage_verified'] and not result['source_bytes_checked']


def test_metadata_and_explicit_content_views_keep_source_boundaries(tenant,cases,case,evidence,reviewed):
    document,holder,run=reviewed
    metadata=cases.environment_profile(tenant.token,case['id'])['profile']
    assert metadata['status']=='metadata_only' and not metadata['identifiers_included']
    assert metadata['snapshot']['unique_event_count']==10
    assert document['events'][0]['actor_id'] not in json.dumps(metadata)
    one=cases.environment_profile(tenant.token,case['id'],include_identifiers=True)
    profile=one['profile']
    assert profile['source_bytes_checked'] and profile['identifiers_included']
    assert len(profile['assets'])==2 and len(profile['identities'])==1 and len(profile['relationships'])==1
    assert profile['identities'][0]['event_count']==10 and profile['relationships'][0]['event_count']==10
    assert all(row['evidence_state']=='reported' and row['owner'] is None and not row['source_verified'] for row in profile['assets'])
    assert profile['identities'][0]['references']==['evidence/'+str(evidence['id'])]
    assert profile['snapshot']['input_evidence_id']==str(holder['id']) and profile['snapshot']['review_id']==run['id']
    assert cases.environment_profile(tenant.token,case['id'],include_identifiers=True)==one


def test_forwarded_duplicates_do_not_inflate_environment_counts(tenant,cases,case,evidence):
    document,holder=intake(tenant,cases,case,evidence)
    document['events']+=deepcopy(document['events'])
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(document),'Generated forwarded event snapshot',approved=True)
    cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    profile=cases.environment_profile(tenant.token,case['id'],include_identifiers=True)['profile']
    assert profile['snapshot']['unique_event_count']==10 and profile['snapshot']['forwarded_duplicate_count']==10
    assert profile['identities'][0]['event_count']==10 and profile['relationships'][0]['event_count']==10


@pytest.mark.parametrize('target',['source','input','receipt'])
def test_invalid_latest_source_or_receipt_denies_content_without_old_snapshot_fallback(tenant,cases,case,evidence,reviewed,target):
    _,holder,run=reviewed
    if target=='receipt':
        with owner_connection(tenant.db) as conn:
            conn.execute('UPDATE gabriel_identity.attack_pattern_runs SET result_digest=%s WHERE organization_id=%s AND id=%s',('0'*64,tenant.org,run['id']))
    else:
        _,path=row_and_file(tenant,cases,evidence if target=='source' else holder)
        path.chmod(0o600);path.write_bytes(b'generated-corrupt-environment-source')
    with pytest.raises((AccessDenied,EvidenceError)):
        cases.environment_profile(tenant.token,case['id'],include_identifiers=True)


def test_viewer_metadata_is_allowed_but_content_and_foreign_case_are_denied(tenant,cases,case,reviewed):
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'generated-profile-viewer',password,'viewer')
    viewer=cases.login(tenant.org,'generated-profile-viewer',password).token
    assert cases.environment_profile(viewer,case['id'])['profile']['status']=='metadata_only'
    with pytest.raises(AccessDenied): cases.environment_profile(viewer,case['id'],include_identifiers=True)
    other,_=provision_organization(tenant.db.owner,'Generated foreign environment org','owner',password)
    foreign=cases.login(other,'owner',password).token
    with pytest.raises(AccessDenied): cases.environment_profile(foreign,case['id'])


def test_future_supplied_clock_and_omitted_older_snapshots_remain_visible(tenant,cases,case,evidence,reviewed):
    document,_,_=reviewed;document=deepcopy(document);document['as_of']='2099-01-01T00:00:00Z'
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(document),'Generated future clock snapshot',approved=True)
    cases.run_attack_review(tenant.token,case['id'],uuid4(),holder['id'])
    profile=cases.environment_profile(tenant.token,case['id'],include_identifiers=True)['profile']
    assert profile['source_clock_ahead'] and profile['older_snapshots_omitted']
    assert not profile['current_environment_verified']


def test_audit_failure_blocks_profile_and_rolls_back_source_accesses(tenant,cases,case,evidence,reviewed):
    with owner_connection(tenant.db) as conn:
        before=conn.execute('SELECT count(*) AS n FROM gabriel_identity.custody_events WHERE organization_id=%s',(tenant.org,)).fetchone()['n']
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.environment_profile(tenant.token,case['id'],include_identifiers=True)
    finally: audit_permission(tenant,True)
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.custody_events WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==before
