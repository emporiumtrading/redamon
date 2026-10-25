"""Metadata reports against actual PostgreSQL, custody and encrypted generated artifacts."""
from hashlib import sha256
import json
import secrets
from uuid import uuid4

import pytest

from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceError,canonical
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,IdentityUnavailable,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence,CONTENT,intake,audit_permission
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_observations_integration import browser,task,grant,payload,submit

pytestmark = pytest.mark.integration


def test_report_preserves_distinct_time_bases_and_never_claims_source_truth(tenant,cases,case,evidence):
    result = cases.case_report(tenant.token,case['id'])
    report = result['snapshot']
    assert result['digest']==sha256(canonical(report)).hexdigest()
    assert report['coverage']=='partial' and report['assessment']=='not_performed'
    assert report['content_integrity']=='not_checked'
    timeline = report['timeline']
    assert timeline==sorted(timeline,key=lambda event:(event['time'],event['id']))
    source = next(event for event in timeline if event['kind']=='source_event_claim')
    collection = next(event for event in timeline if event['kind']=='evidence_collected')
    assert source['time_basis']=='unverified_supplied' and source['time'].startswith('2026-01-01')
    assert collection['time_basis']=='server_recorded' and collection['time']>source['time']
    assert report['evidence'][0]['custody_chain']=='validated'
    assert not report['evidence'][0]['source_verified']
    raw = json.dumps(result)
    for secret in (CONTENT,tenant.token,tenant.db.app,str(cases.store.root),cases.store.keys.active):
        assert secret not in raw
    assert 'object_id' not in raw and 'key_id' not in raw
    fresh = CaseService(tenant.db.app,cases.store).case_report(tenant.token,case['id'])['snapshot']
    assert fresh['timeline']==timeline and fresh['evidence']==report['evidence']
    with owner_connection(tenant.db) as conn:
        assert conn.execute("SELECT count(*) AS n FROM gabriel_identity.audit_events WHERE organization_id=%s AND target_id=%s AND event='case.report_generated'",(tenant.org,case['id'])).fetchone()['n']==2


def test_identical_artifacts_remain_separate_not_independent_corroboration(tenant,cases,case,evidence):
    other = intake(tenant,cases,case)
    report = cases.case_report(tenant.token,case['id'])['snapshot']
    assert len(report['evidence'])==2
    duplicate, = report['identical_artifacts']
    assert set(duplicate['evidence_ids'])=={str(evidence['id']),str(other['id'])}
    assert duplicate['meaning']=='identical_bytes_not_independent_corroboration'


def test_empty_report_is_explicitly_partial(tenant,cases,case):
    report = cases.case_report(tenant.token,case['id'])['snapshot']
    assert not report['evidence'] and not report['browser_observations'] and not report['identical_artifacts']
    assert len(report['timeline'])==1 and report['assessment']=='not_performed'


def test_browser_report_retains_partial_coverage_and_unverified_client_clock(tenant,browser,case,grant,payload):
    receipt = submit(tenant,browser,grant,payload)
    report = browser.case_report(tenant.token,case['id'])['snapshot']
    observed, = report['browser_observations']
    assert observed['evidence_id']==str(receipt['evidence_id']) and observed['state']=='captured'
    assert observed['coverage']=='partial' and not observed['source_verified']
    assert observed['visibility']==payload['visibility']
    event = next(event for event in report['timeline'] if event['kind']=='browser_observation_claim')
    assert event['time_basis']=='unverified_client_clock'
    assert grant.token not in json.dumps(report) and 'token_digest' not in json.dumps(report)


def test_foreign_tenant_and_service_credential_cannot_generate_report(tenant,cases,case,evidence):
    password = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Generated foreign report tenant','owner',password)
    token = cases.login(org,'owner',password).token
    with pytest.raises(AccessDenied): cases.case_report(token,case['id'])
    workers = ServiceIdentityService(tenant.db.app)
    task = workers.create_task(tenant.token,'Generated report denial',['evidence.hash'])
    worker = workers.issue_service(tenant.token,'Generated worker',task['id'],['evidence.hash'])
    with pytest.raises(AuthenticationDenied): cases.case_report(worker.token,case['id'])


def test_viewer_metadata_access_and_immediate_revocation(tenant,cases,case,evidence):
    password = secrets.token_urlsafe(24)
    user = cases.create_member(tenant.token,'report-viewer',password,'viewer')
    token = cases.login(tenant.org,'report-viewer',password).token
    assert cases.case_report(token,case['id'])['snapshot']['evidence'][0]['id']==str(evidence['id'])
    with pytest.raises(AccessDenied): cases.read_evidence(token,evidence['id'])
    cases.set_membership(tenant.token,user,'viewer',False)
    with pytest.raises(AuthenticationDenied): cases.case_report(token,case['id'])


def test_corrupt_custody_is_not_reported_as_valid(tenant,cases,case,evidence):
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.custody_events SET event_hash=repeat('0',64) WHERE organization_id=%s AND evidence_id=%s AND sequence=2",(tenant.org,evidence['id']))
    with pytest.raises(EvidenceError,match='custody_invalid'): cases.case_report(tenant.token,case['id'])


def test_audit_outage_denies_report_without_content_access(tenant,cases,case,evidence):
    audit_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): cases.case_report(tenant.token,case['id'])
    finally:
        audit_permission(tenant,True)
    assert [event['event'] for event in cases.custody(tenant.token,evidence['id'])]==['acquisition_intent','acquired']


def test_report_bound_denies_instead_of_silent_truncation(tenant,cases,case,evidence,monkeypatch):
    monkeypatch.setattr('gabriel.identity.reports.MAX_TIMELINE',2)
    with pytest.raises(AccessDenied,match='case_report_limit'): cases.case_report(tenant.token,case['id'])
