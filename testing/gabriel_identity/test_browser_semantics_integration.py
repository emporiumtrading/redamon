"""Actual scoped receipts, encrypted historical drafts and source-race rejection."""
from datetime import datetime,timezone
from copy import deepcopy
import json
from uuid import uuid4,uuid5
import pytest

from gabriel.identity import browser_semantics as semantics
from gabriel.identity.cases import iso
from gabriel.identity.service import AccessDenied,AuthenticationDenied,connection,provision_organization
from testing.gabriel_identity.test_browser_monitoring_integration import database,enrollment
from testing.gabriel_identity.test_identity_integration import tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_semantics import page

pytestmark=pytest.mark.integration


@pytest.fixture
def scoped(tenant,cases,case,context):
    browser,lease,scope,gateway,ticket=enrollment(tenant,cases,case,context)
    gateway.dispatch('claim',dict(ticket=ticket,context=scope),None)
    return dict(browser=browser,lease=lease,scope=scope,gateway=gateway)


def capture(tenant,scoped,sequence=1,document=None):
    body=dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=sequence,context=scoped['scope'],
        observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',client_minimized=True,
        content=json.dumps(document or page(scoped['scope']['account_label']),ensure_ascii=False))
    return scoped['browser'].observe_browser(tenant.token,scoped['lease'].token,body)


def review(scoped,observed):
    return scoped['gateway'].dispatch('structure-review',dict(context=scoped['scope'],observation_id=str(observed['observation_id'])),
        'Bearer '+scoped['lease'].token)


def test_real_receipt_encrypted_idempotent_draft_and_historical_view_after_stop(tenant,cases,scoped):
    observed=capture(tenant,scoped);first=review(scoped,observed);second=review(scoped,observed)
    assert first==second and first['state']=='unreviewed_historical_structure' and first['model_calls']==0
    assert first['current_semantic_assessment'] is False and first['incident_facts_admitted'] is False
    value=semantics.historical(cases,tenant.token,first['draft_evidence_id'])
    assert value['source']['observation_id']==str(observed['observation_id'])
    assert value['source']['evidence_id']==str(observed['evidence_id'])
    assert value['source']['evidence_digest']==cases.read_evidence(tenant.token,observed['evidence_id']).metadata['digest']
    assert value['structure']==page(scoped['scope']['account_label'])
    assert all(b'Generated security records' not in path.read_bytes() for path in cases.store.root.rglob('*') if path.is_file())
    scoped['browser'].disconnect_browser(scoped['lease'].token)
    assert semantics.historical(cases,tenant.token,first['draft_evidence_id'])==value
    with pytest.raises((AccessDenied,AuthenticationDenied)):review(scoped,observed)
    with connection(cases._dsn) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_dispatch_claims WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==0


@pytest.mark.parametrize('change',['new_capture','prepared','old_receipt','account','foreign_observation','upload_id'])
def test_latest_current_original_capture_required(tenant,cases,case,context,scoped,change):
    doc=page(scoped['scope']['account_label'])
    if change=='account':doc['account']['text']='Other generated scope label'
    observed=capture(tenant,scoped,document=doc)
    if change=='new_capture':capture(tenant,scoped,sequence=2)
    if change=='prepared':
        original=scoped['browser']._finish_acquisition
        scoped['browser']._finish_acquisition=lambda *args,**kw:(_ for _ in ()).throw(RuntimeError('generated interruption'))
        try:
            with pytest.raises(RuntimeError):capture(tenant,scoped,sequence=2)
        finally:scoped['browser']._finish_acquisition=original
    if change=='old_receipt':
        with owner_connection(tenant.db) as conn:
            conn.execute("UPDATE gabriel_identity.browser_observation_receipts SET created_at=clock_timestamp()-interval '121 seconds' WHERE organization_id=%s AND observation_id=%s",(tenant.org,observed['observation_id']))
    if change=='foreign_observation':
        browser,lease,scope,_,_=enrollment(tenant,cases,case,context,tab=2)
        browser.connect_browser(lease.token,scope)
        observed=browser.observe_browser(tenant.token,lease.token,dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=1,
            context=scope,observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',client_minimized=True,content=json.dumps(page(scope['account_label']))))
    if change=='upload_id':
        uploaded=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(doc),'Browser approved observation',approved=True)
        observed=dict(observed,observation_id=uploaded['id'])
    with pytest.raises((AccessDenied,semantics.InvalidIdentityInput)):review(scoped,observed)


def test_source_changes_during_storage_return_no_success_or_current_assessment(tenant,cases,scoped,monkeypatch):
    observed=capture(tenant,scoped)
    acquire=scoped['browser'].acquire
    def changed(*args,**kwargs):
        result=acquire(*args,**kwargs)
        if args[4]==semantics.LABEL:capture(tenant,scoped,sequence=2)
        return result
    monkeypatch.setattr(scoped['browser'],'acquire',changed)
    with pytest.raises(AccessDenied,match='latest_capture'):review(scoped,observed)
    entries=[r for r in cases.get_case(tenant.token,scoped['browser'].get_browser_lease(tenant.token,scoped['lease'].id)['case_id'])['evidence'] if r['source_label']==semantics.LABEL]
    assert len(entries)==1
    retained=semantics.historical(cases,tenant.token,entries[0]['id'])
    assert retained['status']=='unreviewed_historical_structure' and retained['counts']['event_count']=='unknown'
    assert retained['incident_facts_admitted'] is False


def test_arbitrary_same_label_upload_cannot_masquerade_as_a_bound_draft(tenant,cases,case,scoped):
    observed=capture(tenant,scoped);result=review(scoped,observed)
    raw=cases.read_evidence(tenant.token,result['draft_evidence_id']).reveal().decode()
    uploaded=cases.acquire(tenant.token,case['id'],uuid4(),raw,semantics.LABEL,approved=True,parent_id=observed['evidence_id'])
    with pytest.raises(AccessDenied,match='historical_binding'):semantics.historical(cases,tenant.token,uploaded['id'])
    viewer_password='Generated-structure-viewer-long-password'
    cases.create_member(tenant.token,'structure-viewer',viewer_password,'viewer')
    viewer=cases.login(tenant.org,'structure-viewer',viewer_password).token
    with pytest.raises(AccessDenied):semantics.historical(cases,viewer,result['draft_evidence_id'])
    org,_=provision_organization(tenant.db.owner,'Other generated structure organization','owner','Generated-other-structure-password')
    other=cases.login(org,'owner','Generated-other-structure-password').token
    with pytest.raises(AccessDenied):semantics.historical(cases,other,result['draft_evidence_id'])


def test_successful_navigation_without_new_capture_cannot_relabel_old_page(tenant,cases,case,scoped):
    from urllib.parse import urlsplit
    from gabriel.identity.browser_navigation import OPERATOR_PAGES
    observed=capture(tenant,scoped);first=review(scoped,observed)
    parsed=urlsplit(scoped['scope']['page_url']);destination=parsed.scheme+'://'+parsed.netloc+'/alerts'
    browser=scoped['browser'];lease=scoped['lease']
    browser.grant_navigation(tenant.token,lease.token,uuid4(),OPERATOR_PAGES,[destination])
    intent=browser.prepare_navigation(tenant.token,lease.token,uuid4(),destination)
    updated=dict(scoped['scope'],page_url=destination,document_id=str(uuid4()))
    browser.complete_navigation(tenant.token,lease.token,intent['id'],updated)
    with pytest.raises(AccessDenied,match='post_navigation_capture_required'):
        semantics.process(browser,tenant.token,lease.token,updated,observed['observation_id'])
    assert semantics.historical(cases,tenant.token,first['draft_evidence_id'])['source']['evidence_id']==str(observed['evidence_id'])
    scoped['scope']=updated
    fresh=capture(tenant,scoped,sequence=2)
    result=semantics.process(browser,tenant.token,lease.token,updated,fresh['observation_id'])
    assert result['source_evidence_id']!=first['source_evidence_id']


def test_forged_request_digest_in_preempted_deterministic_draft_is_rejected(tenant,cases,case,scoped):
    observed=capture(tenant,scoped)
    row=scoped['browser'].get_browser_observation(tenant.token,observed['observation_id'])
    evidence=cases.read_evidence(tenant.token,observed['evidence_id'])
    source=dict(observation_id=str(row['id']),evidence_id=str(observed['evidence_id']),evidence_digest=evidence.metadata['digest'],
        capture_received_at=iso(observed['created_at']),client_observed_at=iso(row['observed_at']),capture_request_digest='0'*64,
        receipt_sha256=semantics.digest({k:str(observed[k]) for k in ('observation_id','evidence_id','completed_by','mode','created_at')}))
    value=semantics.draft(page(scoped['scope']['account_label']),source)
    uploaded=cases.acquire(tenant.token,case['id'],uuid5(row['id'],semantics.DRAFT),json.dumps(value),semantics.LABEL,
        approved=True,parent_id=observed['evidence_id'],redaction_state='user_declared_redacted')
    with pytest.raises(AccessDenied,match='historical_binding'):semantics.historical(cases,tenant.token,uploaded['id'])
