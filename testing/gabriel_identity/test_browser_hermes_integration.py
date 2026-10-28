"""Real scoped captures and frozen multi-tab sources; provider replies are generated."""
from datetime import datetime,timedelta,timezone
import json
from types import SimpleNamespace
from uuid import uuid4
import pytest

from gabriel.identity import browser_hermes,hermes_supervisor as hermes
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,connection
from testing.gabriel_identity.test_hermes_supervisor_integration import native_runtime,supervision
from testing.gabriel_identity.test_specialist_agents_integration import setup
from testing.gabriel_identity.test_vault_integration import fresh_ring
from testing.gabriel_identity.test_identity_integration import tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_monitoring_integration import database,enrollment

pytestmark=pytest.mark.integration


def capture(tenant,cases,case,context,tab=1,sequence=1,existing=None,observed_offset=0):
    item=existing or enrollment(tenant,cases,case,context,tab=tab,monitoring_approved=True)
    browser,lease,scope,_,_=item
    if existing is None:browser.connect_browser(lease.token,scope)
    payload=dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=sequence,context=scope,
        observed_at=(datetime.now(timezone.utc)+timedelta(seconds=observed_offset)).isoformat(),visibility='partial',client_minimized=True,
        content='Generated dashboard\nGenerated lab account\nNo semantic parser is admitted for this page.')
    result=browser.observe_browser(tenant.token,lease.token,payload)
    return item,result


def test_partial_tabs_prepare_idempotent_receipt_facts_without_text_export(tenant,cases,case,context):
    one,r1=capture(tenant,cases,case,context,1);two,r2=capture(tenant,cases,case,context,2)
    ids=[str(one[1].id),str(two[1].id)]
    prepared=browser_hermes.prepare(cases,tenant.token,case['id'],ids)
    assert prepared==browser_hermes.prepare(cases,tenant.token,case['id'],list(reversed(ids)))
    assert prepared['coverage']=='partial' and not prepared['semantic_telemetry_parsed'] and not prepared['visible_text_exported']
    document=json.loads(cases.read_evidence(tenant.token,prepared['facts_evidence_id']).reveal())
    assert len(document['facts'])==4 and {f['type'] for f in document['facts']}=={'artifact','coverage'}
    assert {f['evidence_id'] for f in document['facts']}=={str(r1['evidence_id']),str(r2['evidence_id'])}
    assert 'Generated dashboard' not in json.dumps(document)
    with connection(cases._dsn) as conn:
        p=cases._human(conn,tenant.token)
        assert hermes.check_tabs(cases,conn,p,tenant.token,case['id'],ids,document)==ids
        document['facts'][0]['data']={'state':'available'}
        with pytest.raises(AccessDenied):hermes.check_tabs(cases,conn,p,tenant.token,case['id'],ids,document)


@pytest.mark.parametrize('change',['disconnect','new_capture','stale'])
def test_frozen_snapshot_cannot_survive_scope_or_freshness_change(tenant,cases,case,context,change):
    item,_=capture(tenant,cases,case,context)
    ids=[str(item[1].id)];prepared=browser_hermes.prepare(cases,tenant.token,case['id'],ids)
    document=json.loads(cases.read_evidence(tenant.token,prepared['facts_evidence_id']).reveal())
    if change=='disconnect':item[0].disconnect_browser(item[1].token)
    elif change=='new_capture':capture(tenant,cases,case,context,sequence=2,existing=item)
    else:
        with owner_connection(tenant.db) as conn:conn.execute("UPDATE gabriel_identity.browser_observation_receipts SET created_at=clock_timestamp()-interval '121 seconds' WHERE organization_id=%s AND observation_id IN (SELECT id FROM gabriel_identity.browser_observations WHERE lease_id=%s)",(tenant.org,item[1].id))
    with connection(cases._dsn) as conn:
        p=cases._human(conn,tenant.token)
        with pytest.raises(AccessDenied):hermes.check_tabs(cases,conn,p,tenant.token,case['id'],ids,document)


def test_invalid_or_unowned_selection_is_denied(tenant,cases,case):
    for selection in [[],[uuid4()]*2,[uuid4() for _ in range(9)]]:
        with pytest.raises(InvalidIdentityInput):browser_hermes.prepare(cases,tenant.token,case['id'],selection)
    with pytest.raises(AccessDenied):browser_hermes.prepare(cases,tenant.token,case['id'],[uuid4()])


def test_two_partial_tabs_run_native_hermes_and_personal_specialists_then_replay(tenant,cases,case,context,supervision):
    analyst=SimpleNamespace(db=tenant.db,token=supervision['token'])
    one,_=capture(analyst,cases,case,context,1);two,_=capture(analyst,cases,case,context,2)
    ids=[str(one[1].id),str(two[1].id)]
    prepared=browser_hermes.prepare(cases,analyst.token,case['id'],ids)
    supervision['hermes_client'].selected=['telemetry_health','dfir_evidence']
    request=uuid4()
    result=hermes.start(cases,supervision['vault'],analyst.token,case['id'],request,prepared['facts_evidence_id'],approved=True,lease_ids=ids)
    assert result['state']=='hermes_completed_requires_review' and len(supervision['posts'])==6
    assert result['scope']=='selected_tabs_and_bound_typed_facts'
    assert result['delegated_roles']==['telemetry_health','dfir_evidence']
    assert 'Generated dashboard' not in json.dumps(supervision['posts'])
    replay=hermes.start(cases,supervision['vault'],analyst.token,case['id'],request,prepared['facts_evidence_id'],approved=True,lease_ids=ids)
    for key in ('run_id','state','delegated_roles','plan_answer_evidence_id','report_answer_evidence_id'):
        assert replay[key]==result[key]
    for original,repeated in zip(result['agents'],replay['agents']):
        assert repeated['result']['job_id']==original['result']['job_id']
        assert [s['answer_evidence_id'] for s in repeated['result']['steps']]==[s['answer_evidence_id'] for s in original['result']['steps']]
        assert all(s['historical'] for s in repeated['result']['steps'])
    assert len(supervision['posts'])==6


def test_second_tab_change_during_provider_call_stops_without_child_dispatch(tenant,cases,case,context,supervision):
    analyst=SimpleNamespace(db=tenant.db,token=supervision['token'])
    one,_=capture(analyst,cases,case,context,1);two,_=capture(analyst,cases,case,context,2)
    ids=[str(one[1].id),str(two[1].id)]
    prepared=browser_hermes.prepare(cases,analyst.token,case['id'],ids)
    supervision['hermes_client'].hermes_callback=lambda:capture(analyst,cases,case,context,2,2,two)
    with pytest.raises(AccessDenied):hermes.start(cases,supervision['vault'],analyst.token,case['id'],uuid4(),prepared['facts_evidence_id'],approved=True,lease_ids=ids)
    assert len(supervision['posts'])==1


def test_receipt_assertion_time_does_not_inherit_client_clock_skew():
    from gabriel.identity.cases import iso
    from gabriel.identity.specialist_analysis import validate_document
    received=datetime.now(timezone.utc);case_id=uuid4()
    observation=dict(id=uuid4(),received_at=received,observed_at=received+timedelta(seconds=3))
    artifact=dict(id=uuid4(),digest='a'*64)
    facts=browser_hermes.capture_facts(observation,artifact)
    assert all(f['event_time']==iso(received) for f in facts)
    document=dict(version='specialist-facts-v1',case_id=str(case_id),as_of=iso(received),facts=facts)
    assert validate_document(document,case_id)==document


def test_future_client_observation_is_not_laundered_into_fresh_receipt_facts(tenant,cases,case,context):
    item,_=capture(tenant,cases,case,context,observed_offset=4)
    with pytest.raises(AccessDenied,match='hermes_fresh_tab_read_required'):
        browser_hermes.prepare(cases,tenant.token,case['id'],[str(item[1].id)])


def test_completed_navigation_requires_new_bound_capture_before_hermes(tenant,cases,case,context):
    from urllib.parse import urlsplit
    from gabriel.identity.browser_navigation import OPERATOR_PAGES
    item,_=capture(tenant,cases,case,context)
    browser,lease,scope,_,_=item
    ids=[str(lease.id)];prepared=browser_hermes.prepare(cases,tenant.token,case['id'],ids)
    original=json.loads(cases.read_evidence(tenant.token,prepared['facts_evidence_id']).reveal())
    parsed=urlsplit(scope['page_url']);destination=parsed.scheme+'://'+parsed.netloc+'/alerts'
    browser.grant_navigation(tenant.token,lease.token,uuid4(),OPERATOR_PAGES,[destination])
    intent=browser.prepare_navigation(tenant.token,lease.token,uuid4(),destination)
    updated=dict(scope,page_url=destination,document_id=str(uuid4()))
    browser.complete_navigation(tenant.token,lease.token,intent['id'],updated)
    with pytest.raises(AccessDenied,match='post_navigation_capture_required'):
        browser_hermes.prepare(cases,tenant.token,case['id'],ids)
    renewed=(browser,lease,updated,item[3],item[4])
    capture(tenant,cases,case,context,sequence=2,existing=renewed)
    fresh=browser_hermes.prepare(cases,tenant.token,case['id'],ids)
    assert fresh['facts_evidence_id']!=prepared['facts_evidence_id']
    with connection(cases._dsn) as conn:
        p=cases._human(conn,tenant.token)
        with pytest.raises(AccessDenied):hermes.check_tabs(cases,conn,p,tenant.token,case['id'],ids,original)
