"""Real scoped captures and frozen multi-tab sources; provider replies are generated."""
from datetime import datetime,timezone
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


def capture(tenant,cases,case,context,tab=1,sequence=1,existing=None):
    item=existing or enrollment(tenant,cases,case,context,tab=tab,monitoring_approved=True)
    browser,lease,scope,_,_=item
    if existing is None:browser.connect_browser(lease.token,scope)
    payload=dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=sequence,context=scope,
        observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',client_minimized=True,
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
        with owner_connection(tenant.db) as conn:conn.execute("UPDATE gabriel_identity.browser_observations SET observed_at=clock_timestamp()-interval '121 seconds' WHERE lease_id=%s",(item[1].id,))
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
    assert hermes.start(cases,supervision['vault'],analyst.token,case['id'],request,prepared['facts_evidence_id'],approved=True,lease_ids=ids)==result
    assert len(supervision['posts'])==6


def test_second_tab_change_during_provider_call_stops_without_child_dispatch(tenant,cases,case,context,supervision):
    analyst=SimpleNamespace(db=tenant.db,token=supervision['token'])
    one,_=capture(analyst,cases,case,context,1);two,_=capture(analyst,cases,case,context,2)
    ids=[str(one[1].id),str(two[1].id)]
    prepared=browser_hermes.prepare(cases,analyst.token,case['id'],ids)
    supervision['hermes_client'].hermes_callback=lambda:capture(analyst,cases,case,context,2,2,two)
    with pytest.raises(AccessDenied):hermes.start(cases,supervision['vault'],analyst.token,case['id'],uuid4(),prepared['facts_evidence_id'],approved=True,lease_ids=ids)
    assert len(supervision['posts'])==1
