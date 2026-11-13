"""Supervisor contracts and minimization; fixtures never qualify live models."""
from copy import deepcopy
from datetime import datetime,timezone
from io import BytesIO
from urllib.parse import urlencode
from uuid import uuid4

import pytest

from gabriel.identity import browser_hermes,hermes_supervisor as hermes
from gabriel.identity.model_protocol import ProbeError
from gabriel.identity.service import AccessDenied
from gabriel.identity.workbench import Workbench,selected_hermes_leases
from testing.gabriel_identity.test_specialist_analysis import document


def decision(actions):
    return dict(disposition='abstain',requested_actions=actions)


def test_required_hermes_has_own_exact_model_context_and_qualification():
    status=hermes.readiness()
    assert status['required'] and status['own_context'] and not status['model_enabled']
    assert status['model']=='openai/gpt-oss-120b'
    assert len(set(status['configuration_digests'].values()))==2
    assert hermes.configuration()['upstream']=='bf0203a794a07aac3ff764972ab9087baa4e4f4e'
    assert 'requested_actions must be empty' in hermes.prompt('report')


def test_projection_keeps_source_semantics_and_hides_private_identifiers():
    source=document('identity',dict(event='mfa_disabled',authorized='no'));before=deepcopy(source)
    prepared=hermes.project(source,'plan')
    wire=hermes.canonical(prepared['packet']).decode()
    for private in [source['case_id'],source['facts'][0]['id'],source['facts'][0]['evidence_id'],source['facts'][0]['entity_id']]:assert private not in wire
    assert prepared['packet']['eligible_roles']==['incident_scoping','threat_hunting','identity_access']
    assert source==before and prepared['local_manifest']['lineage']['o1']['evidence_id']==source['facts'][0]['evidence_id']


@pytest.mark.parametrize('actions',[['shell'],['identity_access','identity_access'],['telemetry_health'],list(hermes.ROLES)[:5]])
def test_assignments_reject_unknown_duplicate_irrelevant_and_excess_roles(actions):
    source=document('identity',dict(event='mfa_disabled',authorized='no'))
    with pytest.raises(ProbeError,match='assignment_not_admitted'):hermes.validate_actions(decision(actions),source,'plan')


def test_urgent_exposure_cannot_be_hidden_or_declared_benign():
    source=document('exposure',dict(severity='critical',reachable='yes',mitigated='no'))
    with pytest.raises(ProbeError,match='urgent_exposure'):hermes.validate_actions(decision([]),source,'plan')
    row=decision(['exposure_vulnerability']);hermes.validate_actions(row,source,'plan')
    row['disposition']='benign'
    with pytest.raises(ProbeError,match='urgent_exposure'):hermes.validate_actions(row,source,'plan')
    with pytest.raises(ProbeError,match='assignment_not_admitted'):hermes.validate_actions(decision(['exposure_vulnerability']),source,'report')


def test_oversized_supervisor_packet_fails_without_truncating_source_facts():
    source=document('activity',dict(category='network',outcome='observed',count=1))
    source['facts']=[dict(source['facts'][0],id=str(uuid4())) for _ in range(128)]
    with pytest.raises(AccessDenied,match='narrower_scope'):hermes.project(source,'plan')


def test_receipt_fact_time_comes_from_server_and_carries_no_page_data():
    source=dict(id=uuid4(),evidence_id=uuid4(),content_digest='a'*64,
        received_at=datetime(2026,10,20,12,0,0,123,tzinfo=timezone.utc),page_url='https://generated-console.invalid/alerts')
    doc=browser_hermes.receipt_document(uuid4(),[source])
    assert doc['as_of']=='2026-10-20T12:00:00.000123Z'
    assert {fact['event_time'] for fact in doc['facts']}=={doc['as_of']}
    assert source['page_url'] not in hermes.canonical(hermes.project(doc,'plan')['packet']).decode()


def test_only_hermes_forms_accept_repeated_selected_tab_fields():
    app=Workbench.__new__(Workbench)
    app._csrf='generated-fixture'
    case_id=str(uuid4())
    tabs=[str(uuid4()) for _ in range(8)]

    def form(path,values):
        body=urlencode([('csrf',app._csrf),*values]).encode()
        return dict(PATH_INFO=path,CONTENT_TYPE='application/x-www-form-urlencoded',CONTENT_LENGTH=str(len(body)),
            **{'wsgi.input':BytesIO(body)})

    path='/cases/'+case_id+'/hermes'
    fields=[('selected_leases',tab) for tab in tabs]
    assert selected_hermes_leases(app._fields(form(path,fields))['selected_leases'])==tabs
    for invalid in (fields+[fields[0]],fields+[('selected_leases','local')]):
        with pytest.raises(AccessDenied,match='invalid_hermes_tab_selection'):
            app._fields(form(path,invalid))
    with pytest.raises(AccessDenied,match='duplicate_form_field'):
        app._fields(form('/cases/new',fields[:2]))
