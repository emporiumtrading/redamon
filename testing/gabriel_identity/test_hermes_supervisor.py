"""Supervisor contracts and minimization; fixtures never qualify live models."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity import hermes_supervisor as hermes
from gabriel.identity.model_protocol import ProbeError
from gabriel.identity.service import AccessDenied
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
