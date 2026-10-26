"""Exact prompts, minimization and qualification do not imply real-model quality."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity import specialist_agents as agents
from gabriel.identity.service import AccessDenied,InvalidIdentityInput
from gabriel.identity.specialist_qualification import evaluate_agents,evaluation_configuration
from testing.gabriel_identity.test_specialist_analysis import CASES,document


def test_twelve_role_specific_prompts_and_configuration_bindings():
    assert len({agents.prompt(role) for role in agents.ROLES})==12
    assert len({agents.digest(agents.configuration(role)) for role in agents.ROLES})==12
    for role in agents.ROLES:
        row=agents.readiness(role)
        assert row['ai_capable'] and not row['model_enabled'] and row['qualification']=='qualification_pending'
        assert evaluation_configuration(role,agents.DEFAULT_MODEL)['adapter_version']=='agent/'+row['configuration_digest']


@pytest.mark.parametrize('role,kind,data,expected,urgency',CASES)
def test_role_projection_retains_typed_semantics_without_private_identifiers(role,kind,data,expected,urgency):
    source=document(kind,data);before=deepcopy(source)
    projected=agents.project(source,role,uuid4(),[])
    wire=agents.canonical(projected['packet']).decode()
    for private in [source['case_id'],source['facts'][0]['id'],source['facts'][0]['evidence_id'],source['facts'][0]['entity_id']]:assert private not in wire
    assert projected['packet']['observations'][0]['data']==data and source==before
    assert projected['local_manifest']['lineage']['o1']['evidence_id']==source['facts'][0]['evidence_id']


def test_qualification_requires_all_roles_and_current_config():
    with pytest.raises(InvalidIdentityInput,match='all_twelve'):evaluate_agents({})
    submitted={r:dict(model=agents.DEFAULT_MODEL,runtime_configuration_digest='0'*64,corpus={},runs=[],reviews=[]) for r in agents.ROLES}
    with pytest.raises(InvalidIdentityInput,match='stale_agent'):evaluate_agents(submitted)


def test_oversized_context_is_not_silently_truncated():
    source=document('activity',dict(category='network',outcome='observed',count=1000000))
    source['facts']=[dict(source['facts'][0],id=str(uuid4())) for _ in range(128)]
    with pytest.raises(AccessDenied,match='narrower_scope'):agents.project(source,'threat_hunting',uuid4(),[])
