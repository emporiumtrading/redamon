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


def test_per_role_qualification_rejects_full_size_simulated_model_evidence():
    from testing.gabriel_identity.test_model_evaluation import corpus,artifacts
    submitted={}
    for role in agents.ROLES:
        data=corpus();config=evaluation_configuration(role,agents.DEFAULT_MODEL)
        runs,reviews=artifacts(data,config)
        for run,review in zip(runs,reviews):
            run['generation_id']=role+'/'+run['generation_id']
            review['run_sha256']=agents.digest(run)
        submitted[role]=dict(model=agents.DEFAULT_MODEL,runtime_configuration_digest=agents.digest(agents.configuration(role)),corpus=data,runs=runs,reviews=reviews)
    report=evaluate_agents(submitted)
    assert report['automated_gate']=='fail' and not report['production_admission']
    assert len(report['roles'])==12 and all(row['completed']==20 for row in report['roles'].values())
    assert all(any(f['reason']=='fixture_is_not_model_evidence' for f in row['failures']) for row in report['roles'].values())
