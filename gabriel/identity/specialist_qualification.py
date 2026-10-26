"""Per-agent exact-configuration qualification; engineering fixtures cannot admit a model."""
from gabriel.identity.model_evaluation import digest,evaluate
from gabriel.identity.service import InvalidIdentityInput
from gabriel.identity.specialist_agents import ROLES,VERSION,configuration


def evaluation_configuration(role,model):
    current=configuration(role,model)
    return dict(provider='openrouter',model=model,endpoint_policy=current['route_registry_version'],
        prompt_sha256=current['prompt_digest'],adapter_version='agent/'+digest(current),
        redaction_version=current['projection_version'],compression_version='none-v1',parameters=current['parameters'])


def evaluate_agents(submissions):
    if type(submissions) is not dict or set(submissions)!=set(ROLES):
        raise InvalidIdentityInput('all_twelve_agent_qualifications_required')
    reports={};generations=set()
    for role in ROLES:
        packet=submissions[role]
        if type(packet) is not dict or set(packet)!={'model','runtime_configuration_digest','corpus','runs','reviews'}:
            raise InvalidIdentityInput('invalid_agent_qualification')
        expected=digest(configuration(role,packet['model']))
        if packet['runtime_configuration_digest']!=expected:
            raise InvalidIdentityInput('stale_agent_qualification_configuration')
        current_generations={run.get('generation_id') for run in packet['runs']}
        if generations & current_generations:raise InvalidIdentityInput('agent_qualification_generation_reused')
        generations.update(current_generations)
        report=evaluate(packet['corpus'],evaluation_configuration(role,packet['model']),packet['runs'],packet['reviews'])
        reports[role]=dict(report,runtime_configuration_digest=expected)
    return dict(version=VERSION,roles=reports,automated_gate='pass' if all(r['automated_gate']=='pass' for r in reports.values()) else 'fail',
        production_admission=False,independent_release_acceptance='pending',
        tool_loop_and_browser_acceptance='requires_separate_workflow_evidence')
