"""Offline exact-config supervisor qualification; never grants production admission."""
import argparse
import json

from gabriel.identity.hermes_supervisor import configuration,DEFAULT_MODEL,VERSION
from gabriel.identity.model_evaluation import digest,evaluate,load_json
from gabriel.identity.service import InvalidIdentityInput


def evaluation_configuration(stage,model=DEFAULT_MODEL):
    current=configuration(stage,model)
    return dict(provider='openrouter',model=model,endpoint_policy=current['route_registry_version'],
        prompt_sha256=current['prompt_digest'],adapter_version='hermes/'+stage+'/'+digest(current),
        redaction_version='hermes-typed-facts-v1',compression_version='none-v1',parameters=current['parameters'])


def evaluate_supervisor(submissions):
    if type(submissions) is not dict or set(submissions)!={'plan','report'}:
        raise InvalidIdentityInput('both_hermes_stage_qualifications_required')
    reports={};generations=set()
    for stage in ('plan','report'):
        row=submissions[stage]
        if type(row) is not dict or set(row)!={'model','runtime_configuration_digest','corpus','runs','reviews','planning_labels'}:
            raise InvalidIdentityInput('invalid_hermes_qualification')
        config=configuration(stage,row['model'])
        if row['runtime_configuration_digest']!=digest(config):
            raise InvalidIdentityInput('stale_hermes_qualification_configuration')
        labels=row['planning_labels']
        if stage=='plan' and type(labels) is not dict or stage=='report' and labels is not None:
            raise InvalidIdentityInput('invalid_hermes_planning_labels')
        ids={r.get('generation_id') for r in row['runs']}
        if ids & generations:raise InvalidIdentityInput('hermes_qualification_generation_reused')
        generations.update(ids)
        report=evaluate(row['corpus'],evaluation_configuration(stage,row['model']),row['runs'],row['reviews'],_planning_labels=labels)
        reports[stage]=dict(report,runtime_configuration_digest=digest(config),planning_labels_sha256=digest(labels))
    return dict(version=VERSION,stages=reports,automated_gate='pass' if all(r['automated_gate']=='pass' for r in reports.values()) else 'fail',
        production_admission=False,independent_release_acceptance='pending',
        scope='Supervisor decision and assignment quality; separate specialist, tool-loop, console, OS and operational acceptance still required.')


def configuration_snapshot():
    from gabriel.identity import specialist_agents
    return dict(version=VERSION,production_admission=False,network_calls=0,
        supervisor={stage:dict(runtime=configuration(stage),runtime_configuration_digest=digest(configuration(stage)),
            evaluation=evaluation_configuration(stage)) for stage in ('plan','report')},
        specialists={role:dict(runtime=specialist_agents.configuration(role),runtime_configuration_digest=digest(specialist_agents.configuration(role))) for role in specialist_agents.ROLES},
        required_evidence=['Independent family-disjoint sealed corpus and artifact rights',
            'Exact-input live-provider runs with usage/cost provenance',
            'Independent analyst reviews bound to the original model answers',
            'Planning labels bound to held-out input hashes and retained outside model requests',
            'Separate real-console, native OS, recovery, operational and human release acceptance'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--submissions')
    choice.add_argument('--configurations',action='store_true')
    args=parser.parse_args()
    print(json.dumps(configuration_snapshot() if args.configurations else evaluate_supervisor(load_json(args.submissions)),sort_keys=True,indent=2))


if __name__=='__main__':main()
