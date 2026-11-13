"""Offline fourteen-configuration review with separately retained pre-run seals."""
import argparse
from datetime import datetime
import json
import sys

from gabriel.identity import hermes_qualification as supervisor, specialist_qualification as specialists
from gabriel.identity.model_evaluation import EvaluationError,digest,fields,identifier,load_json,require,validate_corpus
from gabriel.identity.service import InvalidIdentityInput

VERSION='gabriel-release-qualification-v1'


def rows(submissions):
    fields(submissions,'supervisor specialists')
    require(type(submissions['supervisor']) is dict and set(submissions['supervisor'])=={'plan','report'},'both_supervisor_stages_required')
    require(type(submissions['specialists']) is dict and set(submissions['specialists'])==set(specialists.ROLES),'all_specialist_roles_required')
    return {'hermes/'+k:v for k,v in submissions['supervisor'].items()}|submissions['specialists']


def timestamp(value):
    require(type(value) is str,'invalid_seal_timestamp')
    try:
        result=datetime.fromisoformat(value.replace('Z','+00:00'))
        require(result.tzinfo is not None,'timezone_required')
        return result
    except ValueError:
        raise EvaluationError('invalid_seal_timestamp') from None


def bindings(submissions):
    result={}
    for name,row in rows(submissions).items():
        require(type(row) is dict,'invalid_submission')
        stage=name.split('/')[-1]
        config=supervisor.configuration(stage,row['model']) if name.startswith('hermes/') else specialists.configuration(name,row['model'])
        require(row['runtime_configuration_digest']==digest(config),'stale_release_configuration')
        validate_corpus(row['corpus'])
        result[name]=dict(runtime_configuration_digest=digest(config),corpus_sha256=digest(row['corpus']),
            planning_labels_sha256=digest(row.get('planning_labels')))
    return result


def seal_inputs(submissions,curator_id,operator_id,sealed_at):
    identifier(curator_id);identifier(operator_id);timestamp(sealed_at)
    # The seal is created before collecting answers or their human reviews.
    require(all(type(row) is dict and row.get('runs')==[] and row.get('reviews')==[] for row in rows(submissions).values()),'seal_requires_empty_runs_and_reviews')
    return dict(version=VERSION,curator_id=curator_id,operator_id=operator_id,sealed_at=sealed_at,configurations=bindings(submissions))


def evaluate_release(submissions,seal,approved_seal_sha256):
    fields(seal,'version curator_id operator_id sealed_at configurations')
    require(seal['version']==VERSION and digest(seal)==approved_seal_sha256,'approved_pre_run_seal_required')
    identifier(seal['curator_id']);identifier(seal['operator_id']);sealed=timestamp(seal['sealed_at'])
    require(seal['configurations']==bindings(submissions),'sealed_inputs_changed')
    generations=set();reviewers=set()
    for row in rows(submissions).values():
        require(type(row.get('runs')) is list and type(row.get('reviews')) is list,'invalid_results')
        for run in row['runs']:
            require(type(run) is dict,'invalid_run')
            generation=identifier(run.get('generation_id'))
            require(generation not in generations,'release_generation_reused')
            generations.add(generation)
        for review in row['reviews']:
            require(type(review) is dict,'invalid_review')
            reviewer=identifier(review.get('reviewer_id'))
            require(reviewer not in {seal['curator_id'],seal['operator_id']},'independent_reviewer_required')
            require(timestamp(review.get('reviewed_at'))>=sealed,'review_predates_seal')
            reviewers.add(reviewer)
    parent=supervisor.evaluate_supervisor(submissions['supervisor'])
    children=specialists.evaluate_agents(submissions['specialists'])
    return dict(version=VERSION,supervisor=parent,specialists=children,
        automated_gate='pass' if parent['automated_gate']==children['automated_gate']=='pass' else 'fail',
        seal_sha256=digest(seal),submissions_sha256=digest(submissions),configuration_count=14,
        distinct_generations=len(generations),reviewer_ids=sorted(reviewers),network_calls=0,production_admission=False,
        independence='Declared identities and hashes require independent identity, rights and pre-run seal verification.',
        remaining_acceptance=['Native Hermes SDK and real tool-loop evidence','Real-console semantics and native OS UAT','Security, operational and release-owner acceptance'])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--submissions',required=True)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--seal-inputs',action='store_true')
    choice.add_argument('--seal')
    parser.add_argument('--approved-seal-sha256')
    parser.add_argument('--curator-id');parser.add_argument('--operator-id');parser.add_argument('--sealed-at')
    args=parser.parse_args(argv)
    try:
        data=load_json(args.submissions)
        result=seal_inputs(data,args.curator_id,args.operator_id,args.sealed_at) if args.seal_inputs else evaluate_release(data,load_json(args.seal),args.approved_seal_sha256)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0 if args.seal_inputs or result['automated_gate']=='pass' else 2
    except (EvaluationError,InvalidIdentityInput,TypeError,KeyError,ValueError,RecursionError):
        sys.stderr.write('Release qualification rejected invalid, stale or unsealed evidence.\n')
        return 2


if __name__=='__main__':raise SystemExit(main())
