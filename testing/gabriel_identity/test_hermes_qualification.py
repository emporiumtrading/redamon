"""Planning-role labels preserve original run/review hashes and all quality gates."""
from copy import deepcopy

import pytest

from gabriel.identity import hermes_qualification as qualification
from gabriel.identity.model_evaluation import EvaluationError,digest,evaluate,packets
from gabriel.identity.service import InvalidIdentityInput
from testing.gabriel_identity.test_model_evaluation import corpus,artifacts


def submission(stage):
    data=corpus();config=qualification.evaluation_configuration(stage)
    runs,reviews=artifacts(data,config)
    labels={p['case_id']:dict(input_sha256=p['input_sha256'],eligible_roles=['alert_triage'],expected_roles=['alert_triage']) for p in packets(data,'held_out')} if stage=='plan' else None
    for run,review in zip(runs,reviews):
        run['generation_id']=stage+'/'+run['generation_id']
        if stage=='plan':run['decision']['requested_actions']=['alert_triage']
        review['run_sha256']=digest(run)
    return dict(model=qualification.DEFAULT_MODEL,runtime_configuration_digest=digest(qualification.configuration(stage)),
        corpus=data,runs=runs,reviews=reviews,planning_labels=labels)


def test_supervisor_fixture_answers_never_qualify_even_with_correct_assignments():
    rows={stage:submission(stage) for stage in ('plan','report')}
    before=deepcopy(rows);report=qualification.evaluate_supervisor(rows)
    assert rows==before and report['automated_gate']=='fail' and not report['production_admission']
    for stage,result in report['stages'].items():
        assert result['runs_sha256']==digest(rows[stage]['runs'])
        assert any(f['reason']=='fixture_is_not_model_evidence' for f in result['failures'])
        assert not any(f['reason'] in {'external_action_requested','supervisor_assignment_mismatch'} for f in result['failures'])


def test_generic_evaluator_still_rejects_assignment_actions():
    row=submission('plan')
    report=evaluate(row['corpus'],qualification.evaluation_configuration('plan'),row['runs'],row['reviews'])
    assert any(f['reason']=='external_action_requested' for f in report['failures'])


def test_wrong_or_duplicate_assignments_fail_without_rewriting_records():
    for actions in [[],['shell'],['identity_access']]:
        rows={stage:submission(stage) for stage in ('plan','report')}
        run=rows['plan']['runs'][0];run['decision']['requested_actions']=actions
        rows['plan']['reviews'][0]['run_sha256']=digest(run)
        report=qualification.evaluate_supervisor(rows)
        assert any(f['reason']=='supervisor_assignment_mismatch' for f in report['stages']['plan']['failures'])


    rows={stage:submission(stage) for stage in ('plan','report')}
    run=rows['plan']['runs'][0];run['decision']['requested_actions']=['alert_triage','alert_triage']
    rows['plan']['reviews'][0]['run_sha256']=digest(run)
    with pytest.raises(EvaluationError,match='duplicate_reference'):
        qualification.evaluate_supervisor(rows)


def test_unbound_labels_and_stale_human_reviews_are_rejected():
    rows={stage:submission(stage) for stage in ('plan','report')}
    next(iter(rows['plan']['planning_labels'].values()))['input_sha256']='0'*64
    with pytest.raises(EvaluationError,match='label_input_mismatch'):qualification.evaluate_supervisor(rows)
    rows={stage:submission(stage) for stage in ('plan','report')}
    rows['plan']['runs'][0]['decision']['requested_actions']=[]
    with pytest.raises(EvaluationError,match='stale_review'):qualification.evaluate_supervisor(rows)


def test_both_current_stages_are_required_and_report_cannot_request_actions():
    with pytest.raises(InvalidIdentityInput,match='both_hermes'):qualification.evaluate_supervisor({})
    rows={stage:submission(stage) for stage in ('plan','report')}
    rows['plan']['runtime_configuration_digest']='0'*64
    with pytest.raises(InvalidIdentityInput,match='stale_hermes'):qualification.evaluate_supervisor(rows)
    rows={stage:submission(stage) for stage in ('plan','report')}
    rows['report']['runs'][0]['decision']['requested_actions']=['alert_triage']
    rows['report']['reviews'][0]['run_sha256']=digest(rows['report']['runs'][0])
    report=qualification.evaluate_supervisor(rows)
    assert any(f['reason']=='external_action_requested' for f in report['stages']['report']['failures'])


def test_snapshot_contains_all_fourteen_bound_configurations_without_activation():
    snapshot=qualification.configuration_snapshot()
    assert snapshot['network_calls']==0 and not snapshot['production_admission']
    assert set(snapshot['supervisor'])=={'plan','report'} and len(snapshot['specialists'])==12
    rows=list(snapshot['supervisor'].values())+list(snapshot['specialists'].values())
    assert len({r['runtime_configuration_digest'] for r in rows})==14
    assert all(digest(r['runtime'])==r['runtime_configuration_digest'] for r in rows)
