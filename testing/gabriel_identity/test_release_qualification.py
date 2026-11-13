"""Sealed release evidence software tests; fixture answers cannot qualify AI."""
from copy import deepcopy

import pytest

from gabriel.identity import release_qualification as release,specialist_agents as agents,specialist_qualification as specialist
from gabriel.identity.model_evaluation import EvaluationError,digest
from testing.gabriel_identity.test_hermes_qualification import submission
from testing.gabriel_identity.test_model_evaluation import corpus,artifacts


def bundle():
    rows={}
    for role in agents.ROLES:
        data=corpus();runs,reviews=artifacts(data,specialist.evaluation_configuration(role,agents.DEFAULT_MODEL))
        for run,review in zip(runs,reviews):
            run['generation_id']=role+'/'+run['generation_id'];review['run_sha256']=digest(run)
        rows[role]=dict(model=agents.DEFAULT_MODEL,runtime_configuration_digest=digest(agents.configuration(role)),corpus=data,runs=runs,reviews=reviews)
    return dict(supervisor={stage:submission(stage) for stage in ('plan','report')},specialists=rows)


def seal(data):
    empty=deepcopy(data)
    for row in release.rows(empty).values():row['runs']=[];row['reviews']=[]
    return release.seal_inputs(empty,'independent-curator','run-operator','2026-10-19T00:00:00Z')


def test_complete_fixture_bundle_remains_failed_and_preserves_original_hashes():
    data=bundle();sealed=seal(data);before=deepcopy(data)
    result=release.evaluate_release(data,sealed,digest(sealed))
    assert data==before and result['automated_gate']=='fail' and not result['production_admission']
    assert result['configuration_count']==14 and result['distinct_generations']==280 and result['network_calls']==0
    assert result['submissions_sha256']==digest(data)
    assert all(r['automated_gate']=='fail' for r in result['specialists']['roles'].values())


def test_sealing_requires_empty_results_and_approved_external_digest():
    data=bundle()
    with pytest.raises(EvaluationError,match='empty_runs'):release.seal_inputs(data,'curator','operator','2026-10-19T00:00:00Z')
    sealed=seal(data)
    with pytest.raises(EvaluationError,match='approved_pre_run'):release.evaluate_release(data,sealed,'0'*64)


@pytest.mark.parametrize('change',['corpus','labels','configuration'])
def test_post_seal_input_or_configuration_changes_are_rejected(change):
    data=bundle();sealed=seal(data)
    if change=='corpus':data['specialists']['alert_triage']['corpus']['cases'][0]['label']['rationale']='Changed after sealing.'
    elif change=='labels':next(iter(data['supervisor']['plan']['planning_labels'].values()))['expected_roles']=[]
    else:data['specialists']['alert_triage']['runtime_configuration_digest']='0'*64
    with pytest.raises(EvaluationError,match='sealed_inputs_changed|stale_release_configuration'):release.evaluate_release(data,sealed,digest(sealed))


def test_generation_cannot_be_reused_between_supervisor_and_specialist():
    data=bundle();sealed=seal(data)
    data['specialists']['alert_triage']['runs'][0]['generation_id']=data['supervisor']['plan']['runs'][0]['generation_id']
    with pytest.raises(EvaluationError,match='release_generation_reused'):release.evaluate_release(data,sealed,digest(sealed))


@pytest.mark.parametrize('change',['curator','operator','time'])
def test_declared_independence_and_chronology_fail_closed(change):
    data=bundle();sealed=seal(data);review=data['specialists']['alert_triage']['reviews'][0]
    if change=='time':review['reviewed_at']='2026-10-18T00:00:00Z'
    else:review['reviewer_id']=sealed['curator_id' if change=='curator' else 'operator_id']
    with pytest.raises(EvaluationError,match='independent_reviewer_required|review_predates_seal'):release.evaluate_release(data,sealed,digest(sealed))


def test_cli_never_prints_private_invalid_evidence(monkeypatch,capsys):
    monkeypatch.setattr(release,'load_json',lambda _:dict(private='do-not-export'))
    assert release.main(['--submissions','private.json','--seal','seal.json','--approved-seal-sha256','0'*64])==2
    output=capsys.readouterr();assert not output.out and 'do-not-export' not in output.err
    data=bundle();data['specialists']['alert_triage']='do-not-export'
    monkeypatch.setattr(release,'load_json',lambda _:data)
    assert release.main(['--submissions','private.json','--seal-inputs','--curator-id','curator','--operator-id','operator','--sealed-at','2026-10-19T00:00:00Z'])==2
    output=capsys.readouterr();assert not output.out and 'do-not-export' not in output.err


@pytest.mark.parametrize('field',['runs','reviews'])
def test_cli_rejects_scalar_result_without_private_traceback(field,monkeypatch,capsys):
    data=bundle();sealed=seal(data)
    data['specialists']['alert_triage'][field][0]='private-malformed-result'
    monkeypatch.setattr(release,'load_json',lambda path:sealed if path=='seal.json' else data)
    assert release.main(['--submissions','private.json','--seal','seal.json','--approved-seal-sha256',digest(sealed)])==2
    output=capsys.readouterr();assert not output.out and 'private-malformed-result' not in output.err
    assert 'rejected invalid, stale or unsealed evidence' in output.err
