"""Candidate corpus integrity checks; no answers or analyst reviews are fabricated."""
from copy import deepcopy
from pathlib import Path

import pytest

from gabriel.identity.model_evaluation import (
    EvaluationError, evaluate, load_json, packets, validate_corpus,
)


ROOT = Path(__file__).resolve().parents[2]


def candidate():
    return load_json(ROOT / 'testing/gabriel_model_lab/candidate_corpus_v1.json')


def test_partition_contract_and_development_probe_unchanged():
    data = candidate()
    counts, families = validate_corpus(data)
    assert families == 60
    assert counts == {
        'development': {'attack': 10, 'benign': 10, 'visibility': 10},
        'validation': {'attack': 4, 'benign': 3, 'visibility': 3},
        'held_out': {'attack': 8, 'benign': 6, 'visibility': 6},
    }
    original = load_json(ROOT / 'testing/gabriel_model_lab/development_corpus.json')
    assert data['cases'][:len(original['cases'])] == original['cases']
    assert 'draft labels' in data['provenance']['reference']
    assert 'not independently sealed' in data['provenance']['reference']


@pytest.mark.parametrize('split', ['development', 'validation', 'held_out'])
def test_packets_exclude_answer_metadata_and_other_partitions(split):
    data = candidate()
    output = packets(data, split)
    expected = {case['id']: case for case in data['cases'] if case['split'] == split}
    assert {packet['case_id'] for packet in output} == set(expected)
    for packet in output:
        assert set(packet) == {'version', 'case_id', 'input_sha256', 'question', 'observations'}
        assert packet['observations'] == expected[packet['case_id']]['observations']
        assert packet['question'] == expected[packet['case_id']]['question']


@pytest.mark.parametrize('leak', ['family', 'capture'])
def test_cross_partition_reuse_is_rejected(leak):
    data = deepcopy(candidate())
    development = data['cases'][0]
    held = next(case for case in data['cases'] if case['split'] == 'held_out')
    if leak == 'family':
        held['family'] = development['family']
    else:
        held['observations'] = deepcopy(development['observations'])
    with pytest.raises(EvaluationError, match=leak + '_split_leakage'):
        validate_corpus(data)


def test_full_size_draft_with_no_model_results_cannot_qualify():
    config = dict(provider='openrouter', model='openai/gpt-4.1-mini',
                  endpoint_policy='draft-not-admitted', prompt_sha256='a' * 64,
                  adapter_version='draft', redaction_version='draft',
                  compression_version='draft', parameters={})
    report = evaluate(candidate(), config, [], [])
    assert report['families'] == 60
    assert report['completed'] == 0
    assert report['automated_gate'] == 'fail'
    assert report['production_admission'] is False
    assert report['human_release_acceptance'] == 'pending'
    missing = [row for row in report['failures'] if row['reason'] == 'missing_result']
    assert len(missing) == 20
    assert report['metrics']['cost_usd'] == 0
