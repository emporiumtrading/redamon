"""Evaluator software tests. Fabricated answers here are never model-quality evidence."""
from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from gabriel.identity.model_evaluation import (
    VERSION, EvaluationError, digest, evaluate, interval, load_json, main, packets,
)


def corpus():
    cases = []
    # Family-disjoint synthetic fixtures exercise the gate's full-size success path.
    for index in range(60):
        kind = ('attack', 'benign', 'visibility')[index % 3]
        split = 'development' if index < 30 else 'validation' if index < 40 else 'held_out'
        cases.append({'id': f'case-{index}', 'family': f'family-{index}', 'split': split,
                      'class': kind, 'critical': kind == 'attack',
                      'question': 'Assess observed activity and source limitations.',
                      'observations': [{'id': 'event-1', 'source': 'lab-source',
                                        'event_time': '2026-10-20T00:00:00Z',
                                        'content': f'Software-test fixture {index}; not a live event.'}],
                      'gaps': ['missing-source'] if kind == 'visibility' else [],
                      'label': {'acceptable_decisions': [{'attack': 'escalate', 'benign': 'benign', 'visibility': 'abstain'}[kind]],
                                'rationale': 'Evaluator fixture label; not expert adjudication.'}})
    return {'version': VERSION, 'provenance': {'kind': 'generated_lab',
            'rights': 'Repository-authored software fixtures', 'reference': 'test_model_evaluation.py'}, 'cases': cases}


def configuration():
    return dict(provider='openrouter', model='google/gemini-2.5-flash',
                endpoint_policy='test-only', prompt_sha256='a'*64, adapter_version='v1',
                redaction_version='v1', compression_version='v1', parameters={'temperature': 0})


def artifacts(data, config):
    runs, reviews = [], []
    labels = {c['id']: c for c in data['cases']}
    for packet in packets(data, 'held_out'):
        case = labels[packet['case_id']]
        run = dict(case_id=case['id'], input_sha256=packet['input_sha256'],
                   configuration_sha256=digest(config), origin='test_fixture',
                   generation_id='fixture/'+case['id'], latency_ms=10, cost_usd=0.001,
                   input_tokens=20, output_tokens=20,
                   decision=dict(disposition=case['label']['acceptable_decisions'][0],
                                 claims=[dict(id='claim-1', statement='Fixture claim', references=['event-1'])],
                                 alternatives=['Fixture alternative'], contradictions=['Fixture contradiction check'],
                                 uncertainty=['Fixture uncertainty'], reported_gaps=case['gaps'], requested_actions=[]))
        runs.append(run)
        reviews.append(dict(case_id=case['id'], run_sha256=digest(run), reviewer_id='test-reviewer',
                            role='analyst_adjudicator', reviewed_at='2026-10-20T00:01:00Z',
                            claim_verdicts={'claim-1': True}, alternatives_adequate=True,
                            contradictions_adequate=True, uncertainty_adequate=True,
                            decision_justified=True, rationale='Software-test review fixture.'))
    return runs, reviews


class ModelEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.corpus = corpus()
        self.config = configuration()
        self.runs, self.reviews = artifacts(self.corpus, self.config)

    def report(self):
        return evaluate(self.corpus, self.config, self.runs, self.reviews)

    def reasons(self):
        return {f['reason'] for f in self.report()['failures']}

    def update_review(self, index=0):
        self.reviews[index]['run_sha256'] = digest(self.runs[index])

    def test_packets_exclude_labels_partition_severity_and_expected_gaps(self):
        packet = packets(self.corpus, 'held_out')[0]
        self.assertEqual(set(packet), {'version', 'case_id', 'input_sha256', 'question', 'observations'})
        self.assertEqual(len(packets(self.corpus, 'development')), 30)

    def test_authored_development_corpus_is_not_held_out_evidence(self):
        data = load_json(Path(__file__).resolve().parents[1]/'gabriel_model_lab'/'development_corpus.json')
        self.assertEqual(len(packets(data, 'development')), 12)
        self.assertEqual(packets(data, 'held_out'), [])
        result = evaluate(data, self.config, [], [])
        self.assertEqual(result['automated_gate'], 'fail')
        self.assertEqual(result['families'], 12)
        self.assertFalse(result['production_admission'])

    def test_fixtures_cannot_establish_suitability(self):
        result = self.report()
        self.assertEqual(result['automated_gate'], 'fail')
        self.assertIn('fixture_is_not_model_evidence', self.reasons())
        self.assertFalse(result['production_admission'])

    def test_supplied_live_tag_does_not_authenticate_provider_or_admit_model(self):
        for index, run in enumerate(self.runs):
            run['origin'] = 'live_provider'
            self.update_review(index)
        result = self.report()
        self.assertEqual(result['automated_gate'], 'pass')
        self.assertEqual(result['human_release_acceptance'], 'pending')
        self.assertEqual(result['provenance_status'], 'operator_supplied_not_provider_authenticated')
        self.assertFalse(result['production_admission'])

    def test_missing_result_remains_in_recall_denominator(self):
        index = next(i for i, r in enumerate(self.runs) if r['decision']['disposition'] == 'escalate')
        cid = self.runs[index]['case_id']
        self.runs.pop(index)
        self.reviews = [r for r in self.reviews if r['case_id'] != cid]
        result = self.report()
        metric = result['metrics']['attack_escalation_recall']
        self.assertLess(metric['numerator'], metric['denominator'])
        self.assertIn('critical_attack_missed', self.reasons())

    def test_abstention_is_not_an_attack_detection(self):
        index = next(i for i, r in enumerate(self.runs) if r['decision']['disposition'] == 'escalate')
        self.runs[index]['decision']['disposition'] = 'abstain'
        self.update_review(index)
        self.assertIn('critical_attack_missed', self.reasons())
        self.assertLess(self.report()['metrics']['attack_escalation_recall']['rate'], 1)

    def test_urgent_inconclusive_is_visible_escalation_not_confirmed_attack(self):
        index = next(i for i, r in enumerate(self.runs) if r['decision']['disposition'] == 'escalate')
        self.runs[index]['decision']['disposition'] = 'urgent_inconclusive'
        self.update_review(index)
        self.assertNotIn('critical_attack_missed', self.reasons())

    def test_false_alarm_is_scored(self):
        index = next(i for i, r in enumerate(self.runs) if r['decision']['disposition'] == 'benign')
        self.runs[index]['decision']['disposition'] = 'escalate'
        self.update_review(index)
        self.assertIn('benign_escalation_above_target', self.reasons())

    def test_missing_visibility_gap_fails(self):
        index = next(i for i, r in enumerate(self.runs) if r['decision']['reported_gaps'])
        self.runs[index]['decision']['reported_gaps'] = []
        self.update_review(index)
        self.assertIn('unreported_gap', self.reasons())

    def test_requested_external_execution_fails(self):
        self.runs[0]['decision']['requested_actions'] = ['isolate-endpoint']
        self.update_review()
        self.assertIn('external_action_requested', self.reasons())

    def test_unsupported_reference_rejected(self):
        self.runs[0]['decision']['claims'][0]['references'] = ['invented-event']
        with self.assertRaises(EvaluationError):
            self.report()

    def test_stale_review_rejected(self):
        self.runs[0]['decision']['claims'][0]['statement'] = 'Changed claim'
        with self.assertRaises(EvaluationError):
            self.report()

    def test_configuration_change_requires_new_results(self):
        for key in ('model', 'endpoint_policy', 'redaction_version', 'compression_version', 'prompt_sha256'):
            with self.subTest(key=key):
                changed = deepcopy(self.config)
                changed[key] = 'b'*64 if key == 'prompt_sha256' else 'changed'
                with self.assertRaises(EvaluationError):
                    evaluate(self.corpus, changed, self.runs, self.reviews)

    def test_input_change_rejects_stale_result(self):
        self.runs[0]['input_sha256'] = 'b'*64
        with self.assertRaises(EvaluationError):
            self.report()

    def test_duplicate_result_and_generation_rejected(self):
        self.runs.append(deepcopy(self.runs[0]))
        with self.assertRaises(EvaluationError):
            self.report()
        self.runs.pop()
        self.runs[1]['generation_id'] = self.runs[0]['generation_id']
        with self.assertRaises(EvaluationError):
            self.report()

    def test_missing_review_cannot_pass(self):
        self.reviews.pop()
        self.assertIn('analyst_review_missing', self.reasons())

    def test_claim_citation_alone_does_not_prove_entailment(self):
        self.reviews[0]['claim_verdicts']['claim-1'] = False
        self.assertIn('analyst_review_failed', self.reasons())
        self.assertLess(self.report()['metrics']['supported_claims']['rate'], 1)

    def test_reasoning_quality_requires_review(self):
        for key in ('alternatives_adequate', 'contradictions_adequate', 'uncertainty_adequate', 'decision_justified'):
            self.reviews[0][key] = False
            self.assertIn('analyst_review_failed', self.reasons())
            self.reviews[0][key] = True

    def test_family_and_capture_leakage_rejected(self):
        self.corpus['cases'][-1]['family'] = self.corpus['cases'][0]['family']
        with self.assertRaises(EvaluationError):
            self.report()
        self.corpus = corpus()
        self.corpus['cases'][-1]['observations'][0]['content'] = self.corpus['cases'][0]['observations'][0]['content']
        with self.assertRaises(EvaluationError):
            self.report()

    def test_small_corpus_cannot_pass(self):
        self.corpus['cases'] = self.corpus['cases'][40:]
        self.assertIn('insufficient_corpus_coverage', self.reasons())

    def test_nonfinite_negative_boolean_cost_rejected(self):
        for cost in (float('nan'), float('inf'), -1, True):
            self.runs[0]['cost_usd'] = cost
            with self.assertRaises(EvaluationError):
                self.report()

    def test_overbudget_generation_fails(self):
        self.runs[0]['cost_usd'] = 0.051
        self.update_review()
        self.assertIn('investigation_budget_exceeded', self.reasons())

    def test_wilson_intervals_do_not_claim_certainty(self):
        self.assertIsNone(interval(0, 0))
        self.assertLess(interval(7, 7)['wilson_95'][0], 1)
        self.assertGreater(interval(0, 7)['wilson_95'][1], 0)

    def test_json_reader_rejects_duplicates_nan_and_oversize(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root)/'artifact.json'
            for value in ('{"id":1,"id":2}', '{"cost":NaN}', ' '* (8*1024*1024+1)):
                target.write_text(value)
                with self.assertRaises(EvaluationError):
                    load_json(target)

    def test_cli_reports_failure_without_echoing_bad_input(self):
        with tempfile.TemporaryDirectory() as root:
            paths = {}
            for key, value in [('corpus', self.corpus), ('configuration', self.config), ('runs', self.runs), ('reviews', self.reviews)]:
                target = Path(root)/(key+'.json')
                target.write_text(json.dumps(value))
                paths[key] = str(target)
            argv = ['report'] + [part for key, path in paths.items() for part in ('--'+key, path)]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(argv), 2)
            self.assertEqual(json.loads(output.getvalue())['automated_gate'], 'fail')
            Path(paths['runs']).write_text('SECRET_INVALID_ARTIFACT')
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(argv), 2)
            self.assertNotIn('SECRET_INVALID_ARTIFACT', output.getvalue())


if __name__ == '__main__':
    unittest.main()
