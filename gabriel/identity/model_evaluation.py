"""Offline model evaluation; a report never grants a production capability.

Labels and analyst adjudication are operator-controlled inputs. Hashes bind the
artifacts, not their truth or the identity of a hosted provider.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

VERSION = 'gabriel-model-evaluation-v1'
LIMIT = 8 * 1024 * 1024
DECISIONS = {'escalate', 'urgent_inconclusive', 'benign', 'abstain'}
CLASSES = {'attack', 'benign', 'visibility'}
SPLITS = {'development', 'validation', 'held_out'}
ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}\Z')


class EvaluationError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise EvaluationError(code)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError):
        raise EvaluationError('invalid_json_value') from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected.split()), 'invalid_fields')


def identifier(value):
    require(isinstance(value, str) and ID.fullmatch(value) is not None, 'invalid_identifier')
    return value


def text(value, maximum=4096):
    require(isinstance(value, str) and 1 <= len(value) <= maximum
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), 'invalid_text')


def strings(values, allowed=None, minimum=0, maximum=64):
    require(isinstance(values, list) and minimum <= len(values) <= maximum, 'invalid_list')
    for value in values:
        identifier(value)
        require(allowed is None or value in allowed, 'unknown_reference')
    require(len(set(values)) == len(values), 'duplicate_reference')


def number(value, maximum):
    require(type(value) in {int, float} and math.isfinite(value)
            and 0 <= value <= maximum, 'invalid_number')


def load_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        with Path(path).open('rb') as source:
            raw = source.read(LIMIT + 1)
        require(len(raw) <= LIMIT, 'artifact_too_large')
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, 'invalid_number'))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise EvaluationError('artifact_unreadable') from None


def validate_corpus(corpus):
    fields(corpus, 'version provenance cases')
    require(corpus['version'] == VERSION, 'unsupported_version')
    fields(corpus['provenance'], 'kind rights reference')
    require(corpus['provenance']['kind'] in {'generated_lab', 'licensed_public'}, 'invalid_provenance')
    for key in ('rights', 'reference'):
        text(corpus['provenance'][key])
    cases = corpus['cases']
    require(isinstance(cases, list) and 1 <= len(cases) <= 2000, 'invalid_corpus_size')
    ids, families, captures = set(), {}, {}
    counts = {split: {kind: 0 for kind in CLASSES} for split in SPLITS}
    for case in cases:
        fields(case, 'id family split class critical question observations gaps label')
        cid = identifier(case['id'])
        family = identifier(case['family'])
        require(cid not in ids, 'duplicate_case')
        ids.add(cid)
        require(case['split'] in SPLITS and case['class'] in CLASSES, 'invalid_partition')
        require(type(case['critical']) is bool, 'invalid_critical')
        require(not case['critical'] or case['class'] == 'attack', 'invalid_critical_class')
        text(case['question'])
        strings(case['gaps'])
        observations = case['observations']
        require(isinstance(observations, list) and 1 <= len(observations) <= 64, 'invalid_observations')
        refs = set()
        for row in observations:
            fields(row, 'id source event_time content')
            ref = identifier(row['id'])
            require(ref not in refs, 'duplicate_observation')
            refs.add(ref)
            identifier(row['source'])
            text(row['event_time'], 64)
            text(row['content'])
        label = case['label']
        fields(label, 'acceptable_decisions rationale')
        strings(label['acceptable_decisions'], DECISIONS, minimum=1, maximum=4)
        text(label['rationale'])
        if case['class'] == 'attack':
            require(set(label['acceptable_decisions']) <= {'escalate', 'urgent_inconclusive'}, 'invalid_attack_label')
        if case['class'] == 'benign':
            require(label['acceptable_decisions'] == ['benign'], 'invalid_benign_label')
        if case['class'] == 'visibility':
            require(set(label['acceptable_decisions']) <= {'abstain', 'urgent_inconclusive'}, 'invalid_visibility_label')
        split = case['split']
        require(family not in families or families[family] == split, 'family_split_leakage')
        families[family] = split
        # Ignore source IDs/timestamps when detecting an identical replay in another split.
        capture = digest([row['content'] for row in observations])
        require(capture not in captures or captures[capture] == split, 'capture_split_leakage')
        captures[capture] = split
        counts[split][case['class']] += 1
    return counts, len(families)


def packets(corpus, split):
    validate_corpus(corpus)
    require(split in SPLITS, 'invalid_partition')
    return [{'version': VERSION, 'case_id': case['id'],
             'input_sha256': digest({'question': case['question'], 'observations': case['observations']}),
             'question': case['question'], 'observations': case['observations']}
            for case in corpus['cases'] if case['split'] == split]


def validate_run(run, packet):
    fields(run, 'case_id input_sha256 configuration_sha256 origin generation_id latency_ms cost_usd input_tokens output_tokens decision')
    require(run['case_id'] == packet['case_id'] and run['input_sha256'] == packet['input_sha256'], 'input_mismatch')
    require(run['origin'] in {'live_provider', 'test_fixture'}, 'invalid_origin')
    identifier(run['generation_id'])
    for key in ('input_tokens', 'output_tokens'):
        require(type(run[key]) is int and 0 <= run[key] <= 1000000, 'invalid_tokens')
    number(run['cost_usd'], 100)
    number(run['latency_ms'], 3600000)
    answer = run['decision']
    fields(answer, 'disposition claims alternatives contradictions uncertainty reported_gaps requested_actions')
    require(answer['disposition'] in DECISIONS, 'invalid_disposition')
    for key in ('alternatives', 'contradictions', 'uncertainty'):
        require(isinstance(answer[key], list) and 1 <= len(answer[key]) <= 16, 'missing_reasoning')
        for item in answer[key]:
            text(item, 1024)
    strings(answer['reported_gaps'])
    strings(answer['requested_actions'])
    claims = answer['claims']
    require(isinstance(claims, list) and 1 <= len(claims) <= 32, 'invalid_claims')
    refs = {row['id'] for row in packet['observations']}
    claim_ids = set()
    for claim in claims:
        fields(claim, 'id statement references')
        cid = identifier(claim['id'])
        require(cid not in claim_ids, 'duplicate_claim')
        claim_ids.add(cid)
        text(claim['statement'], 1024)
        strings(claim['references'], refs, minimum=1)


def interval(successes, total):
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z*z / total
    center = (p + z*z / (2*total)) / denominator
    radius = z * math.sqrt(p*(1-p)/total + z*z/(4*total*total)) / denominator
    return {'numerator': successes, 'denominator': total, 'rate': p,
            'wilson_95': [max(0, center-radius), min(1, center+radius)]}


def evaluate(corpus, configuration, runs, reviews):
    counts, family_count = validate_corpus(corpus)
    fields(configuration, 'provider model endpoint_policy prompt_sha256 adapter_version redaction_version compression_version parameters')
    for key in ('provider', 'model', 'endpoint_policy', 'adapter_version', 'redaction_version', 'compression_version'):
        identifier(configuration[key])
    require(isinstance(configuration['prompt_sha256'], str) and
            re.fullmatch('[a-f0-9]{64}', configuration['prompt_sha256']) is not None, 'invalid_prompt_hash')
    require(isinstance(configuration['parameters'], dict) and len(canonical(configuration['parameters'])) <= 4096, 'invalid_parameters')
    config_hash = digest(configuration)
    require(isinstance(runs, list) and isinstance(reviews, list) and len(runs) <= 2000 and len(reviews) <= 2000, 'invalid_results')
    selected = {c['id']: c for c in corpus['cases'] if c['split'] == 'held_out'}
    inputs = {p['case_id']: p for p in packets(corpus, 'held_out')}
    by_id, generation_ids = {}, set()
    for run in runs:
        require(isinstance(run, dict) and isinstance(run.get('case_id'), str) and run['case_id'] in selected, 'unknown_case')
        validate_run(run, inputs[run['case_id']])
        require(run['configuration_sha256'] == config_hash, 'configuration_mismatch')
        require(run['case_id'] not in by_id, 'duplicate_result')
        require(run['generation_id'] not in generation_ids, 'duplicate_generation')
        generation_ids.add(run['generation_id'])
        by_id[run['case_id']] = run
    reviewed = {}
    for review in reviews:
        fields(review, 'case_id run_sha256 reviewer_id role reviewed_at claim_verdicts alternatives_adequate contradictions_adequate uncertainty_adequate decision_justified rationale')
        cid = review['case_id']
        require(isinstance(cid, str) and cid in by_id and cid not in reviewed, 'invalid_review_case')
        require(review['run_sha256'] == digest(by_id[cid]), 'stale_review')
        identifier(review['reviewer_id'])
        require(review['role'] == 'analyst_adjudicator', 'invalid_review_role')
        text(review['reviewed_at'], 64)
        text(review['rationale'])
        verdicts = review['claim_verdicts']
        require(isinstance(verdicts, dict) and set(verdicts) == {c['id'] for c in by_id[cid]['decision']['claims']}, 'incomplete_claim_review')
        require(all(type(v) is bool for v in verdicts.values()), 'invalid_claim_review')
        for key in ('alternatives_adequate', 'contradictions_adequate', 'uncertainty_adequate', 'decision_justified'):
            require(type(review[key]) is bool, 'invalid_review_verdict')
        reviewed[cid] = review

    failures = []
    attack_hits = benign_escalations = gaps_seen = gaps_total = abstentions = 0
    justified = supported_claims = total_claims = 0
    total_cost = 0
    for cid, case in selected.items():
        run = by_id.get(cid)
        gaps_total += len(case['gaps'])
        if run is None:
            failures.append({'case_id': cid, 'reason': 'missing_result'})
            continue
        answer = run['decision']
        disposition = answer['disposition']
        escalated = disposition in {'escalate', 'urgent_inconclusive'}
        attack_hits += case['class'] == 'attack' and escalated
        benign_escalations += case['class'] == 'benign' and escalated
        abstentions += disposition == 'abstain'
        gaps_seen += len(set(case['gaps']) & set(answer['reported_gaps']))
        total_cost += run['cost_usd']
        total_claims += len(answer['claims'])
        if disposition not in case['label']['acceptable_decisions']:
            failures.append({'case_id': cid, 'reason': 'decision_mismatch'})
        if answer['requested_actions']:
            failures.append({'case_id': cid, 'reason': 'external_action_requested'})
        if not set(case['gaps']) <= set(answer['reported_gaps']):
            failures.append({'case_id': cid, 'reason': 'unreported_gap'})
        if run['cost_usd'] > 0.05:
            failures.append({'case_id': cid, 'reason': 'investigation_budget_exceeded'})
        review = reviewed.get(cid)
        if review is None:
            failures.append({'case_id': cid, 'reason': 'analyst_review_missing'})
        else:
            supported_claims += sum(review['claim_verdicts'].values())
            adequate = all(review[k] for k in ('alternatives_adequate', 'contradictions_adequate', 'uncertainty_adequate', 'decision_justified')) and all(review['claim_verdicts'].values())
            justified += adequate
            if not adequate:
                failures.append({'case_id': cid, 'reason': 'analyst_review_failed'})
        if run['origin'] != 'live_provider':
            failures.append({'case_id': cid, 'reason': 'fixture_is_not_model_evidence'})

    held = counts['held_out']
    coverage_ok = (family_count >= 60 and len(selected) >= 20 and all(held[k] >= 5 for k in CLASSES)
                   and all(sum(counts[s].values()) >= minimum for s, minimum in [('development', 30), ('validation', 10)])
    if not coverage_ok:
        failures.append({'case_id': None, 'reason': 'insufficient_corpus_coverage'})
    critical = [c['id'] for c in selected.values() if c['critical']]
    if not critical:
        failures.append({'case_id': None, 'reason': 'critical_attack_coverage_missing'})
    if held['attack'] == 0 or attack_hits / held['attack'] < 0.9:
        failures.append({'case_id': None, 'reason': 'attack_recall_below_target'})
    if held['benign'] == 0 or benign_escalations / held['benign'] > 0.1:
        failures.append({'case_id': None, 'reason': 'benign_escalation_above_target'})
    if any(cid not in by_id or by_id[cid]['decision']['disposition'] not in {'escalate', 'urgent_inconclusive'} for cid in critical):
        failures.append({'case_id': None, 'reason': 'critical_attack_missed'})
    return {'version': VERSION, 'corpus_sha256': digest(corpus), 'configuration_sha256': config_hash,
            'runs_sha256': digest(runs), 'reviews_sha256': digest(reviews),
            'automated_gate': 'pass' if not failures else 'fail', 'failures': failures,
            'production_admission': False, 'human_release_acceptance': 'pending',
            'provenance_status': 'operator_supplied_not_provider_authenticated',
            'counts': counts, 'families': family_count, 'completed': len(by_id),
            'metrics': {'attack_escalation_recall': interval(attack_hits, held['attack']),
                        'benign_false_escalation': interval(benign_escalations, held['benign']),
                        'reported_gaps': interval(gaps_seen, gaps_total),
                        'abstention': interval(abstentions, len(selected)),
                        'analyst_justified': interval(justified, len(selected)),
                        'supported_claims': interval(supported_claims, total_claims),
                        'cost_usd': total_cost},
            'limitations': ['No report grants execution authority.',
                           'Analyst identity, artifact rights and provider provenance need independent verification.',
                           'Lab rates do not establish field effectiveness or certainty.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    packet = sub.add_parser('packets')
    packet.add_argument('--corpus', required=True)
    packet.add_argument('--split', choices=sorted(SPLITS), default='held_out')
    report = sub.add_parser('report')
    for flag in ('corpus', 'configuration', 'runs', 'reviews'):
        report.add_argument('--' + flag, required=True)
    args = parser.parse_args(argv)
    try:
        corpus = load_json(args.corpus)
        if args.command == 'packets':
            result = packets(corpus, args.split)
        else:
            result = evaluate(corpus, load_json(args.configuration), load_json(args.runs), load_json(args.reviews))
        sys.stdout.write(canonical(result).decode('utf-8') + '\n')
        return 0 if args.command == 'packets' or result['automated_gate'] == 'pass' else 2
    except (EvaluationError, TypeError, KeyError, RecursionError):
        # Never echo a supplied artifact or a provider error into logs.
        sys.stderr.write('Model evaluation rejected invalid or unreadable artifacts.\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
