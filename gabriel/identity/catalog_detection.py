"""False-negative analysis of versioned, case-bound detection trial facts."""
from collections import defaultdict


def _groups(document):
    groups = defaultdict(lambda: defaultdict(set))
    for index, fact in enumerate(document['facts'], 1):
        if fact['type'] == 'detection_trial':
            data = fact['data']
            identity = (data['rule_digest'], data['engine_digest'], data['fixture_digest'])
            outcome = (data['cohort'], data['expected_match'], data['matched'])
            groups[identity][outcome].add(index)
    return groups


def _base(status, **values):
    return dict(status=status, **values, scope='supplied_case_facts',
                source_authenticity='unverified', confidence='unqualified',
                incident_status='unknown', external_actions_authorized=False,
                model_used=False, requires_analyst_review=True)


def review_false_positive_fixtures(document):
    groups = _groups(document)
    valid = [(next(iter(v)), min(next(iter(v.values())))) for v in groups.values() if len(v) == 1]
    benign = [(o, i) for o, i in valid if o[0] == 'benign']
    unexpected = [i for (cohort, expected, matched), i in benign if not expected and matched]
    conflicts = sum(len(v) > 1 for v in groups.values())
    return _base('review_required' if unexpected or conflicts else 'reviewed_benign_trials' if benign else 'no_benign_trials',
                 distinct_fixture_trial_count=len(groups), benign_control_count=len(benign),
                 reported_unexpected_benign_match_count=len(unexpected), conflicting_trial_count=conflicts,
                 sample_unexpected_match_refs=[f'o{i}' for i in unexpected[:4]], root_cause_established=False)


def _divergence(document, by):
    grouped = defaultdict(set)
    groups = _groups(document)
    for (rule, engine, fixture), outcomes in groups.items():
        if len(outcomes) == 1:
            cohort, expected, matched = next(iter(outcomes))
            key = (engine, fixture, cohort, expected) if by == 'rule' else (rule, fixture, cohort, expected)
            grouped[key].add((rule if by == 'rule' else engine, matched))
    comparable = [records for records in grouped.values() if len({digest for digest, _ in records}) > 1]
    divergent = sum(len({matched for _, matched in records}) > 1 for records in comparable)
    label = 'rule' if by == 'rule' else 'engine'
    return _base('review_required' if divergent else 'no_comparable_version_divergence' if grouped else 'no_versioned_detection_trials',
                 distinct_fixture_trial_count=len(groups), comparable_group_count=len(comparable),
                 reported_outcome_divergence_count=divergent,
                 conflicting_trial_count=sum(len(v) > 1 for v in groups.values()),
                 comparison_dimension=label, version_order_verified=False,
                 environment_equivalence_verified=False, regression_established=False)


def review_detection_fixture_divergence(document):
    return _divergence(document, 'rule')


def review_detection_engine_drift(document):
    return _divergence(document, 'engine')


METADATA_SKILLS = {
    'map_attack_coverage', 'review_detection_as_code', 'review_detection_optimization',
    'review_detection_thresholds', 'map_detection_dependencies', 'map_adversary_emulation',
    'audit_detection_versions', 'benchmark_detection_performance', 'prioritize_detection_gaps',
}


def review_detection_metadata(name, document):
    if name not in METADATA_SKILLS:
        raise ValueError('unknown_detection_metadata_skill')
    specs = [f['data'] for f in document['facts'] if f['type'] == 'detection_spec']
    trials = [f['data'] for f in document['facts'] if f['type'] == 'detection_trial']
    benches = [f['data'] for f in document['facts'] if f['type'] == 'detection_benchmark']
    defined = {s['rule_digest'] for s in specs}
    tested = {t['rule_digest'] for t in trials}
    measured = {b['rule_digest'] for b in benches}
    values = dict(supplied_spec_count=len(specs), supplied_trial_count=len(trials),
                  supplied_benchmark_count=len(benches), compiler_validation_performed=False,
                  replay_verified=False, deployment_performed=False, mapping_accuracy_verified=False)
    concern = False
    if name == 'map_attack_coverage':
        mapped = {s['technique_id'] for s in specs}
        tested_mapping = {s['technique_id'] for s in specs if s['rule_digest'] in tested}
        values.update(supplied_technique_count=len(mapped), techniques_with_supplied_trial_count=len(tested_mapping),
                      techniques_without_supplied_trial_count=len(mapped-tested_mapping))
        concern = bool(mapped-tested_mapping)
    elif name == 'review_detection_as_code':
        parents = {s['parent_digest'] for s in specs if s['parent_digest'] != '0'*64}
        conflicts = sum(len({(s['format'],s['threshold'],s['technique_id']) for s in specs if s['rule_digest']==d})>1 for d in defined)
        values.update(unique_rule_digest_count=len(defined), missing_parent_digest_count=len(parents-defined),
                      conflicting_same_digest_metadata_count=conflicts, repository_state_verified=False)
        concern = bool(parents-defined or conflicts)
    elif name == 'review_detection_optimization':
        comparisons = defaultdict(list)
        for b in benches: comparisons[(b['engine_digest'],b['fixture_digest'])].append(b)
        pairs = [v for v in comparisons.values() if len({b['rule_digest'] for b in v})>1]
        spread = sum(max(b['latency_ms'] for b in v)>min(b['latency_ms'] for b in v) for v in pairs)
        values.update(comparable_fixture_benchmark_groups=len(pairs), groups_with_reported_latency_spread=spread,
                      equivalent_detection_quality_verified=False, optimization_applied=False)
        concern = bool(spread)
    elif name == 'review_detection_thresholds':
        grouped = defaultdict(set)
        for s in specs: grouped[s['rule_digest']].add(s['threshold'])
        missing = sum(not any(t['rule_digest']==d and t['cohort']=='benign' for t in trials) for d in defined)
        values.update(supplied_threshold_count=len({s['threshold'] for s in specs}),
                      conflicting_threshold_by_digest_count=sum(len(v)>1 for v in grouped.values()),
                      rules_without_benign_control_count=missing, threshold_optimum_verified=False)
        concern = bool(missing or values['conflicting_threshold_by_digest_count'])
    elif name == 'map_detection_dependencies':
        values.update(rules_with_declared_dependencies=sum(s['dependency_count']>0 for s in specs),
                      missing_field_metadata_count=sum(s['field_count']==0 for s in specs),
                      dependency_identity_verified=False)
        concern = bool(values['missing_field_metadata_count'])
    elif name == 'map_adversary_emulation':
        adversarial={t['rule_digest'] for t in trials if t['cohort']=='adversarial'}
        values.update(reported_adversarial_trial_count=sum(t['cohort']=='adversarial' for t in trials),
                      mapped_rule_with_adversarial_trial_count=len(defined & adversarial),
                      mapped_rule_without_adversarial_trial_count=len(defined-adversarial),
                      emulation_execution_verified=False)
        concern=bool(defined-adversarial)
    elif name == 'audit_detection_versions':
        parents={s['parent_digest'] for s in specs if s['parent_digest']!='0'*64}
        values.update(unique_supplied_version_count=len(defined), supplied_parent_reference_count=len(parents),
                      unresolved_parent_reference_count=len(parents-defined),
                      self_parent_reference_count=sum(s['parent_digest']==s['rule_digest'] for s in specs),
                      version_lineage_attested=False)
        concern=bool(parents-defined or values['self_parent_reference_count'])
    elif name == 'benchmark_detection_performance':
        values.update(supplied_measurement_count=len(benches), benchmarked_rule_count=len(measured),
                      missing_measurement_for_defined_rule_count=len(defined-measured),
                      reported_total_events=sum(b['event_count'] for b in benches),
                      reported_total_latency_ms=sum(b['latency_ms'] for b in benches),
                      independent_benchmark_verified=False)
        concern=bool(defined-measured)
    else:
        misses={t['rule_digest'] for t in trials if t['expected_match'] and not t['matched']}
        values.update(rules_without_reported_trials=len(defined-tested),
                      rules_with_reported_expected_match_miss=len(defined & misses),
                      disabled_rules_with_reported_miss=sum(not s['enabled'] and s['rule_digest'] in misses for s in specs),
                      proposed_review_order='reported_misses_then_untested_rules', automated_rule_change=False)
        concern=bool(defined-tested or misses)
    return _base('review_required' if concern else 'reviewed_supplied_metadata' if specs or trials or benches else 'no_detection_metadata', **values)


def analyze_false_negatives(document):
    """Group validated outcomes by asserted rule, engine and fixture identity.

    The caller verifies same-case evidence bytes and authorization. Matching
    configuration digests group supplied assertions without authenticating
    the engine, the fixture label or the reported execution.
    """
    trials = {}
    for index, fact in enumerate(document['facts'], start=1):
        if fact['type'] != 'detection_trial':
            continue
        data = fact['data']
        identity = (data['rule_digest'], data['engine_digest'], data['fixture_digest'])
        outcome = (data['cohort'], data['expected_match'], data['matched'])
        # Repeated reports of the same fixture outcome add no trial or vote.
        trials.setdefault(identity, {}).setdefault(outcome, f'o{index}')

    misses = []
    conflicts = []
    conflicted_count = expected_count = missed_count = 0
    for outcomes in trials.values():
        if len(outcomes) != 1:
            conflicted_count += 1
            if len(conflicts) < 4:
                conflicts.extend(list(outcomes.values())[:2])
            continue
        (cohort, expected, matched), reference = next(iter(outcomes.items()))
        # Benign control fixtures contribute no expected-positive evidence.
        if cohort == 'benign' or not expected:
            continue
        expected_count += 1
        if not matched:
            missed_count += 1
            if len(misses) < 4:
                misses.append(reference)

    if missed_count or conflicted_count:
        status = 'review_required'
    elif expected_count:
        status = 'analyzed'
    else:
        status = 'no_expected_positive_trials' if trials else 'no_versioned_detection_trials'
    return dict(
        status=status,
        asserted_configuration_count=len({identity[:2] for identity in trials}),
        distinct_fixture_trial_count=len(trials),
        expected_positive_trial_count=expected_count,
        reported_false_negative_count=missed_count,
        conflicting_trial_count=conflicted_count,
        sample_miss_refs=misses,
        sample_conflict_refs=conflicts,
        scope='supplied_fixture_trials',
        source_authenticity='unverified',
        confidence='unqualified',
        incident_status='unknown',
        external_actions_authorized=False,
        model_used=False,
        requires_analyst_review=True,
    )
