"""False-negative analysis of versioned, case-bound detection trial facts."""


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
