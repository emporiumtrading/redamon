"""Review supplied indicator lifecycle versions from case-bound evidence."""

from collections import Counter, defaultdict


VERSION = 'gabriel-intel-lifecycle-v1'
SKILLS = {'review_intelligence_lifecycle': 'threat_intelligence'}
INTEL_LIFECYCLE_SCHEMA = {
    'feed_id': 'uuid',
    'feed_version': int,
    'state': {'active', 'superseded', 'revoked'},
    'retrieved_at': 'time',
    'valid_until': 'time',
}
MAX_QUEUE_DETAILS = 4
NEXT_STEPS = {
    'source_verification_unavailable': 'verify_case_source',
    'version_conflict': 'reconcile_same_version_assertions',
    'effective_time_conflict': 'review_version_chronology',
    'reactivation_requires_review': 'review_revocation_and_reactivation',
    'reported_revoked': 'review_indicator_retirement',
    'reported_superseded': 'review_replacement_indicator',
    'reported_expired': 'review_indicator_refresh',
    'reported_active': 'review_indicator_context',
}


def validate_intel_lifecycle(fact, as_of):
    """Validate ordering and the required local indicator identity."""
    from gabriel.identity.specialist_analysis import at, require

    data = fact['data']
    effective = at(fact['event_time'])
    require(fact['entity_id'] is not None, 'intel_lifecycle_indicator_alias_required')
    require(1 <= data['feed_version'] <= 1_000_000, 'invalid_intel_lifecycle_version')
    require(effective <= at(data['retrieved_at']) <= as_of, 'invalid_intel_lifecycle_retrieval_time')
    if data['state'] == 'active':
        require(effective < at(data['valid_until']), 'invalid_intel_lifecycle_active_interval')


def _verified_digests(case_id, refs):
    cases = []
    candidates = defaultdict(list)
    for ref in refs or ():
        if type(ref) is not dict:
            continue
        if ref.get('kind') == 'case_record':
            cases.append(ref)
        if ref.get('kind') == 'evidence_metadata' and type(ref.get('record_id')) is str:
            candidates[ref['record_id']].append(ref)
    if len(cases) != 1 or cases[0].get('record_id') != case_id or cases[0].get('ref') != f'case/{case_id}':
        return {}
    return {evidence_id: entries[0].get('digest') for evidence_id, entries in candidates.items()
            if len(entries) == 1 and entries[0].get('ref') == f'evidence/{evidence_id}'
            and entries[0].get('content_integrity') == 'verified'}


def _review_track(reports, as_of):
    versions = defaultdict(dict)
    for version, assertion, ref, verified in reports:
        if not verified:
            return 'source_verification_unavailable', [ref], None
        # Repeat reports do not become additional versions or independent votes.
        versions[version].setdefault(assertion, ref)

    ordered = []
    for _, assertions in sorted(versions.items()):
        if len(assertions) > 1:
            return 'version_conflict', list(assertions.values())[:2], None
        ordered.append(next(iter(assertions.items())))

    for ((_, previous_time, _), previous_ref), ((_, following_time, _), following_ref) in zip(ordered, ordered[1:]):
        if following_time < previous_time:
            return 'effective_time_conflict', [previous_ref, following_ref], None

    (state, _, valid_until), latest_ref = ordered[-1]
    if state == 'active':
        prior_revocation = next((ref for (prior_state, _, _), ref in reversed(ordered[:-1])
                                 if prior_state == 'revoked'), None)
        if prior_revocation is not None:
            return 'reactivation_requires_review', [prior_revocation, latest_ref], None
        if valid_until <= as_of:
            return 'reported_expired', [latest_ref], 'expired'
    return f'reported_{state}', [latest_ref], state


def evaluate(name, document, *, verified_refs=None):
    """Build a bounded analyst review queue from locally verified source references."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, at, validate_document

    if name not in SKILLS:
        raise ValueError('unknown_intelligence_catalog_skill')
    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)
    as_of = at(document['as_of'])
    verified_digests = _verified_digests(case_id, verified_refs)
    visible_types = ROLE_TYPES[SKILLS[name]] | {'coverage'}
    visible_facts = (fact for fact in document['facts'] if fact['type'] in visible_types)

    tracks = defaultdict(list)
    for index, fact in enumerate(visible_facts, 1):
        if fact['type'] != 'intel_lifecycle':
            continue
        data = fact['data']
        assertion = (data['state'], at(fact['event_time']), at(data['valid_until']))
        verified = verified_digests.get(fact['evidence_id']) == fact['evidence_digest']
        tracks[(fact['entity_id'], data['feed_id'])].append((data['feed_version'], assertion, f'o{index}', verified))

    details = []
    current_states = defaultdict(dict)
    for (indicator, _), reports in tracks.items():
        status, refs, state = _review_track(reports, as_of)
        details.append(dict(status=status, refs=refs, analyst_step=NEXT_STEPS[status]))
        if state is not None:
            current_states[indicator].setdefault(state, refs[0])

    disagreements = [list(states.values())[:2] for states in current_states.values() if len(states) > 1]
    status_counts = Counter(detail['status'] for detail in details)
    priority = {status: index for index, status in enumerate(NEXT_STEPS)}
    details.sort(key=lambda detail: priority[detail['status']])
    status = 'no_lifecycle_facts'
    if status_counts['source_verification_unavailable']:
        status = 'incomplete_local_verification'
    elif details:
        status = 'review_required'
    return dict(
        version=VERSION, status=status,
        reported_indicator_alias_count=len({indicator for indicator, _ in tracks}),
        reported_indicator_feed_track_count=len(tracks),
        track_status_counts=dict(sorted(status_counts.items())),
        cross_feed_state_disagreement_count=len(disagreements),
        sample_cross_feed_disagreement_refs=disagreements[:1],
        queue=details[:MAX_QUEUE_DETAILS], omitted_track_count=max(0, len(details) - MAX_QUEUE_DETAILS),
        source_authenticity='unverified', feed_identity_and_versions='supplied_assertions',
        source_independence='unestablished', threat_actor_attribution='unknown', confidence='unqualified',
        external_actions_authorized=False, model_used=False, requires_analyst_review=True,
    )
