"""Normalize reported incident timestamps into bounded UTC review intervals."""

from collections import defaultdict
from datetime import timedelta
from itertools import combinations

TIMELINE_EVENT_SCHEMA = {
    'offset_status': {'measured', 'unknown'},
    'clock_offset_ms': 'nullable_clock_ms',
    'uncertainty_ms': 'nullable_clock_ms',
}
CLOCK_LIMIT_MS = 86_400_000
DETAIL_LIMIT = 4


def _bounds(reported, data):
    center = reported - timedelta(milliseconds=data['clock_offset_ms'])
    error = timedelta(milliseconds=data['uncertainty_ms'])
    return center - error, center + error


def validate_timeline_event(fact, as_of):
    from gabriel.identity.specialist_analysis import at, require

    data = fact['data']
    reported = at(fact['event_time'])
    offset, error = data['clock_offset_ms'], data['uncertainty_ms']
    if data['offset_status'] == 'unknown':
        require(offset is None and error is None, 'unknown_timeline_offset_requires_null_bounds')
        require(reported <= as_of + timedelta(milliseconds=CLOCK_LIMIT_MS), 'timeline_report_after_snapshot')
        return
    require(offset is not None and error is not None and error >= 0, 'invalid_timeline_clock_bounds')
    earliest, _ = _bounds(reported, data)
    require(earliest <= as_of, 'normalized_timeline_event_after_snapshot')


def _utc(value):
    return value.isoformat().replace('+00:00', 'Z')


def normalize_incident_timeline(document):
    """Compare only intervals that are fully inside the supplied case snapshot."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, at, validate_document

    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)
    as_of = at(document['as_of'])
    observations = (fact for fact in document['facts']
                    if fact['type'] in ROLE_TYPES['incident_scoping'] | {'coverage'})
    intervals = []
    unresolved = []
    reports = defaultdict(dict)
    duplicate_count = 0
    for index, fact in enumerate(observations, 1):
        if fact['type'] != 'timeline_event':
            continue
        data = fact['data']
        reported = at(fact['event_time'])
        identity = (fact['evidence_id'], fact['evidence_digest'], fact['entity_id'], reported)
        calibration = (data['offset_status'], data['clock_offset_ms'], data['uncertainty_ms'])
        if calibration in reports[identity]:
            duplicate_count += 1
            continue
        reports[identity][calibration] = (f'o{index}', data)

    for (_, _, _, reported), calibrations in reports.items():
        if len(calibrations) > 1:
            for reference, _ in calibrations.values():
                unresolved.append(dict(ref=reference, reason='conflicting_clock_assertions'))
            continue
        reference, data = next(iter(calibrations.values()))
        if data['offset_status'] == 'unknown':
            unresolved.append(dict(ref=reference, reason='clock_offset_unknown'))
            continue
        earliest, latest = _bounds(reported, data)
        if latest > as_of:
            unresolved.append(dict(ref=reference, reason='interval_crosses_snapshot'))
            continue
        intervals.append((earliest, latest, reference))

    intervals.sort()
    ordered = []
    overlap_count = ordered_count = 0
    for first, second in combinations(intervals, 2):
        if first[1] < second[0]:
            ordered_count += 1
            if len(ordered) < DETAIL_LIMIT:
                ordered.append([first[2], second[2]])
        else:
            overlap_count += 1

    return dict(
        status='review_required' if reports else 'no_timeline_event_facts',
        distinct_report_count=sum(map(len, reports.values())), repeated_report_count=duplicate_count,
        normalized_interval_count=len(intervals), unordered_report_count=len(unresolved),
        disjoint_interval_pair_count=ordered_count, overlapping_or_touching_pair_count=overlap_count,
        sample_intervals=[dict(ref=ref, earliest=_utc(start), latest=_utc(end))
                          for start, end, ref in intervals[:DETAIL_LIMIT]],
        sample_reported_order=ordered, sample_unordered=unresolved[:DETAIL_LIMIT],
        source_clock_calibration_verified=False, source_authenticity='unverified',
        actual_event_order_verified=False, causality_established=False,
        external_actions_authorized=False, confidence='unqualified', requires_analyst_review=True,
    )
