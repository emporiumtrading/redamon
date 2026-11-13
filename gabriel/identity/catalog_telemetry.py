"""Map supplied monitoring reports to case-local, unverified data source aliases."""

from collections import defaultdict


SOURCE_COVERAGE_SCHEMA = {
    'state': {'available', 'stale', 'missing'},
    'source_kind': {'application', 'authentication', 'cloud', 'endpoint', 'network', 'other', 'unknown'},
    'window_start': 'time',
}
MAX_SOURCE_DETAILS = 3


def validate_source_coverage(fact):
    """Validate the additional invariants after shared typed-fact validation."""
    from gabriel.identity.specialist_analysis import at, require

    require(fact['entity_id'] is not None, 'source_coverage_alias_required')
    require(at(fact['data']['window_start']) < at(fact['event_time']), 'invalid_source_coverage_window')


def _overlap_conflict(rows):
    for index, first in enumerate(rows):
        for second in rows[index + 1:]:
            if second['start'] >= first['end']:
                break
            comparable = first['kind'] == second['kind'] or 'unknown' in (first['kind'], second['kind'])
            if comparable and first['state'] != second['state']:
                return [first['ref'], second['ref']]
    return []


def map_source_coverage(document):
    """Summarize asserted intervals without inferring continuous visibility or a missing inventory."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, at, validate_document

    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)
    observations = [fact for fact in document['facts'] if fact['type'] in ROLE_TYPES['telemetry_health']]
    aliases = {
        value: f'e{index}'
        for index, value in enumerate(sorted({fact['entity_id'] for fact in observations if fact['entity_id']}), 1)
    }
    grouped = defaultdict(list)
    for index, fact in enumerate(observations, 1):
        if fact['type'] != 'source_coverage':
            continue
        data = fact['data']
        grouped[fact['entity_id']].append({
            'start': at(data['window_start']),
            'end': at(fact['event_time']),
            'kind': data['source_kind'],
            'state': data['state'],
            'ref': f'o{index}',
        })

    details = []
    for alias, reports in sorted(grouped.items()):
        reports.sort(key=lambda report: (report['start'], report['end'], report['ref']))
        first, last = reports[0], max(reports, key=lambda report: report['end'])
        last_gap = max((report for report in reports if report['state'] in {'missing', 'stale'}),
                       key=lambda report: report['end'], default=None)
        details.append({
            'source': aliases[alias],
            'kinds': sorted({report['kind'] for report in reports}),
            'states': sorted({report['state'] for report in reports}),
            'first_window_ref': first['ref'],
            'last_window_ref': last['ref'],
            'last_reported_gap_ref': last_gap['ref'] if last_gap else None,
            'overlap_conflict_refs': _overlap_conflict(reports),
        })

    def has_reported_gap(detail):
        return 'missing' in detail['states'] or 'stale' in detail['states']

    details.sort(key=lambda detail: not (has_reported_gap(detail) or detail['overlap_conflict_refs']))
    return {
        'version': 'gabriel-source-coverage-map-v1',
        'status': 'review_required' if details else 'no_source_coverage_facts',
        'reported_source_count': len(details),
        'reported_gap_source_count': sum(has_reported_gap(detail) for detail in details),
        'conflicting_window_source_count': sum(bool(detail['overlap_conflict_refs']) for detail in details),
        'source_kind_disagreement_count': sum(len(set(detail['kinds']) - {'unknown'}) > 1 for detail in details),
        'sources': details[:MAX_SOURCE_DETAILS],
        'omitted_source_detail_count': max(0, len(details) - MAX_SOURCE_DETAILS),
        'source_authenticity': 'unverified',
        'source_clocks_verified': False,
        'expected_source_inventory_supplied': False,
        'continuous_visibility_verified': False,
        'attack_status': 'unknown',
        'confidence': 'unqualified',
        'external_actions_authorized': False,
        'requires_analyst_review': True,
    }
