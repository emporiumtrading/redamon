"""Review reported vulnerability age and case-bound remediation deadlines."""

from collections import Counter, defaultdict


VULNERABILITY_SLA_SCHEMA = {
    'first_seen': 'time',
    'due_at': 'time',
    'state': {'open', 'remediated', 'unknown'},
}
MAX_FINDING_DETAILS = 3
SECONDS_PER_DAY = 86400
PRIORITY = {'conflicting': 0, 'overdue': 1, 'remediated_late': 2,
            'due_now': 3, 'unknown': 4, 'within_sla': 5, 'remediated_on_time': 6}


def validate_vulnerability_sla(fact):
    """Apply chronology and alias checks after shared typed-fact validation."""
    from gabriel.identity.specialist_analysis import at, require

    require(fact['entity_id'] is not None, 'vulnerability_sla_alias_required')
    first_seen = at(fact['data']['first_seen'])
    require(first_seen <= at(fact['event_time']) and first_seen <= at(fact['data']['due_at']),
            'invalid_vulnerability_sla_chronology')


def _finding(alias, reports, snapshot):
    newest = max(reports, key=lambda report: report['event_time'])
    simultaneous = [report for report in reports if report['event_time'] == newest['event_time']]
    competing = next((report for report in reports if report['first_seen'] != newest['first_seen']
                      or report['due_at'] != newest['due_at']), None)
    if competing is None:
        competing = next((report for report in simultaneous if report['state'] != newest['state']), None)
    if competing is None:
        completed = [report for report in reports if report['state'] == 'remediated']
        if len({report['event_time'] for report in completed}) > 1:
            newest, competing = min(completed, key=lambda report: report['event_time']), max(completed, key=lambda report: report['event_time'])
        elif completed and newest['state'] == 'open':
            competing = completed[0]

    review = 'unknown'
    end = newest['event_time'] if newest['state'] == 'remediated' else snapshot
    if competing:
        review = 'conflicting'
    elif newest['state'] == 'remediated':
        review = 'remediated_late' if end > newest['due_at'] else 'remediated_on_time'
    elif newest['state'] == 'open':
        if snapshot > newest['due_at']:
            review = 'overdue'
        else:
            review = 'due_now' if snapshot == newest['due_at'] else 'within_sla'

    return {
        'finding': alias,
        'review': review,
        'age_days': None if competing else (end - newest['first_seen']).days,
        'observation_ref': newest['ref'],
        'conflict_ref': competing['ref'] if competing else None,
    }


def review_vulnerability_sla(document):
    """Compare supplied deadlines and reported lifecycle dates in the case snapshot."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, at, validate_document

    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)
    scope = ROLE_TYPES['exposure_vulnerability'] | {'coverage'}
    observations = [fact for fact in document['facts'] if fact['type'] in scope]
    aliases = {
        value: f'e{index}'
        for index, value in enumerate(sorted({fact['entity_id'] for fact in observations if fact['entity_id']}), 1)
    }
    grouped = defaultdict(list)
    for index, fact in enumerate(observations, 1):
        if fact['type'] == 'vulnerability_sla':
            data = fact['data']
            grouped[fact['entity_id']].append({
                'first_seen': at(data['first_seen']), 'due_at': at(data['due_at']),
                'event_time': at(fact['event_time']), 'state': data['state'], 'ref': f'o{index}',
            })

    snapshot = at(document['as_of'])
    details = [_finding(aliases[key], grouped[key], snapshot) for key in sorted(grouped)]
    details.sort(key=lambda row: PRIORITY[row['review']])
    counts = Counter(row['review'] for row in details)
    return {
        'version': 'gabriel-vulnerability-sla-v1',
        'status': 'review_required' if details else 'no_vulnerability_sla_facts',
        'reported_finding_count': len(details),
        'review_counts': dict(sorted(counts.items())),
        'findings': details[:MAX_FINDING_DETAILS],
        'omitted_finding_detail_count': max(0, len(details) - MAX_FINDING_DETAILS),
        'policy_verified': False,
        'source_authenticity': 'unverified',
        'source_clocks_verified': False,
        'open_status_carried_to_snapshot': True,
        'current_remediation_verified': False,
        'confidence': 'unqualified',
        'external_actions_authorized': False,
        'requires_analyst_review': True,
    }
