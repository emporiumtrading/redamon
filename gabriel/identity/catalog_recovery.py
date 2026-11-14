"""Compare a reported restored data point with the supplied recovery objective."""

from collections import Counter, defaultdict

RECOVERY_POINT_SCHEMA = {
    'disrupted_at': 'time',
    'restored_data_at': 'time',
    'objective_seconds': 'recovery_objective_seconds',
}
MAX_DETAILS = 4


def validate_recovery_point(fact):
    from gabriel.identity.specialist_analysis import at, require

    data = fact['data']
    require(fact['entity_id'] is not None, 'recovery_system_alias_required')
    require(at(data['restored_data_at']) <= at(data['disrupted_at']) <= at(fact['event_time']),
            'invalid_recovery_point_chronology')


def review_recovery_point(document):
    """Use event-relative data age; preserve conflicting recovery records."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, at, validate_document

    validate_document(document, document.get('case_id') if type(document) is dict else None)
    visible = ROLE_TYPES['recovery_learning'] | {'coverage'}
    events = defaultdict(dict)
    for i, fact in enumerate((f for f in document['facts'] if f['type'] in visible), 1):
        if fact['type'] != 'recovery_point':
            continue
        data = fact['data']
        disrupted_at = at(data['disrupted_at'])
        point = at(data['restored_data_at'])
        events[fact['entity_id'], disrupted_at].setdefault(
            (point, data['objective_seconds']), f'o{i}')

    details = []
    for (_, disrupted_at), reports in events.items():
        if len(reports) > 1:
            details.append(dict(status='conflicting_reports', references=list(reports.values())[:2]))
            continue
        (point, objective), ref = next(iter(reports.items()))
        age = (disrupted_at - point).total_seconds()
        details.append(dict(status='reported_outside_objective' if age > objective else 'reported_within_objective',
                            references=[ref], reported_data_age_seconds=age, objective_seconds=objective))

    priority = {'conflicting_reports': 0, 'reported_outside_objective': 1, 'reported_within_objective': 2}
    details.sort(key=lambda item: priority[item['status']])
    return dict(status='review_required' if details else 'no_recovery_point_facts',
                reported_recovery_event_count=len(details), counts=dict(Counter(r['status'] for r in details)),
                events=details[:MAX_DETAILS], omitted_event_count=max(0, len(details) - MAX_DETAILS),
                source_authenticity='unverified', policy_independently_verified=False,
                restored_data_independently_verified=False, clocks_independently_verified=False,
                incident_closure_authorized=False, external_actions_authorized=False,
                confidence='unqualified', requires_analyst_review=True)
