"""Review case-bound PowerShell execution indicators and reported approval."""

from collections import defaultdict

POWERSHELL_EXECUTION_SCHEMA = {
    'process_instance_id': 'uuid',
    'indicator': {'encoded_command', 'network_fetch', 'expression_execution',
                  'execution_policy_bypass', 'standard_invocation'},
    'approved': {'yes', 'no', 'unknown'},
}
MAX_DETAIL = 4
HIGH_RISK_PAIRS = (
    frozenset({'encoded_command', 'network_fetch'}),
    frozenset({'network_fetch', 'expression_execution'}),
    frozenset({'encoded_command', 'execution_policy_bypass'}),
)


def review_powershell_activity(document):
    """Group only by asserted process instance, never by host or temporal proximity alone."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, validate_document

    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)
    visible_types = ROLE_TYPES['threat_hunting'] | {'coverage'}
    processes = defaultdict(lambda: defaultdict(dict))
    for index, fact in enumerate((f for f in document['facts'] if f['type'] in visible_types), 1):
        if fact['type'] != 'powershell_execution':
            continue
        data = fact['data']
        identity = (fact['entity_id'], data['process_instance_id'])
        processes[identity][data['indicator']].setdefault(data['approved'], f'o{index}')

    details = []
    for indicators in processes.values():
        signals = set(indicators)
        signals.discard('standard_invocation')
        approvals = {approval for signal in signals for approval in indicators[signal]}
        paired = any(pair <= signals for pair in HIGH_RISK_PAIRS)
        if 'yes' in approvals and 'no' in approvals:
            state = 'conflicting_approval'
        elif signals and approvals == {'yes'}:
            state = 'reported_approved_activity'
        elif paired:
            state = 'review_combined_indicators'
        elif signals:
            state = 'review_single_indicators'
        else:
            state = 'routine_indicator_only'
        references = list(dict.fromkeys(ref for signal, states in indicators.items()
                                       if signal in signals or not signals for ref in states.values()))
        details.append(dict(status=state, indicators=sorted(signals), references=references[:4],
                            references_omitted=max(0, len(references) - 4)))

    priority = ('conflicting_approval', 'review_combined_indicators', 'review_single_indicators',
                'reported_approved_activity', 'routine_indicator_only')
    details.sort(key=lambda item: priority.index(item['status']))
    return dict(
        status='review_required' if details else 'no_powershell_execution_facts',
        reported_process_count=len(details),
        counts={key: sum(item['status'] == key for item in details) for key in priority},
        processes=details[:MAX_DETAIL], omitted_process_count=max(0, len(details) - MAX_DETAIL),
        source_authenticity='unverified', process_identity_independently_verified=False,
        approval_independently_verified=False, attack_status='unknown', confidence='unqualified',
        external_actions_authorized=False, requires_analyst_review=True,
    )
