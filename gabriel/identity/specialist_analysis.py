"""Bounded local specialist rules over explicitly supplied, untrusted typed facts.

These rules produce review work, never incident verdicts, permissions or external
effects. A caller must verify the referenced evidence and current case authority.
"""
from collections import Counter
from datetime import datetime, timezone
import re
from uuid import UUID

from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import InvalidIdentityInput

VERSION = 'specialist-rules-v1'
CONTRACT = 'specialist-analysis-v2'
SEVERITIES = {'informational', 'low', 'medium', 'high', 'critical'}
YES_NO = {'yes', 'no', 'unknown'}
SCHEMAS = {
    'coverage': {'state': {'available', 'stale', 'missing'}},
    'alert': {'severity': SEVERITIES, 'state': {'open', 'resolved', 'unknown'}},
    'activity': {'category': {'authentication', 'process', 'network', 'file'},
                 'outcome': {'success', 'failure', 'blocked', 'observed', 'unknown'}, 'count': int},
    'intelligence': {'match': bool, 'valid_until': 'time'},
    'artifact': {'integrity': {'match', 'mismatch', 'unknown'}, 'custody': {'complete', 'gap', 'unknown'}},
    'detection': {'cohort': {'malicious', 'benign', 'adversarial'}, 'matched': bool, 'expected_match': bool},
    'exposure': {'severity': SEVERITIES, 'reachable': YES_NO, 'mitigated': YES_NO},
    'identity': {'event': {'privilege_grant', 'session_revocation', 'mfa_disabled', 'login_failure', 'login_success'},
                 'authorized': YES_NO},
    'cloud': {'finding': {'public_access', 'privileged_workload', 'unsigned_component', 'policy_drift'},
              'state': {'present', 'absent', 'unknown'}, 'authorized': YES_NO},
    'response_check': {'check': {'target_binding', 'dependencies', 'recovery'}, 'passed': YES_NO},
    'recovery': {'check': {'restore', 'service_health', 'security_control'},
                 'result': {'pass', 'fail', 'unknown'}, 'baseline': {'current', 'stale', 'unknown'}},
}
ROLE_TYPES = {
    'telemetry_health': {'coverage'},
    'alert_triage': {'alert', 'activity'},
    'incident_scoping': {'activity', 'alert', 'identity', 'cloud'},
    'threat_intelligence': {'intelligence'},
    'threat_hunting': {'activity', 'identity', 'cloud'},
    'dfir_evidence': {'artifact'},
    'detection_engineering': {'detection'},
    'exposure_vulnerability': {'exposure'},
    'identity_access': {'identity', 'activity'},
    'cloud_supply_chain': {'cloud'},
    'response_remediation': {'response_check'},
    'recovery_learning': {'recovery'},
}
NEXT_STEPS = {
    'telemetry_health': ['review_source_visibility'],
    'alert_triage': ['review_alert_context', 'review_benign_administration'],
    'incident_scoping': ['review_entity_binding', 'review_timeline'],
    'threat_intelligence': ['verify_intelligence_attribution', 'review_indicator_validity'],
    'threat_hunting': ['propose_existing_search', 'review_hunt_hypothesis'],
    'dfir_evidence': ['review_custody', 'verify_artifact_integrity'],
    'detection_engineering': ['review_detection_test_failures', 'prepare_local_detection_draft'],
    'exposure_vulnerability': ['verify_reachability', 'review_exposure_ownership'],
    'identity_access': ['review_identity_authorization', 'review_session_context'],
    'cloud_supply_chain': ['review_configuration_baseline', 'verify_component_provenance'],
    'response_remediation': ['prepare_local_response_proposal', 'request_exact_action_review'],
    'recovery_learning': ['review_recovery_validation', 'propose_reviewed_lesson'],
}
ALTERNATIVES = {
    'telemetry_health': 'Maintenance, logout or collection failure can explain missing coverage.',
    'alert_triage': 'Approved administration or a detector false positive can explain an alert.',
    'incident_scoping': 'Reused identifiers or forwarded duplicates can produce misleading associations.',
    'threat_intelligence': 'Shared infrastructure or an obsolete indicator can explain a reported match.',
    'threat_hunting': 'Approved testing or administration can produce the same activity categories.',
    'dfir_evidence': 'Collection or export errors can explain integrity and custody discrepancies.',
    'detection_engineering': 'A fixture, parser or rule-version mismatch can explain a failed test.',
    'exposure_vulnerability': 'Compensating controls or an outdated inventory can change reported exposure.',
    'identity_access': 'An approved role change, recovery or administrative session can explain the activity.',
    'cloud_supply_chain': 'Approved deployment changes or a stale baseline can explain configuration findings.',
    'response_remediation': 'Incomplete planning records can explain missing readiness checks.',
    'recovery_learning': 'A test-environment mismatch can explain recovery-validation failure.',
}


def require(condition, code):
    if not condition:
        raise InvalidIdentityInput(code)


def uid(value):
    try:
        require(type(value) is str and str(UUID(value)) == value, 'invalid_specialist_fact_identifier')
    except (ValueError, AttributeError):
        raise InvalidIdentityInput('invalid_specialist_fact_identifier') from None
    return value


def at(value):
    try:
        require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value) is not None, 'invalid_specialist_fact_time')
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
        require(1970 <= parsed.year <= 2100 and parsed.utcoffset().total_seconds() == 0, 'invalid_specialist_fact_time')
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise InvalidIdentityInput('invalid_specialist_fact_time') from None


def validate_document(document, case_id):
    require(type(document) is dict and set(document) == {'version', 'case_id', 'as_of', 'facts'}
            and document['version'] == 'specialist-facts-v1', 'invalid_specialist_facts')
    require(uid(document['case_id']) == str(case_id), 'specialist_fact_case_mismatch')
    as_of = at(document['as_of'])
    facts = document['facts']
    require(type(facts) is list and 1 <= len(facts) <= 128, 'specialist_fact_limit')
    require(len(canonical(document)) <= 65536, 'specialist_fact_limit')
    seen = set()
    for fact in facts:
        require(type(fact) is dict and set(fact) == {'id', 'type', 'evidence_id', 'evidence_digest', 'entity_id', 'event_time', 'data'},
                'invalid_specialist_fact')
        fid = uid(fact['id'])
        require(fid not in seen, 'duplicate_specialist_fact')
        seen.add(fid)
        uid(fact['evidence_id'])
        if fact['entity_id'] is not None:
            uid(fact['entity_id'])
        value = fact['evidence_digest']
        require(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'invalid_specialist_fact_digest')
        require(at(fact['event_time']) <= as_of, 'specialist_fact_after_snapshot')
        kind = fact['type']
        require(type(kind) is str and kind in SCHEMAS, 'unknown_specialist_fact_type')
        data, schema = fact['data'], SCHEMAS[kind]
        require(type(data) is dict and set(data) == set(schema), 'invalid_specialist_fact_fields')
        for key, allowed in schema.items():
            item = data[key]
            if allowed is bool:
                require(type(item) is bool, 'invalid_specialist_fact_value')
            elif allowed is int:
                require(type(item) is int and 1 <= item <= 1000000, 'invalid_specialist_fact_value')
            elif allowed == 'time':
                at(item)
            else:
                require(type(item) is str and item in allowed, 'invalid_specialist_fact_value')
    require(len({fact['evidence_id'] for fact in facts}) <= 32, 'specialist_fact_source_limit')
    return document


def analyze(role, document, input_ref):
    """Summarize typed assertions without treating supplied records as source truth."""
    require(type(role) is str and role in ROLE_TYPES, 'unknown_specialist_role')
    require(type(document) is dict, 'invalid_specialist_facts')
    validate_document(document, document.get('case_id'))
    selected = [fact for fact in document['facts'] if fact['type'] in ROLE_TYPES[role]]
    observations, hypotheses, contradictions = [], [], []
    urgent = False

    def claim(target, statement, rows):
        refs = sorted({'evidence/' + row['evidence_id'] for row in rows}) or [input_ref]
        target.append(dict(statement=statement, references=refs, source_verified=False))

    def note(statement, rows=selected):
        claim(observations, statement, rows)

    def concern(statement, rows):
        nonlocal urgent
        if rows:
            urgent = True
            claim(hypotheses, statement, rows)

    def of(kind):
        return [row for row in selected if row['type'] == kind]

    if role == 'telemetry_health':
        counts = Counter(row['data']['state'] for row in selected)
        note(f"Reported coverage: {counts['available']} available, {counts['stale']} stale, {counts['missing']} missing.")
    elif role == 'alert_triage':
        alerts = of('alert')
        unresolved = [r for r in alerts if r['data']['state'] != 'resolved' and r['data']['severity'] in {'high', 'critical'}]
        note(f'Reported alerts: {len(alerts)}; unresolved high/critical: {len(unresolved)}.', alerts)
        concern('Reported high/critical alert severity warrants prompt analyst review; compromise is unestablished.', unresolved)
    elif role == 'incident_scoping':
        entities = {r['entity_id'] for r in selected if r['entity_id'] is not None}
        ordered = sorted(selected, key=lambda r: (at(r['event_time']), r['id']))
        note(f'Reported scope: {len(entities)} supplied entity keys across {len(selected)} facts; keys do not verify identity.')
        if ordered:
            note('Reported event interval: ' + ordered[0]['event_time'] + ' to ' + ordered[-1]['event_time'] + '.', [ordered[0], ordered[-1]])
    elif role == 'threat_intelligence':
        matches = [r for r in selected if r['data']['match']]
        current = [r for r in matches if at(r['data']['valid_until']) > at(document['as_of'])]
        note(f'Reported indicator matches: {len(matches)}; within supplied validity interval: {len(current)}. Attribution is unverified.')
        concern('A reported current indicator match warrants contextual verification; it does not establish malicious activity.', current)
    elif role == 'threat_hunting':
        categories = {r['data']['category'] for r in of('activity')}
        note(f'Reported activity categories: {len(categories)}. Existing search capabilities must be admitted separately.')
        if selected:
            claim(hypotheses, 'Test whether the supplied activity has an approved administrative explanation using an existing scoped search.', selected)
    elif role == 'dfir_evidence':
        bad = [r for r in selected if r['data']['integrity'] == 'mismatch' or r['data']['custody'] == 'gap']
        note(f'Reported artifact checks: {len(selected)}; integrity/custody discrepancies: {len(bad)}.')
        concern('Reported artifact discrepancies require collection and custody review before reliance.', bad)
    elif role == 'detection_engineering':
        failed = [r for r in selected if r['data']['matched'] != r['data']['expected_match']]
        missed = [r for r in failed if r['data']['expected_match']]
        false = [r for r in failed if not r['data']['expected_match']]
        note(f'Supplied detection-test records: {len(selected)}; expected matches missed: {len(missed)}; unexpected matches: {len(false)}.')
        if failed:
            claim(contradictions, 'Supplied observed and expected detection outcomes disagree; this does not qualify the rule.', failed)
    elif role == 'exposure_vulnerability':
        high = [r for r in selected if r['data']['severity'] in {'high', 'critical'} and r['data']['reachable'] == 'yes' and r['data']['mitigated'] != 'yes']
        note(f'Reported exposure records: {len(selected)}; high/critical, reportedly reachable and not confirmed mitigated: {len(high)}.')
        concern('Review reported reachable high/critical exposures; vulnerability is not evidence of exploitation.', high)
    elif role == 'identity_access':
        changes = [r for r in of('identity') if r['data']['event'] in {'privilege_grant', 'mfa_disabled'} and r['data']['authorized'] != 'yes']
        failures = sum(r['data']['count'] for r in of('activity') if r['data']['category'] == 'authentication' and r['data']['outcome'] == 'failure')
        note(f'Reported sensitive identity changes lacking confirmed authorization: {len(changes)}; supplied authentication-failure counts total: {failures}. Counts may overlap.')
        concern('Verify authorization for reported privilege or MFA changes and investigate session context.', changes)
    elif role == 'cloud_supply_chain':
        findings = [r for r in selected if r['data']['state'] == 'present' and r['data']['authorized'] != 'yes']
        note(f'Reported cloud/component checks: {len(selected)}; present findings lacking confirmed authorization: {len(findings)}.')
        concern('Review reported cloud or component findings against the approved deployment baseline.', findings)
    elif role == 'response_remediation':
        complete = all(any(r['data']['check'] == check and r['data']['passed'] == 'yes' for r in selected)
                       and all(r['data']['passed'] == 'yes' for r in selected if r['data']['check'] == check)
                       for check in SCHEMAS['response_check']['check'])
        note('Reported planning checks are ' + ('complete' if complete else 'incomplete or contradictory') + '; exact-action authorization is not assessed or granted.')
        for check in sorted(SCHEMAS['response_check']['check']):
            rows = [r for r in selected if r['data']['check'] == check]
            if len({r['data']['passed'] for r in rows}) > 1:
                claim(contradictions, 'Reported readiness checks disagree for ' + check + '.', rows)
    elif role == 'recovery_learning':
        failed = [r for r in selected if r['data']['result'] == 'fail']
        current = {r['data']['check'] for r in selected if r['data']['result'] == 'pass' and r['data']['baseline'] == 'current'}
        note(f'Reported recovery checks: {len(selected)}; failures: {len(failed)}; distinct passing checks against supplied current baselines: {len(current)}. Recovery acceptance is unestablished.')
        concern('Reported recovery-validation failures require review before accepting recovery.', failed)

    uncertainty = ['Supplied facts and entity keys are unverified assertions; byte integrity does not establish source truth.',
                   'Coverage is partial and historical at the supplied snapshot time; no clean-environment conclusion is supported.',
                   'Adapter semantics and specialist decision quality require independent acceptance.',
                   'Repeated supplied records are not independent corroboration; reported counts may overlap.']
    if not selected:
        uncertainty.append('No facts relevant to this specialist were supplied; the role abstains from assessment.')
    gaps = [r for r in document['facts'] if r['type'] == 'coverage' and r['data']['state'] != 'available']
    if gaps:
        uncertainty.append('The supplied packet reports stale or missing collection; absent observations cannot exclude activity.')
        claim(observations, 'Reported stale or missing coverage affects interpretation.', gaps)
    urgency = 'urgent_review' if urgent else 'visibility_gap' if gaps or not selected else 'review'
    return dict(schema_version=2, purpose='specialist-result-v2', contract_version=CONTRACT, role=role,
        observations=observations, hypotheses=hypotheses, contradictions=contradictions,
        alternatives=[dict(statement=ALTERNATIVES[role], references=[input_ref], source_verified=False)],
        uncertainty=uncertainty, next_steps=NEXT_STEPS[role], coverage='partial',
        incident_assessment='bounded_rule_review' if selected else 'abstained', attack_status='unknown',
        urgency=urgency, confidence='unqualified', external_actions_authorized=False,
        execution=dict(engine=VERSION, provider=None, model=None, prompt_version=None, playbook_version=VERSION,
                       tools=[dict(name='typed_fact_rules', version=VERSION)], model_cost_usd='0', elapsed_ms=0))
