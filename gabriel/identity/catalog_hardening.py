"""Conservative, local reviews of case-bound hardening and response evidence."""
from collections import Counter, defaultdict
from datetime import datetime

SKILLS = {
    'review_vulnerability_recurrence': 'exposure_vulnerability',
    'review_remediation_validation': 'exposure_vulnerability',
    'review_vulnerability_exceptions': 'exposure_vulnerability',
    'review_compensating_controls': 'exposure_vulnerability',
    'review_end_of_support': 'exposure_vulnerability',
    'review_patch_compliance': 'exposure_vulnerability',
    'review_response_sla': 'response_remediation',
    'review_response_rollback': 'response_remediation',
    'review_containment_effectiveness': 'response_remediation',
    'review_post_remediation_evidence': 'response_remediation',
    'select_response_playbook': 'response_remediation',
    'review_cloud_audit_coverage': 'cloud_supply_chain',
    'review_cloud_rbac_grants': 'cloud_supply_chain',
    'review_cloud_network_rules': 'cloud_supply_chain',
}
SCHEMAS = {
    'response_milestone': {'milestone_id':'uuid','stage':{'triage','containment','eradication','recovery'},'due_at':'time','state':{'open','completed','unknown'}},
    'cloud_audit_window': {'stream_id':'uuid','scope':{'activity','configuration','identity'},'window_start':'time','window_end':'time','state':{'available','partial','missing','unknown'},'retain_until':'time'},
    'remediation_validation': {'remediation_digest':'digest','remediated_at':'time','check':{'original_finding','regression','control_integrity'},'result':{'pass','fail','unknown'}},
    'response_rollback': {'action_id':'uuid','plan_digest':'digest','check':{'owner','dependencies','rollback_test'},'result':{'pass','fail','unknown'},'valid_until':'time'},
    'vulnerability_exception': {'exception_id':'uuid','policy_digest':'digest','decision':{'granted','denied','revoked','unknown'},'approved_at':'time','valid_until':'time'},
    'control_trial': {'control_digest':'digest','baseline':{'current','stale','unknown'},'test':{'blocked_path','monitoring','recovery'},'result':{'pass','fail','unknown'},'valid_until':'time'},
    'software_lifecycle': {'component_digest':'digest','support_ends':'time','state':{'installed','removed','unknown'},'inventory_valid_until':'time'},
    'cloud_rbac_grant': {'grant_id':'uuid','scope':{'cluster','namespace','resource'},'subject':{'human','service','workload','unknown'},'verb':{'all','read','write','escalate'},'resource':{'all','secrets','workloads','roles','other'},'state':{'granted','revoked','unknown'},'valid_until':'time'},
    'cloud_network_rule': {'rule_id':'uuid','direction':{'ingress','egress'},'source':{'public','private','unknown'},'destination':{'administrative','datastore','application','other'},'decision':{'allow','deny','unknown'},'valid_until':'time'},
    'containment_effectiveness': {'action_id':'uuid','observation':{'before','after'},'activity_count':'zero_to_million','window_start':'time','window_end':'time','valid_until':'time'},
    'post_remediation': {'action_id':'uuid','action_digest':'digest','check':{'target','original_signal','control_health','rollback'},'result':{'pass','fail','unknown'},'baseline':{'current','stale','unknown'}},
    'patch_state': {'patch_digest':'digest','state':{'applied','missing','unknown'},'due_at':'time','inventory_valid_until':'time'},
    'response_scenario': {'scenario':{'ransomware','credential_misuse','phishing','cloud_change'},'impact':{'low','medium','high','critical','unknown'},'scope':{'single_entity','multiple_entities','unknown'},'valid_until':'time'},
}
ROLE_TYPES = {
    'exposure_vulnerability': {'remediation_validation','vulnerability_exception','control_trial','software_lifecycle','patch_state'},
    'response_remediation': {'response_milestone','response_rollback','containment_effectiveness','post_remediation','response_scenario'},
    'cloud_supply_chain': {'cloud_audit_window','cloud_rbac_grant','cloud_network_rule'},
}


def _at(value):
    return datetime.fromisoformat(value.replace('Z','+00:00'))


def validate_fact(fact):
    from gabriel.identity.specialist_analysis import require
    kind, data, observed = fact['type'], fact['data'], _at(fact['event_time'])
    require(fact['entity_id'] is not None, 'hardening_entity_alias_required')
    if kind == 'remediation_validation':
        require(_at(data['remediated_at']) <= observed, 'validation_before_remediation')
    elif kind == 'cloud_audit_window':
        require(_at(data['window_start']) < _at(data['window_end']) <= observed, 'invalid_cloud_audit_window')
    elif kind == 'containment_effectiveness':
        require(_at(data['window_start']) < _at(data['window_end']) <= observed, 'invalid_containment_window')
    if kind == 'vulnerability_exception':
        require(_at(data['approved_at']) <= observed, 'invalid_exception_interval')
    end = data.get('inventory_valid_until',data.get('valid_until'))
    if end is not None:
        require(observed < _at(end), 'invalid_hardening_observation_interval')


def _selected(document, role):
    from gabriel.identity.specialist_analysis import ROLE_TYPES as ADMITTED
    return [(f,'o'+str(i)) for i,f in enumerate((f for f in document['facts'] if f['type'] in ADMITTED[role] | {'coverage'}),1)]


def _group(rows, kind, key):
    grouped = defaultdict(list)
    for fact,ref in rows:
        if fact['type'] == kind:
            grouped[(fact['entity_id'],fact['data'][key])].append((fact,ref))
    return list(grouped.values())


def _latest(rows):
    instant = max(_at(f['event_time']) for f,_ in rows)
    return [(f,ref) for f,ref in rows if _at(f['event_time']) == instant]


def _result(name, details, *, limitations=()):
    counts = Counter(d['status'] for d in details)
    details.sort(key=lambda d:(0 if d['status'].startswith(('conflicting','reported_','expired')) else 1,d['refs'][0] if d['refs'] else ''))
    return dict(version='gabriel-hardening-review-v1',skill=name,role=SKILLS[name],
        status='review_required' if details else 'no_applicable_role_facts',
        reported_item_count=len(details),status_counts=dict(sorted(counts.items())),
        findings=details[:4],omitted_finding_count=max(0,len(details)-4),
        limitations=list(limitations),source_authenticity='unverified',confidence='unqualified',
        incident_status='unknown',external_actions_authorized=False,model_used=False,
        requires_analyst_review=True)


def evaluate(name, document, *, verified_refs=None):
    from gabriel.identity.specialist_analysis import validate_document
    if name not in SKILLS: raise ValueError('unknown_hardening_skill')
    validate_document(document, document.get('case_id') if type(document) is dict else None)
    rows = _selected(document,SKILLS[name])
    now = _at(document['as_of'])
    handler = HANDLERS[name]
    return _result(name,handler(rows,now),limitations=('supplied_assertions_only','no_live_verification','no_action_authorization'))


def _recurrence(rows,now):
    out=[]
    for reports in _group(rows,'vulnerability_sla','first_seen'):
        reports.sort(key=lambda row:(_at(row[0]['event_time']),row[1]))
        times=defaultdict(set)
        for fact,_ in reports: times[fact['event_time']].add(fact['data']['state'])
        repaired=None
        for fact,ref in reports:
            state=fact['data']['state']
            if len(times[fact['event_time']])>1 or state=='unknown': repaired=None
            elif state=='remediated': repaired=ref
            elif state=='open' and repaired:
                out.append(dict(status='reported_recurrence_candidate',refs=[repaired,ref]));repaired=None
    return out


def _deadline(rows,now):
    out=[]
    for reports in _group(rows,'response_milestone','milestone_id'):
        latest=_latest(reports)
        due={f['data']['due_at'] for f,_ in reports}
        states={f['data']['state'] for f,_ in latest}
        completions={f['event_time'] for f,_ in reports if f['data']['state']=='completed'}
        if len(due)>1 or len(states)>1 or len(completions)>1 or completions and states=={'open'}: status='conflicting_assertions'
        elif states=={'unknown'}: status='unknown_milestone'
        elif completions: status='reported_completed_late' if _at(next(iter(completions)))>_at(next(iter(due))) else 'reported_completed_on_time'
        else: status='reported_overdue' if now>_at(next(iter(due))) else 'reported_open_within_deadline'
        out.append(dict(status=status,refs=[ref for _,ref in latest[:2]]))
    return out


def _audit(rows,now):
    grouped=defaultdict(list)
    for fact,ref in rows:
        if fact['type']=='cloud_audit_window':
            d=fact['data'];grouped[(fact['entity_id'],d['stream_id'],d['scope'],d['window_start'],d['window_end'])].append((fact,ref))
    out=[]
    for reports in grouped.values():
        states={f['data']['state'] for f,_ in reports}
        if len(states)>1: status='conflicting_assertions'
        elif states=={'missing'}: status='reported_missing'
        elif states=={'partial'}: status='reported_partial'
        elif states=={'unknown'}: status='unknown_audit_window'
        elif any(_at(f['data']['retain_until'])<=now for f,_ in reports): status='expired_retention'
        else: status='reported_available_unverified'
        out.append(dict(status=status,refs=[ref for _,ref in reports[:2]]))
    return out


def _checklist(rows,kind,key,required,*,baseline=False,expiry=False):
    out=[]
    for reports in _group(rows,kind,key):
        checks=defaultdict(set)
        for f,_ in reports:
            d=f['data'];checks[d['check']].add((d['result'],d.get('baseline')))
        missing=sorted(set(required)-checks.keys())
        if any(len(v)>1 for v in checks.values()): status='conflicting_assertions'
        elif any(f['data']['result']=='fail' for f,_ in reports): status='reported_failed_check'
        elif expiry and any(_at(f['data']['valid_until'])<=expiry for f,_ in reports): status='expired_check'
        elif missing or any(f['data']['result']=='unknown' or baseline and f['data']['baseline']!='current' for f,_ in reports): status='incomplete_checks'
        else: status='reported_checks_passed_unverified'
        out.append(dict(status=status,missing_checks=missing,refs=[ref for _,ref in reports[:4]]))
    return out


def _remediation(rows,now):
    return _checklist(rows,'remediation_validation','remediation_digest',('original_finding','regression','control_integrity'))


def _rollback(rows,now):
    return _checklist(rows,'response_rollback','action_id',('owner','dependencies','rollback_test'),expiry=now)


def _control(rows,now):
    return _checklist(rows,'control_trial','control_digest',('blocked_path','monitoring','recovery'),baseline=True,expiry=now)


def _post(rows,now):
    return _checklist(rows,'post_remediation','action_id',('target','original_signal','control_health','rollback'),baseline=True)


def _exceptions(rows,now):
    out=[]
    for reports in _group(rows,'vulnerability_exception','exception_id'):
        latest=_latest(reports);decisions={f['data']['decision'] for f,_ in latest}
        policies={f['data']['policy_digest'] for f,_ in reports}
        if len(decisions)>1 or len(policies)>1: status='conflicting_assertions'
        elif any(_at(f['data']['valid_until'])<=now for f,_ in latest): status='expired_exception'
        else: status='reported_'+next(iter(decisions))
        out.append(dict(status=status,refs=[ref for _,ref in latest[:2]]))
    return out


def _support(rows,now):
    out=[]
    for reports in _group(rows,'software_lifecycle','component_digest'):
        latest=_latest(reports);states={f['data']['state'] for f,_ in latest}
        dates={f['data']['support_ends'] for f,_ in latest}
        if len(states)>1 or len(dates)>1: status='conflicting_assertions'
        elif any(_at(f['data']['inventory_valid_until'])<=now for f,_ in latest): status='stale_inventory'
        elif states=={'installed'} and _at(next(iter(dates)))<=now: status='reported_unsupported_installed'
        elif states=={'installed'}: status='reported_installed_within_support'
        else: status='installation_unestablished'
        out.append(dict(status=status,refs=[ref for _,ref in latest[:2]]))
    return out


def _rbac(rows,now):
    out=[]
    for reports in _group(rows,'cloud_rbac_grant','grant_id'):
        latest=_latest(reports);assertions={tuple(sorted(f['data'].items())) for f,_ in latest};d=latest[0][0]['data']
        if len(assertions)>1: status='conflicting_assertions'
        elif any(_at(f['data']['valid_until'])<=now for f,_ in latest): status='stale_grant'
        elif d['state']=='granted' and d['scope']=='cluster' and d['verb'] in {'all','escalate'}: status='reported_privileged_grant'
        elif d['state']=='granted' and d['resource']=='secrets' and d['verb'] in {'all','read'}: status='reported_sensitive_read_grant'
        else: status='review_other_grant_state'
        out.append(dict(status=status,refs=[ref for _,ref in latest[:2]]))
    return out


def _network(rows,now):
    out=[]
    for reports in _group(rows,'cloud_network_rule','rule_id'):
        latest=_latest(reports);assertions={tuple(sorted(f['data'].items())) for f,_ in latest};d=latest[0][0]['data']
        if len(assertions)>1: status='conflicting_assertions'
        elif any(_at(f['data']['valid_until'])<=now for f,_ in latest): status='stale_rule'
        elif d['direction']=='ingress' and d['source']=='public' and d['destination'] in {'administrative','datastore'} and d['decision']=='allow': status='reported_public_admin_allow'
        elif 'unknown' in (d['source'],d['decision']): status='ambiguous_rule_scope'
        else: status='review_other_rule_state'
        out.append(dict(status=status,refs=[ref for _,ref in latest[:2]]))
    return out


def _containment(rows,now):
    grouped=defaultdict(lambda:defaultdict(list))
    for f,ref in rows:
        if f['type']=='containment_effectiveness': grouped[(f['entity_id'],f['data']['action_id'])][f['data']['observation']].append((f,ref))
    out=[]
    for windows in grouped.values():
        before,after=windows['before'],windows['after'];refs=[ref for _,ref in before[:1]+after[:1]]
        if not before or not after: status='missing_comparison_window'
        elif len(before)!=1 or len(after)!=1: status='ambiguous_comparison_windows'
        elif _at(before[0][0]['data']['window_end'])>_at(after[0][0]['data']['window_start']): status='overlapping_windows'
        elif any(_at(f['data']['valid_until'])<=now for f,_ in before+after): status='stale_comparison'
        elif before[0][0]['data']['activity_count']==0: status='no_pre_action_signal'
        elif after[0][0]['data']['activity_count']>0: status='reported_post_action_signal'
        else: status='reported_no_post_action_signal_unverified'
        out.append(dict(status=status,refs=refs))
    return out


def _patch(rows,now):
    out=[]
    for reports in _group(rows,'patch_state','patch_digest'):
        latest=_latest(reports)
        states={f['data']['state'] for f,_ in latest}
        dates={f['data']['due_at'] for f,_ in reports}
        if len(states)>1 or len(dates)>1: status='conflicting_assertions'
        elif any(_at(f['data']['inventory_valid_until'])<=now for f,_ in latest): status='stale_patch_inventory'
        elif states=={'missing'} and _at(next(iter(dates)))<now: status='reported_patch_overdue'
        elif states=={'missing'}: status='reported_patch_missing_within_deadline'
        elif states=={'applied'}: status='reported_patch_applied_unverified'
        else: status='unknown_patch_state'
        out.append(dict(status=status,refs=[ref for _,ref in latest[:2]]))
    return out


PLAYBOOKS={
    'ransomware':('ransomware_review_v1',('preserve_artifacts','check_scope','review_recovery_dependencies')),
    'credential_misuse':('identity_review_v1',('verify_identity_binding','check_session_scope','review_recovery_dependencies')),
    'phishing':('message_scope_review_v1',('verify_message_provenance','review_recipient_scope','preserve_artifacts')),
    'cloud_change':('cloud_config_review_v1',('verify_configuration_source','check_resource_scope','review_rollback')),
}


def _playbook(rows,now):
    grouped=defaultdict(list)
    for f,ref in rows:
        if f['type']=='response_scenario': grouped[f['entity_id']].append((f,ref))
    out=[]
    for reports in grouped.values():
        latest=_latest(reports)
        scenarios={tuple(sorted(f['data'].items())) for f,_ in latest}
        d=latest[0][0]['data']
        if len(scenarios)>1: status,playbook,checks='conflicting_assertions',None,()
        elif _at(d['valid_until'])<=now: status,playbook,checks='stale_scenario',None,()
        else:
            playbook,checks=PLAYBOOKS[d['scenario']]
            status='candidate_for_analyst_review'
        out.append(dict(status=status,candidate_playbook=playbook,prerequisites=list(checks),
                        refs=[ref for _,ref in latest[:2]]))
    return out

HANDLERS = {
    'review_vulnerability_recurrence':_recurrence,
    'review_response_sla':_deadline,
    'review_cloud_audit_coverage':_audit,
    'review_remediation_validation':_remediation,
    'review_response_rollback':_rollback,
    'review_vulnerability_exceptions':_exceptions,
    'review_compensating_controls':_control,
    'review_end_of_support':_support,
    'review_cloud_rbac_grants':_rbac,
    'review_cloud_network_rules':_network,
    'review_containment_effectiveness':_containment,
    'review_post_remediation_evidence':_post,
    'review_patch_compliance':_patch,
    'select_response_playbook':_playbook,
}
