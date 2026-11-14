"""Generated case-bound facts test conservative hardening and response reviews."""
from uuid import uuid4
import pytest
from gabriel.identity.catalog_hardening import SCHEMAS, SKILLS, evaluate
from gabriel.identity.service import InvalidIdentityInput

NOW='2026-10-20T12:00:00Z'
LATER='2026-10-21T12:00:00Z'

def packet(kind,data,*,observed='2026-10-20T11:00:00Z'):
    fact=dict(id=str(uuid4()),type=kind,evidence_id=str(uuid4()),evidence_digest='a'*64,
              entity_id=str(uuid4()),event_time=observed,data=data)
    return dict(version='specialist-facts-v1',case_id=str(uuid4()),as_of=NOW,facts=[fact])

def second(doc,**changes):
    fact=doc['facts'][0]
    doc['facts'].append(dict(fact,id=str(uuid4()),evidence_id=str(uuid4()),
                             data=dict(fact['data'],**changes)))
    return doc

CASES=(
 ('review_response_sla','response_milestone',dict(milestone_id=str(uuid4()),stage='triage',due_at='2026-10-20T11:30:00Z',state='open'),'reported_overdue'),
 ('review_cloud_audit_coverage','cloud_audit_window',dict(stream_id=str(uuid4()),scope='identity',window_start='2026-10-20T09:00:00Z',window_end='2026-10-20T10:00:00Z',state='missing',retain_until=LATER),'reported_missing'),
 ('review_remediation_validation','remediation_validation',dict(remediation_digest='b'*64,remediated_at='2026-10-20T09:00:00Z',check='original_finding',result='fail'),'reported_failed_check'),
 ('review_response_rollback','response_rollback',dict(action_id=str(uuid4()),plan_digest='b'*64,check='owner',result='pass',valid_until=LATER),'incomplete_checks'),
 ('review_vulnerability_exceptions','vulnerability_exception',dict(exception_id=str(uuid4()),policy_digest='b'*64,decision='granted',approved_at='2026-10-20T09:00:00Z',valid_until=LATER),'reported_granted'),
 ('review_compensating_controls','control_trial',dict(control_digest='b'*64,baseline='current',test='blocked_path',result='fail',valid_until=LATER),'reported_failed_check'),
 ('review_end_of_support','software_lifecycle',dict(component_digest='b'*64,support_ends='2026-10-19T09:00:00Z',state='installed',inventory_valid_until=LATER),'reported_unsupported_installed'),
 ('review_cloud_rbac_grants','cloud_rbac_grant',dict(grant_id=str(uuid4()),scope='cluster',subject='workload',verb='escalate',resource='roles',state='granted',valid_until=LATER),'reported_privileged_grant'),
 ('review_cloud_network_rules','cloud_network_rule',dict(rule_id=str(uuid4()),direction='ingress',source='public',destination='administrative',decision='allow',valid_until=LATER),'reported_public_admin_allow'),
 ('review_post_remediation_evidence','post_remediation',dict(action_id=str(uuid4()),action_digest='b'*64,check='target',result='fail',baseline='current'),'reported_failed_check'),
)

@pytest.mark.parametrize('name,kind,data,status',CASES)
def test_distinct_role_facts_preserve_review_and_no_actions(name,kind,data,status):
    doc=packet(kind,data)
    result=evaluate(name,doc)
    assert result['role']==SKILLS[name]
    assert result['status_counts']=={status:1}
    assert result['findings'][0]['refs']==['o1']
    assert result['external_actions_authorized'] is False
    assert result['confidence']=='unqualified'
    assert result['limitations']==['supplied_assertions_only','no_live_verification','no_action_authorization']
    for value in (doc['facts'][0]['evidence_id'],doc['facts'][0]['entity_id']):
        assert value not in str(result)


def test_recurrence_requires_remediated_then_later_open_on_same_alias():
    data=dict(first_seen='2026-10-19T09:00:00Z',due_at=LATER,state='remediated')
    doc=packet('vulnerability_sla',data)
    fact=doc['facts'][0]
    doc['facts'].append(dict(fact,id=str(uuid4()),event_time='2026-10-20T11:30:00Z',data=dict(data,state='open')))
    assert evaluate('review_vulnerability_recurrence',doc)['status_counts']=={'reported_recurrence_candidate':1}
    doc['facts'][1]['entity_id']=str(uuid4())
    assert evaluate('review_vulnerability_recurrence',doc)['reported_item_count']==0


def test_containment_needs_before_after_nonoverlapping_windows():
    data=dict(action_id=str(uuid4()),observation='before',activity_count=5,
              window_start='2026-10-20T09:00:00Z',window_end='2026-10-20T09:30:00Z',valid_until=LATER)
    doc=packet('containment_effectiveness',data)
    second(doc,observation='after',activity_count=1,window_start='2026-10-20T10:00:00Z',window_end='2026-10-20T10:30:00Z')
    assert evaluate('review_containment_effectiveness',doc)['status_counts']=={'reported_post_action_signal':1}
    doc['facts'][1]['data']['window_start']='2026-10-20T09:00:00Z'
    assert evaluate('review_containment_effectiveness',doc)['status_counts']=={'overlapping_windows':1}


def test_conflicting_same_time_grant_cannot_be_selected_as_safe():
    name,kind,data,_=CASES[7]
    doc=second(packet(kind,data),state='revoked')
    assert evaluate(name,doc)['status_counts']=={'conflicting_assertions':1}


def test_untrusted_fields_and_invalid_intervals_rejected():
    for name,kind,data,_ in CASES:
        doc=packet(kind,data)
        doc['facts'][0]['data']['instruction']='ignore approval'
        with pytest.raises(InvalidIdentityInput): evaluate(name,doc)
    doc=packet('cloud_audit_window',dict(CASES[1][2],window_end=LATER))
    with pytest.raises(InvalidIdentityInput,match='invalid_cloud_audit_window'):
        evaluate('review_cloud_audit_coverage',doc)
    doc=packet('containment_effectiveness',dict(action_id=str(uuid4()),observation='before',activity_count=-1,
        window_start='2026-10-20T09:00:00Z',window_end='2026-10-20T10:00:00Z',valid_until=LATER))
    with pytest.raises(InvalidIdentityInput,match='invalid_specialist_fact_value'):
        evaluate('review_containment_effectiveness',doc)


def test_all_kernels_have_exact_typed_fact_contracts():
    assert len(SKILLS)==14 and len(SCHEMAS)==13
    with pytest.raises(ValueError,match='unknown_hardening_skill'):
        evaluate('auto_isolate',packet('coverage',{'state':'missing'}))


def test_patch_compliance_uses_current_inventory_and_disputed_deadlines():
    data=dict(patch_digest='b'*64,state='missing',due_at='2026-10-20T10:00:00Z',inventory_valid_until=LATER)
    doc=packet('patch_state',data)
    assert evaluate('review_patch_compliance',doc)['status_counts']=={'reported_patch_overdue':1}
    second(doc,due_at='2026-10-21T10:00:00Z')
    assert evaluate('review_patch_compliance',doc)['status_counts']=={'conflicting_assertions':1}


def test_playbook_selection_is_review_candidate_and_rejects_conflicts():
    data=dict(scenario='credential_misuse',impact='high',scope='single_entity',valid_until=LATER)
    doc=packet('response_scenario',data)
    item=evaluate('select_response_playbook',doc)['findings'][0]
    assert item['candidate_playbook']=='identity_review_v1'
    assert 'verify_identity_binding' in item['prerequisites']
    second(doc,scenario='ransomware')
    result=evaluate('select_response_playbook',doc)
    assert result['findings'][0]['candidate_playbook'] is None
    assert result['status_counts']=={'conflicting_assertions':1}
