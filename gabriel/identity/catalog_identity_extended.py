"""Distinct bounded identity reviews over typed, case-linked assertions."""
from collections import defaultdict
from datetime import datetime
from gabriel.identity.specialist_analysis import validate_document
SKILLS={name:'identity_access' for name in ('review_active_directory_posture','review_entra_id_posture','analyze_service_account_security','review_non_human_identity_governance','assess_conditional_access_policy','analyze_privilege_escalation_paths','identify_excessive_permissions','analyze_oauth_application_permissions','detect_suspicious_token_usage','investigate_session_hijacking_indicators','verify_identity_lifecycle_controls','review_joiner_mover_leaver_access','assess_federation_sso_configuration','evaluate_zero_trust_access_policy')}
def _at(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
def evaluate(name,document):
 if name not in SKILLS:raise ValueError('unknown_catalog_skill')
 validate_document(document,document.get('case_id') if type(document) is dict else None)
 facts=document['facts'];of=lambda kind:[f for f in facts if f['type']==kind]
 out=dict(version='identity-v3',skill=name,role='identity_access',source_authenticity='unverified',confidence='unqualified',model_used=False,requires_analyst_review=True,external_actions_authorized=False)
 if name in ('review_active_directory_posture','review_entra_id_posture'):
  platform='active_directory' if name=='review_active_directory_posture' else 'entra_id'
  expected={'ldap_signing','legacy_auth','privileged_review','password_protection'} if platform=='active_directory' else {'legacy_auth','conditional_access','app_consent','mfa_registration'}
  rows=[f for f in of('directory_control') if f['data']['platform']==platform]
  out.update(status='review_required' if rows else 'insufficient_directory_evidence',platform=platform,missing_control_types=sorted(expected-{f['data']['control'] for f in rows}),reported_gap_count=sum(f['data']['state']=='gap' for f in rows),stale_or_unknown_baseline_count=sum(f['data']['baseline']!='current' for f in rows),conflicting_control_count=sum(len({f['data']['state'] for f in rows if f['data']['control']==key})>1 for key in expected),directory_posture_established=False)
 elif name in ('analyze_service_account_security','review_non_human_identity_governance'):
  rows=of('identity_workload');enabled=[f for f in rows if f['data']['enabled']]
  if name=='analyze_service_account_security':
   selected=[f for f in enabled if f['data']['kind']=='service']
   out.update(status='review_required' if rows else 'insufficient_workload_evidence',supplied_service_count=len(selected),interactive_login_count=sum(f['data']['interactive_login'] for f in selected),rotation_older_than_90_days_count=sum((_at(document['as_of'])-_at(f['data']['last_rotated'])).days>=90 for f in selected),credential_rotation_verified=False,interactive_use_approved=False)
  else:
   out.update(status='review_required' if rows else 'insufficient_workload_evidence',supplied_nonhuman_count=len(rows),enabled_owner_not_active_count=sum(f['data']['owner']!='active' for f in enabled),enabled_without_workload_binding_count=sum(not f['data']['workload_bound'] for f in enabled),non_human_inventory_complete=False)
 elif name in ('assess_conditional_access_policy','evaluate_zero_trust_access_policy'):
  rows=of('identity_policy');active=[f for f in rows if f['data']['mode']=='enforced']
  out.update(status='review_required' if rows else 'insufficient_policy_evidence',enforced_policy_count=len(active),disabled_or_report_only_count=len(rows)-len(active),privileged_exception_count=sum(f['data']['scope']=='privileged' and f['data']['exception']=='yes' for f in rows),missing_mfa_requirement_count=sum(f['data']['requires_mfa']!='yes' for f in active),effective_policy_verified=False)
  if name=='evaluate_zero_trust_access_policy':out.update(missing_device_requirement_count=sum(f['data']['requires_healthy_device']!='yes' for f in active),all_resource_enforcement_reported=any(f['data']['scope']=='all' for f in active),continuous_verification_established=False)
  else:out.update(unknown_scope_count=sum(f['data']['scope']=='unknown' for f in rows),conditional_access_coverage_established=False)
 elif name=='analyze_privilege_escalation_paths':
  rows=[f for f in of('identity_edge') if f['data']['active'] and f['entity_id']];adj=defaultdict(list)
  for f in rows:adj[f['entity_id']].append(f)
  paths=sum(not f['data']['privileged_target'] and g['data']['privileged_target'] for f in rows for g in adj[f['data']['target_id']])
  out.update(status='review_required' if rows else 'insufficient_entitlement_graph',supplied_active_edge_count=len(rows),direct_privileged_edges=sum(f['data']['privileged_target'] for f in rows),two_hop_privileged_path_candidates=paths,max_hops_evaluated=2,path_exploitability_established=False)
 elif name=='identify_excessive_permissions':
  rows=[f for f in of('identity_permission') if f['data']['active']]
  out.update(status='review_required' if rows else 'insufficient_permission_evidence',active_admin_not_needed_count=sum(f['data']['level']=='admin' and f['data']['needed']=='no' for f in rows),admin_need_unknown_count=sum(f['data']['level']=='admin' and f['data']['needed']=='unknown' for f in rows),business_need_independently_verified=False)
 elif name=='analyze_oauth_application_permissions':
  rows=[f for f in of('identity_oauth') if f['data']['state']=='active']
  out.update(status='review_required' if rows else 'insufficient_oauth_evidence',broad_manage_grant_count=sum(f['data']['scope']=='manage' and f['data']['resource_scope']=='all' for f in rows),unapproved_grant_count=sum(f['data']['consent']=='no' for f in rows),publisher_unverified_count=sum(f['data']['publisher_verified']!='yes' for f in rows),grant_effectiveness_verified=False)
 elif name=='detect_suspicious_token_usage':
  rows=of('identity_token')
  out.update(status='review_required' if rows else 'insufficient_token_evidence',revoked_success_count=sum(f['data']['state']=='revoked' and f['data']['outcome']=='success' for f in rows),unexpected_audience_success_count=sum(f['data']['audience']=='unexpected' and f['data']['outcome']=='success' for f in rows),token_compromise_established=False)
 elif name=='investigate_session_hijacking_indicators':
  rows=of('identity_session');groups=defaultdict(list)
  for f in rows:groups[f['data']['session_id']].append(f)
  switches=0
  for events in groups.values():
   events.sort(key=lambda f:(_at(f['event_time']),f['id']))
   switches+=sum(a['data']['device']=='known' and b['data']['device']=='new' and b['data']['outcome']=='success' and b['data']['mfa']!='yes' for a,b in zip(events,events[1:]))
  out.update(status='review_required' if rows else 'insufficient_session_evidence',same_session_device_switch_candidate_count=switches,new_device_without_mfa_count=sum(f['data']['device']=='new' and f['data']['mfa']!='yes' and f['data']['outcome']=='success' for f in rows),session_binding_verified=False,hijacking_established=False)
 elif name in ('verify_identity_lifecycle_controls','review_joiner_mover_leaver_access'):
  rows=of('identity_lifecycle');groups=defaultdict(list)
  for f in rows:
   if f['entity_id']:groups[f['entity_id']].append(f)
  post=missing=0
  for events in groups.values():
   events.sort(key=lambda f:(_at(f['event_time']),f['id']))
   for i,f in enumerate(events):
    if f['data']['event']=='leave':
     later=events[i+1:];post+=sum(x['data']['event']=='grant' for x in later);missing+=not any(x['data']['event']=='revoke' for x in later)
  out.update(status='review_required' if rows else 'insufficient_lifecycle_evidence',post_leave_grant_count=post,unapproved_change_count=sum(f['data']['event'] in ('move','grant') and f['data']['approved']=='no' for f in rows),owner_hr_state_verified=False)
  if name=='review_joiner_mover_leaver_access':out.update(leave_without_later_revoke_count=missing,jml_compliance_established=False)
  else:out.update(unknown_approval_change_count=sum(f['data']['approved']=='unknown' for f in rows),lifecycle_control_effectiveness_established=False)
 else:
  rows=[f for f in of('identity_federation') if f['data']['mode']=='active']
  out.update(status='review_required' if rows else 'insufficient_federation_evidence',unsigned_metadata_count=sum(f['data']['metadata_signed']!='yes' for f in rows),expired_or_unknown_certificate_count=sum(f['data']['certificate']!='current' for f in rows),unverified_endpoint_count=sum(f['data']['endpoint_verified']!='yes' for f in rows),federation_chain_independently_verified=False)
 return out
