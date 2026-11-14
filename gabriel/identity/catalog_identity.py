"""Bounded identity evidence calculations, without tenant access or account changes."""
from collections import Counter, defaultdict
from datetime import datetime
from math import asin, cos, radians, sin, sqrt
from gabriel.identity import catalog_identity_extended
from gabriel.identity.specialist_analysis import validate_document
VERSION='gabriel-identity-catalog-v2'
SKILLS={**catalog_identity_extended.SKILLS,**{name:'identity_access' for name in ('identify_dormant_accounts','identify_orphaned_accounts','review_mfa_coverage_bypass','review_impossible_travel_candidates','monitor_privileged_group_membership')}}
def _at(value):return datetime.fromisoformat(value.replace('Z','+00:00'))
def _distance_km(a,b):
    lat1,lon1=map(lambda x:radians(x/1000),(a['latitude_millidegrees'],a['longitude_millidegrees']))
    lat2,lon2=map(lambda x:radians(x/1000),(b['latitude_millidegrees'],b['longitude_millidegrees']))
    chord=sin((lat2-lat1)/2)**2+cos(lat1)*cos(lat2)*sin((lon2-lon1)/2)**2
    return 12742*asin(min(1.0,sqrt(chord)))
def evaluate(name,document):
    if name not in SKILLS:raise ValueError('unknown_catalog_skill')
    if name in catalog_identity_extended.SKILLS:return catalog_identity_extended.evaluate(name,document)
    validate_document(document,document.get('case_id') if type(document) is dict else None)
    facts=document['facts'];accounts=[f for f in facts if f['type']=='identity_account']
    result=dict(version=VERSION,skill=name,role='identity_access',source_authenticity='unverified',
                confidence='unqualified',source_clocks_verified=False,model_used=False,
                external_actions_authorized=False,requires_analyst_review=True,account_change_performed=False)
    if name=='identify_dormant_accounts':
        rows=[f for f in accounts if f['data']['kind']=='human']
        old=[f for f in rows if f['data']['enabled'] and (_at(document['as_of'])-_at(f['data']['last_used'])).days>=90]
        result.update(status='review_required' if rows else 'insufficient_account_evidence',supplied_human_account_count=len(rows),
                      enabled_unused_90_day_count=len(old),last_used_source_verified=False,dormant_account_established=False)
    elif name=='identify_orphaned_accounts':
        result.update(status='review_required' if accounts else 'insufficient_account_evidence',supplied_account_count=len(accounts),
                      enabled_inactive_owner_count=sum(f['data']['enabled'] and f['data']['owner']=='inactive' for f in accounts),
                      enabled_unknown_owner_count=sum(f['data']['enabled'] and f['data']['owner']=='unknown' for f in accounts),
                      owner_directory_verified=False,orphaned_account_established=False)
    elif name=='review_mfa_coverage_bypass':
        rows=[f for f in accounts if f['data']['kind']=='human' and f['data']['enabled']]
        states=Counter(f['data']['mfa'] for f in rows)
        result.update(status='review_required' if rows else 'insufficient_mfa_evidence',supplied_enabled_human_count=len(rows),
                      supplied_mfa_state_counts={k:states[k] for k in ('enforced','bypassed','unenrolled','unknown')},
                      privileged_without_enforced_mfa_count=sum(f['data']['privileged'] and f['data']['mfa']!='enforced' for f in rows),
                      tenant_coverage_verified=False,bypass_policy_verified=False)
    elif name=='monitor_privileged_group_membership':
        rows=[f for f in facts if f['type']=='identity_group_change' and f['data']['privileged']]
        result.update(status='review_required' if rows else 'insufficient_group_change_evidence',supplied_privileged_change_count=len(rows),
                      unapproved_grant_count=sum(f['data']['change']=='grant' and f['data']['approved']=='no' for f in rows),
                      unknown_approval_grant_count=sum(f['data']['change']=='grant' and f['data']['approved']=='unknown' for f in rows),
                      observed_membership_conflict_count=sum((f['data']['change']=='grant' and f['data']['membership_state']=='absent') or
                          (f['data']['change']=='revoke' and f['data']['membership_state']=='present') for f in rows),
                      group_membership_independently_verified=False)
    else:
        groups=defaultdict(list)
        for f in facts:
            if f['type']=='identity_location' and f['data']['login']=='success' and f['entity_id']:groups[f['entity_id']].append(f)
        candidates=0;equal_time=0
        for events in groups.values():
            events.sort(key=lambda f:(_at(f['event_time']),f['id']))
            for a,b in zip(events,events[1:]):
                hours=(_at(b['event_time'])-_at(a['event_time'])).total_seconds()/3600
                if hours<=0:equal_time+=1
                elif _distance_km(a['data'],b['data'])/hours>1000:candidates+=1
        count=sum(map(len,groups.values()))
        result.update(status='review_required' if count else 'insufficient_location_evidence',supplied_successful_location_count=count,
                      reported_impossible_travel_candidate_count=candidates,equal_time_pair_count=equal_time,
                      entity_identity_verified=False,geolocation_accuracy_verified=False,impossible_travel_established=False,
                      threshold_km_per_hour=1000)
    return result
