"""Source-bound receipt/visibility facts for a frozen selection of browser tabs.

Unknown dashboards supply no incident semantics. Their visible text stays local;
models receive only capture-integrity assertions and an explicit coverage gap.
"""
from uuid import uuid5
from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,connection,identifier
from gabriel.identity.specialist_analysis import validate_document

VERSION='browser-hermes-snapshot-v1'


def capture_facts(observation,artifact):
    """These two claims concern the receipt, never the truth of page content."""
    parent=identifier(observation['id'])
    common=dict(evidence_id=str(artifact['id']),evidence_digest=artifact['digest'],entity_id=None,
        event_time=iso(observation['observed_at']))
    return [dict(common,id=str(uuid5(parent,VERSION+'/integrity')),type='artifact',data=dict(integrity='match',custody='unknown')),
        dict(common,id=str(uuid5(parent,VERSION+'/coverage')),type='coverage',data=dict(state='missing'))]


def selected(value):
    if type(value) not in {list,tuple} or not 1<=len(value)<=8:raise InvalidIdentityInput('invalid_hermes_tab_selection')
    ids=[identifier(v) for v in value]
    if len(set(ids))!=len(ids):raise InvalidIdentityInput('invalid_hermes_tab_selection')
    return sorted(ids,key=str)


def snapshot(service,conn,p,case_id,lease_ids):
    from gabriel.identity.browser_navigation import BrowserNavigationService,pending_navigation
    browser=BrowserNavigationService(service._dsn,service.store)
    facts=[];captures=[]
    for lease_id in selected(lease_ids):
        lease=conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',(p.organization_id,lease_id)).fetchone()
        if not lease or lease['case_id']!=case_id or lease['issued_by']!=p.user_id:raise AccessDenied('hermes_selected_tab_not_owned')
        state=browser._browser_lease_status(conn,p,lease)
        if not state['authorization_current'] or not state['heartbeat_fresh'] or lease['state']!='active' or not lease['intake_enabled']:
            raise AccessDenied('hermes_selected_tab_not_current')
        if pending_navigation(conn,p.organization_id,lease_id):raise AccessDenied('hermes_navigation_outcome_unresolved')
        observation=conn.execute('''SELECT o.*,r.created_at AS received_at,clock_timestamp()-o.observed_at AS age,
            clock_timestamp()-r.created_at AS capture_age FROM gabriel_identity.browser_observations o
            JOIN gabriel_identity.browser_observation_receipts r ON (r.organization_id,r.observation_id,r.evidence_id)=(o.organization_id,o.id,o.evidence_id)
            WHERE o.organization_id=%s AND o.lease_id=%s AND o.state='captured' ORDER BY o.sequence DESC LIMIT 1''',(p.organization_id,lease_id)).fetchone()
        if not observation or not 0<=observation['age'].total_seconds()<=120 or not 0<=observation['capture_age'].total_seconds()<=120:
            raise AccessDenied('hermes_fresh_tab_read_required')
        artifact=service._evidence(conn,p,observation['evidence_id'])
        content=service._verify(conn,artifact).decode('utf-8')
        import re
        if re.search(r'(?im)^\s*(?:sign in to continue|session expired|access denied|authentication required)\s*$',content):
            raise AccessDenied('hermes_dashboard_access_wall')
        if artifact['case_id']!=case_id or artifact['digest']!=observation['content_digest']:
            raise AccessDenied('hermes_capture_binding_mismatch')
        facts.extend(capture_facts(observation,artifact));captures.append(observation)
    document=dict(version='specialist-facts-v1',case_id=str(case_id),as_of=iso(max(o['received_at'] for o in captures)),facts=facts)
    validate_document(document,case_id)
    return document,captures


def prepare(service,token,case_id,lease_ids):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True,content=True)
        case=service._case(conn,p,case_id,open_only=True)
        document,captures=snapshot(service,conn,p,case['id'],lease_ids)
    # Fixed capture IDs make repeated preparation idempotent without changing age.
    request=uuid5(identifier(case_id),VERSION+'/'+digest([str(o['id']) for o in captures]))
    holder=service.acquire(token,case_id,request,canonical(document).decode(),'Browser scoped Hermes receipt facts',
        approved=True,parent_id=captures[0]['evidence_id'],redaction_state='user_declared_redacted')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True,content=True)
        service._case(conn,p,case_id,open_only=True)
        repeated,_=snapshot(service,conn,p,identifier(case_id),lease_ids)
        if repeated!=document:raise AccessDenied('hermes_selected_capture_changed')
    return dict(facts_evidence_id=str(holder['id']),selected_leases=[str(v) for v in selected(lease_ids)],
        coverage='partial',semantic_telemetry_parsed=False,visible_text_exported=False,model_calls=0,
        limitation='Capture integrity and visibility gaps only; no incident facts are inferred from unknown dashboards.')
