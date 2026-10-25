"""Bounded tenant metadata for analyst source health and audit screens."""
from gabriel.identity.browser_sessions import BrowserSessionService
from gabriel.identity.cases import iso
from gabriel.identity.service import AccessDenied,connection
from datetime import datetime,timezone


def audit_history(service,token):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        if p.role=='viewer': raise AccessDenied('audit_role_required')
        rows=conn.execute('''SELECT id,event,actor_id,target_id,created_at FROM gabriel_identity.audit_events
            WHERE organization_id=%s ORDER BY created_at DESC,id DESC LIMIT 201''',(p.organization_id,)).fetchall()
        return dict(events=[dict(id=str(row['id']),event=row['event'],actor_id=str(row['actor_id']) if row['actor_id'] else None,
            target_id=str(row['target_id']) if row['target_id'] else None,created_at=iso(row['created_at'])) for row in rows[:200]],
            truncated=len(rows)>200,limit=200)


def source_health(service,token,case_id=None):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        if case_id is None:
            rows=conn.execute('''SELECT id FROM gabriel_identity.browser_leases
                WHERE organization_id=%s ORDER BY created_at DESC,id DESC LIMIT 33''',(p.organization_id,)).fetchall()
        else:
            case=service._case(conn,p,case_id)
            rows=conn.execute('''SELECT id FROM gabriel_identity.browser_leases
                WHERE organization_id=%s AND case_id=%s ORDER BY created_at DESC,id DESC LIMIT 33''',(p.organization_id,case['id'])).fetchall()
    browser=BrowserSessionService(service._dsn,service.store)
    sources=[]
    # Reuse authoritative live task/session/role checks; each sample has its own transaction.
    for row in rows[:32]:
        lease=browser.get_browser_lease(token,row['id'])
        health=('disconnected' if lease['state']=='disconnected' else 'authority_unavailable' if not lease['authorization_current']
            else 'awaiting_connection' if lease['state']=='pending' else 'recent_heartbeat' if lease['heartbeat_fresh'] else 'coverage_gap')
        with connection(service._dsn) as conn:
            capture=conn.execute('''SELECT count(*) AS n,max(r.created_at) AS last_capture FROM gabriel_identity.browser_observations o
                JOIN gabriel_identity.browser_observation_receipts r ON (r.organization_id,r.observation_id)=(o.organization_id,o.id)
                WHERE o.organization_id=%s AND o.lease_id=%s AND o.state='captured' ''',(lease['organization_id'],lease['id'])).fetchone()
        sources.append(dict(captured_observations=capture['n'],last_capture=iso(capture['last_capture']),
            scheduled_permission=lease['scheduled_review_enabled'],id=str(lease['id']),case_id=str(lease['case_id']),browser=lease['browser'],health=health,
            state=lease['state'],expires_at=iso(lease['expires_at']),last_seen=iso(lease['last_seen']),
            authorization_current=lease['authorization_current'],heartbeat_fresh=lease['heartbeat_fresh'],page_visibility='unverified',
            sampled_at=iso(datetime.now(timezone.utc))))
    return dict(sources=sources,truncated=len(rows)>32,limit=32,sampling='individual_live_checks',coverage='partial')
