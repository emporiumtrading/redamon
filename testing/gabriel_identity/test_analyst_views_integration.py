"""Real tenant source-health and audit projections, without manufactured visibility."""
import secrets

import pytest

from gabriel.identity.analyst_views import audit_history,source_health
from gabriel.identity.browser_sessions import BrowserSessionService
from gabriel.identity.service import AccessDenied,AuthenticationDenied,provision_organization
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context

pytestmark=pytest.mark.integration


def test_source_health_tracks_connection_gap_disconnect_and_authority(tenant,cases,case,context):
    browser=BrowserSessionService(tenant.db.app,cases.store)
    password=secrets.token_urlsafe(24)
    browser.create_member(tenant.token,'health-analyst',password,'analyst')
    token=browser.login(tenant.org,'health-analyst',password).token
    task=browser.create_browser_task(token,'Generated health task')
    grant=browser.issue_browser_lease(token,task['id'],case['id'],context)
    assert source_health(cases,tenant.token)['sources'][0]['health']=='awaiting_connection'
    browser.connect_browser(grant.token,context)
    row=source_health(cases,tenant.token)['sources'][0]
    assert row['health']=='recent_heartbeat' and row['page_visibility']=='unverified'
    assert 'token_digest' not in row and 'page_url' not in row and 'account_label' not in row
    with owner_connection(tenant.db) as conn:
        # Owner-only historical fixture, matching the existing browser clock-fault tests.
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DISABLE TRIGGER require_browser_lease_transition')
        conn.execute("UPDATE gabriel_identity.browser_leases SET created_at=created_at-interval '60 seconds',last_seen=last_seen-interval '60 seconds',expires_at=expires_at-interval '60 seconds' WHERE id=%s",(grant.id,))
        conn.execute('ALTER TABLE gabriel_identity.browser_leases ENABLE TRIGGER require_browser_lease_transition')
    assert source_health(cases,tenant.token)['sources'][0]['health']=='coverage_gap'
    browser.logout(token)
    assert source_health(cases,tenant.token)['sources'][0]['health']=='authority_unavailable'
    browser.revoke_browser_lease(tenant.token,grant.id)
    assert source_health(cases,tenant.token)['sources'][0]['health']=='disconnected'


def test_empty_health_and_live_caller_revocation(tenant,cases):
    assert source_health(cases,tenant.token)['sources']==[]
    cases.logout(tenant.token)
    with pytest.raises(AuthenticationDenied): source_health(cases,tenant.token)


def test_audit_and_sources_do_not_cross_tenants(tenant,cases,case,context):
    browser=BrowserSessionService(tenant.db.app,cases.store)
    task=browser.create_browser_task(tenant.token,'Generated source task')
    browser.issue_browser_lease(tenant.token,task['id'],case['id'],context)
    password=secrets.token_urlsafe(24)
    org,_=provision_organization(tenant.db.owner,'Generated audit tenant','owner',password)
    token=cases.login(org,'owner',password).token
    assert source_health(cases,token)['sources']==[]
    events=audit_history(cases,token)['events']
    assert events and all(row['target_id']!=str(case['id']) for row in events)
    assert all(row['event']!='case.created' for row in events)


def test_viewer_denied_audit_but_allowed_partial_health(tenant,cases):
    password=secrets.token_urlsafe(24)
    cases.create_member(tenant.token,'audit-viewer',password,'viewer')
    token=cases.login(tenant.org,'audit-viewer',password).token
    assert source_health(cases,token)['coverage']=='partial'
    with pytest.raises(AccessDenied): audit_history(cases,token)
    assert any(row['event']=='identity.member_created' for row in audit_history(cases,tenant.token)['events'])
