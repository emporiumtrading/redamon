"""Versioned executor enrollment and read-only plan retrieval using generated PostgreSQL fixtures."""
from pathlib import Path
from uuid import uuid4

import pytest

from gabriel.identity.browser_gateway import BrowserGateway
from gabriel.identity.service import AccessDenied,IdentityUnavailable,migrate
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_navigation_integration import browser,grant,navigation,VERSION,DESTINATION
from testing.gabriel_identity.test_browser_observations_integration import rows
from testing.gabriel_identity.db_history import remove_v22

pytestmark=pytest.mark.integration


def test_assigned_plan_is_read_only_and_has_no_peer_secrets(tenant,browser,grant,navigation,context):
    plan=browser.navigation_plan(tenant.token,grant.token,context)
    assert plan['id']==navigation['id'] and plan['contract_version']==VERSION
    assert plan['destinations']==[DESTINATION,context['page_url']]
    assert plan['sharing_approved'] and not plan['source_verified']
    assert plan['monitoring_approved'] is False
    assert set(plan)=={'id','contract_version','destinations','max_moves','expires_at','sharing_approved','monitoring_approved','source_verified'}
    assert not rows(tenant,'browser_navigation_intents') and not rows(tenant,'browser_navigation_receipts')
    with pytest.raises(AccessDenied): browser.navigation_plan(tenant.token,grant.token,dict(context,account_label='Other generated account'))
    browser.prepare_navigation(tenant.token,grant.token,uuid4(),DESTINATION)
    with pytest.raises(AccessDenied,match='outcome_unresolved'): browser.navigation_plan(tenant.token,grant.token,context)


def test_v22_upgrade_failure_preserves_old_pairing_and_then_admits_v02(tenant,browser,grant,case,context,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v22(conn)
    read=Path.read_text
    def interrupted(path,*args,**kwargs):
        raw=read(path,*args,**kwargs)
        return raw+'\nSELECT 1/0;' if path.name=='schema_v22.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        assert browser.heartbeat_browser(grant.token,context)
        with owner_connection(tenant.db) as conn:
            assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==21
    finally: migrate(tenant.db.owner)
    task=browser.create_browser_task(tenant.token,'Generated version two executor task',900,10)
    new_context=dict(context,extension_version='0.2.0',document_id=str(uuid4()))
    lease=browser.issue_browser_lease(tenant.token,task['id'],case['id'],new_context)
    try:
        assert browser.connect_browser(lease.token,new_context)['paired']
        assert browser.heartbeat_browser(lease.token,new_context)['page_content_received'] is False
        with pytest.raises(AccessDenied): browser.heartbeat_browser(lease.token,dict(new_context,extension_version='0.1.0'))
    finally:
        # Historical-schema tests elsewhere require data representable in version 21.
        with owner_connection(tenant.db) as conn:
            conn.execute('DELETE FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',(tenant.org,lease.id))
