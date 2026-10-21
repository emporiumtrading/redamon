"""Generated rows captured through real PostgreSQL/crypto before cross-capture normalization."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from uuid import uuid4

import pytest

from gabriel.identity.service import AccessDenied,AuthenticationDenied,InvalidIdentityInput,IdentityUnavailable,migrate
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context
from testing.gabriel_identity.test_browser_navigation_integration import browser,grant
from testing.gabriel_identity.test_browser_observations_integration import payload,rows,receipt_permission
from testing.gabriel_identity.test_attack_pattern_runs_integration import event_document
from testing.gabriel_identity.db_history import remove_v24

pytestmark=pytest.mark.integration


def browser_document(document,offset=0,count=5):
    events=[]
    for source in document['events'][offset:offset+count]:
        row={key:value for key,value in source.items() if key not in {'evidence_id','evidence_digest','authorization'}}
        row['reported_authority']=source['authorization'];events.append(row)
    return dict(version='generated-browser-events-v1',as_of=document['as_of'],missing_sources=document['missing_sources'],events=events)


@pytest.fixture
def admitted(tenant,browser,grant,context,monkeypatch):
    from gabriel.identity.browser_navigation import CONTRACTS
    monkeypatch.setitem(CONTRACTS,'generated-console-v1',{'/security#events','/security#traffic'})
    return browser.grant_navigation(tenant.token,grant.token,uuid4(),'generated-console-v1',
        ['https://generated-console.invalid/security#traffic'])


def capture(tenant,browser,grant,payload,raw,sequence=1):
    return browser.observe_browser(tenant.token,grant.token,dict(payload,request_id=str(uuid4()),sequence=sequence,content=json.dumps(raw,separators=(',',':'))))


def test_two_captures_correlate_without_rebinding_earlier_snapshot(tenant,browser,grant,admitted,context,payload,case):
    document=event_document(case['id'],dict(id=uuid4(),digest='a'*64))
    first=capture(tenant,browser,grant,payload,browser_document(document))
    one=browser.review_browser_events(tenant.token,grant.token,context,first['observation_id'])
    assert one['unique_event_count']==5 and one['candidate_count']==0 and one['source_count']==1
    second=capture(tenant,browser,grant,payload,browser_document(document,5),2)
    two=browser.review_browser_events(tenant.token,grant.token,context,second['observation_id'])
    assert two['unique_event_count']==10 and two['candidate_count']==1 and two['families']==['brute_force'] and two['source_count']==2
    assert not two['quality_qualified'] and not two['live_detection_accepted'] and two['model_cost_usd']=='0'
    assert two['capture_to_review_ms']>=0 and two['time_basis']=='server_capture_receipt_to_review'
    assert browser.review_browser_events(tenant.token,grant.token,context,first['observation_id'])==one
    assert len(browser.list_attack_reviews(tenant.token,case['id'])['runs'])==2
    review=browser.get_attack_review(tenant.token,case['id'],two['review_id'])
    assert set(review['result']['findings'][0]['references'])=={'evidence/'+str(first['evidence_id']),'evidence/'+str(second['evidence_id'])}
    assert document['events'][0]['actor_id'] not in json.dumps(rows(tenant,'browser_event_snapshots'),default=str)


def test_concurrent_review_reuses_one_snapshot_derived_artifact_and_review(tenant,browser,grant,admitted,context,payload,case):
    raw=browser_document(event_document(case['id'],dict(id=uuid4(),digest='a'*64)))
    captured=capture(tenant,browser,grant,payload,raw)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda _:browser.review_browser_events(tenant.token,grant.token,context,captured['observation_id']),range(3)))
    assert all(result==results[0] for result in results)
    assert len(rows(tenant,'browser_event_snapshots'))==len(rows(tenant,'attack_pattern_runs'))==1
    assert len(rows(tenant,'browser_observations'))==1 and len(rows(tenant,'evidence_objects'))==2


@pytest.mark.parametrize('change',['unsupported','extra_field','source_corruption','stop','logout'])
def test_bad_source_or_lost_authority_cannot_publish_review(tenant,browser,grant,admitted,context,payload,case,change):
    raw=browser_document(event_document(case['id'],dict(id=uuid4(),digest='a'*64)))
    if change=='unsupported': raw['version']='unsupported-generated-v1'
    elif change=='extra_field': raw['events'][0]['instructions']='Generated hostile page instructions'
    captured=capture(tenant,browser,grant,payload,raw)
    if change=='source_corruption':
        with owner_connection(tenant.db) as conn:
            artifact=conn.execute('SELECT object_id FROM gabriel_identity.evidence_objects WHERE organization_id=%s AND id=%s',(tenant.org,captured['evidence_id'])).fetchone()
        path=browser.store.root/(artifact['object_id'].hex+'.gbe');path.chmod(0o600);path.write_bytes(b'generated-corrupt-event-source')
    elif change=='stop': browser.disconnect_browser(grant.token)
    elif change=='logout': browser.logout(tenant.token)
    from gabriel.identity.evidence_store import EvidenceError
    with pytest.raises((AccessDenied,AuthenticationDenied,InvalidIdentityInput,EvidenceError)):
        browser.review_browser_events(tenant.token,grant.token,context,captured['observation_id'])
    assert not rows(tenant,'attack_pattern_runs')


def test_stop_during_derivation_blocks_review_commit(tenant,browser,grant,admitted,context,payload,case,monkeypatch):
    captured=capture(tenant,browser,grant,payload,browser_document(event_document(case['id'],dict(id=uuid4(),digest='a'*64))))
    acquire=browser.acquire
    def stop_after_local_derivation(*args,**kwargs):
        value=acquire(*args,**kwargs);browser.disconnect_browser(grant.token);return value
    monkeypatch.setattr(browser,'acquire',stop_after_local_derivation)
    with pytest.raises(AuthenticationDenied): browser.review_browser_events(tenant.token,grant.token,context,captured['observation_id'])
    assert not rows(tenant,'attack_pattern_runs') and len(rows(tenant,'browser_observations'))==1


def test_unresolved_capture_blocks_navigation_and_correlation(tenant,browser,grant,admitted,context,payload,case):
    raw=browser_document(event_document(case['id'],dict(id=uuid4(),digest='a'*64)))
    first=capture(tenant,browser,grant,payload,raw)
    receipt_permission(tenant,False)
    try:
        with pytest.raises(IdentityUnavailable): capture(tenant,browser,grant,payload,raw,2)
    finally: receipt_permission(tenant,True)
    with pytest.raises(AccessDenied,match='capture_outcome_unresolved'):
        browser.prepare_navigation(tenant.token,grant.token,uuid4(),'https://generated-console.invalid/security#traffic')
    with pytest.raises(AccessDenied,match='capture_outcome_unresolved'):
        browser.review_browser_events(tenant.token,grant.token,context,first['observation_id'])
    assert not rows(tenant,'browser_navigation_intents') and not rows(tenant,'attack_pattern_runs')


def test_v24_upgrade_failure_is_atomic(tenant,browser,grant,context,monkeypatch):
    with owner_connection(tenant.db) as conn: remove_v24(conn)
    read=Path.read_text
    def interrupted(path,*args,**kwargs):
        raw=read(path,*args,**kwargs);return raw+'\nSELECT 1/0;' if path.name=='schema_v24.sql' else raw
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path,'read_text',interrupted)
            with pytest.raises(IdentityUnavailable): migrate(tenant.db.owner)
        assert browser.heartbeat_browser(grant.token,context)
        with owner_connection(tenant.db) as conn:
            assert conn.execute("SELECT to_regclass('gabriel_identity.browser_event_snapshots') AS t").fetchone()['t'] is None
            assert conn.execute('SELECT max(version) AS v FROM gabriel_identity.migrations').fetchone()['v']==23
    finally: migrate(tenant.db.owner)
