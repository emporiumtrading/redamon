"""Metadata dashboard presentation; execute in the checked identity test image."""
from types import SimpleNamespace
from unittest.mock import MagicMock,patch
from uuid import UUID

from gabriel.identity.workbench import Workbench,hermes_outcome,hermes_stages,source_cards

CASE=str(UUID(int=1))


def source(**overrides):
    row=dict(browser='chrome',health='recent_heartbeat',authorization_current=True,heartbeat_fresh=True,state='active',
        last_seen='2026-01-02T03:04:05Z',captured_observations=2,last_capture=None,page_visibility='unverified',
        scheduled_permission=True,expires_at='2026-01-02T03:09:05Z',case_id=CASE)
    return dict(row,**overrides)


def test_source_cards_distinguish_connection_from_visibility_and_bound_counts():
    html=source_cards(dict(sources=[source(),source(health='authority_unavailable',authorization_current=False)]))
    assert '<dt>Recent active links</dt><dd>1</dd>' in html
    assert '<dt>Other connection states</dt><dd>1</dd>' in html
    assert '<dt>Page visibility</dt><dd>Unverified</dd>' in html
    assert 'A heartbeat is not a complete page read' in html
    assert 'Approved; activity unverified' in html and 'Latest 32' not in html
    assert 'Bounded to the latest 32 sessions' in html
    assert html.count('Open linked investigation')==2
    assert 'Complete monitoring' not in html


def test_source_cards_empty_state_and_untrusted_metadata_are_escaped():
    assert 'No browser sessions recorded' in source_cards(dict(sources=[]))
    html=source_cards(dict(sources=[source(browser='<script>bad()</script>',last_seen='<img src=x>')]))
    assert '<script>' not in html and '<img ' not in html
    assert '&lt;script&gt;' in html and '&lt;img src=x&gt;' in html


def test_hermes_workflow_is_a_process_map_and_outcome_only_links_existing_receipts():
    stages=hermes_stages()
    assert stages.count('<li>')==4 and 'Hermes investigation workflow' in stages
    result=dict(state='hermes_bounded_investigation_requires_review',report_answer_evidence_id=str(UUID(int=2)),
        agents=[dict(role='telemetry_health',result=dict(state='blocked_requires_review',steps=[]))])
    html=hermes_outcome(result,CASE)
    assert '/cases/'+CASE+'/evidence/'+str(UUID(int=2)) in html
    assert 'Review Hermes assignment plan' not in html
    assert 'blocked requires review' in html and 'not a live background monitor' in html
    assert '<form' not in html and '<script' not in html
    assert 'Stopped.' in hermes_outcome(dict(stopped=True),CASE)


def workbench(role):
    wb=Workbench.__new__(Workbench);wb.target='https://localhost:9443';wb._token='fixture-not-live';wb._csrf='fixture-csrf'
    wb.service=MagicMock()
    principal=SimpleNamespace(role=role,organization_id=UUID(int=3),user_id=UUID(int=4))
    env=dict(REQUEST_METHOD='GET',PATH_INFO='/cases',HTTP_HOST='localhost:9443',**{'wsgi.url_scheme':'https'})
    return wb,principal,env


def test_investigation_queue_counts_only_displayed_rows_and_respects_viewer_controls():
    for role in ('owner','viewer'):
        wb,principal,env=workbench(role)
        wb.service.list_cases.return_value=[dict(id=CASE,title='<script>unsafe</script>',state='open',created_at='generated-time'),
            dict(id=str(UUID(int=5)),title='Generated historical case',state='closed',created_at='generated-time')]
        with patch.object(wb,'_authenticate',return_value=principal):
            status,raw,_=wb._route(env)
        html=raw.decode()
        assert status=='200 OK' and '<dt>Investigations displayed</dt><dd>2</dd>' in html
        assert '<dt>Open cases</dt><dd>1</dd>' in html
        assert 'Latest 100 cases in this view' in html and '&lt;script&gt;unsafe&lt;/script&gt;' in html
        assert ('Start an investigation' in html)==(role!='viewer')
        assert '<script>' not in html
        wb.service.read_evidence.assert_not_called();wb.service.create_case.assert_not_called()


def test_case_overview_uses_workflow_metadata_without_revealing_evidence_contents():
    wb,principal,env=workbench('viewer');env['PATH_INFO']='/cases/'+CASE
    snapshot=dict(case=dict(title='Generated case',state='open',purpose='investigation'),evidence=[],timeline=[],browser_observations=[])
    wb.service.case_report.return_value=dict(snapshot=snapshot)
    wb.service.case_workflow.return_value=dict(assignment=None,questions=[],questions_restricted=True)
    with patch.object(wb,'_authenticate',return_value=principal):
        status,raw,_=wb._route(env)
    html=raw.decode()
    assert status=='200 OK' and 'Jump to investigation section' in html
    for section in ('case-questions','case-evidence','case-timeline','case-observations'):
        assert 'href="#'+section+'"' in html and 'id="'+section+'"' in html
    assert '<dt>Questions awaiting answers</dt><dd>Restricted</dd>' in html
    assert 'Metadata; contents stay private' in html and 'Prepare the next investigation step' not in html
    wb.service.read_evidence.assert_not_called();wb.service.list_members.assert_not_called()
