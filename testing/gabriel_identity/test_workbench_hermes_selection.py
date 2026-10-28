"""Hermes form scope and consent boundary; runs inside the identity test image."""
from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import MagicMock,patch
from urllib.parse import urlencode
from uuid import UUID

import pytest

from gabriel.identity.service import AccessDenied
from gabriel.identity.workbench import Workbench,selected_hermes_leases

CASE=str(UUID(int=1))
TABS=[str(UUID(int=i)) for i in range(2,10)]
PATH='/cases/'+CASE+'/hermes'


def form(pairs,path=PATH):
    raw=urlencode(pairs).encode()
    return dict(PATH_INFO=path,CONTENT_TYPE='application/x-www-form-urlencoded',CONTENT_LENGTH=str(len(raw)),
        **{'wsgi.input':BytesIO(raw)})


def app():
    wb=Workbench.__new__(Workbench)
    wb._csrf='csrf-fixture';wb._token='not-a-live-token';wb._provider_vault=object();wb.target='https://localhost:9443'
    wb.service=MagicMock()
    wb.service.get_case.return_value=dict(case=dict(state='open'),evidence=[])
    return wb


def fields(operation='start',approved=True):
    values=[('csrf','csrf-fixture'),('request_id',str(UUID(int=22))),('input_evidence_id','selected_tabs'),
        ('model','openai/gpt-oss-120b'),('specialist_model','openai/gpt-oss-120b'),('key_scope','personal'),('operation',operation)]
    values += [('selected_leases',tab) for tab in TABS]
    if approved:values.append(('approved','yes'))
    return values


def test_hermes_start_accepts_eight_selected_tabs_and_explicit_consent():
    result=app()._fields(form(fields()))
    assert result['approved']=='yes'
    assert selected_hermes_leases(result['selected_leases'])==TABS


@pytest.mark.parametrize('value',['',','.join(TABS+[str(UUID(int=10))]),','.join(TABS+[TABS[0]]),'local,'+TABS[0],'not-a-uuid'])
def test_scope_rejects_empty_excess_duplicate_or_mixed_local_tabs(value):
    with pytest.raises(AccessDenied):selected_hermes_leases(value)


def test_non_hermes_forms_still_reject_duplicate_fields_and_oversized_field_sets():
    wb=app()
    with pytest.raises(AccessDenied,match='duplicate_form_field'):
        wb._fields(form([('csrf','csrf-fixture'),('selected_leases',TABS[0]),('selected_leases',TABS[1])],'/cases/new'))
    with pytest.raises(ValueError):wb._fields(form(fields(),'/cases/new'))
    with pytest.raises(AccessDenied,match='duplicate_form_field'):
        wb._fields(form(fields()+[('model','other')]))


@pytest.mark.parametrize('operation,approved',[('preflight',False),('start',True)])
@pytest.mark.parametrize('automatic',[True,False])
def test_selected_tab_snapshot_routes_to_hermes_with_exact_selected_scope(operation,approved,automatic):
    from gabriel.identity import browser_hermes,hermes_supervisor as hermes
    submitted=fields(operation,approved)
    if not automatic:submitted=[(k,str(UUID(int=44)) if k=='input_evidence_id' else v) for k,v in submitted if k!='selected_leases']
    wb=app();env=form(submitted)
    env.update(REQUEST_METHOD='POST',HTTP_HOST='localhost:9443',HTTP_ORIGIN=wb.target,**{'wsgi.url_scheme':'https'})
    principal=SimpleNamespace(role='analyst')
    @contextmanager
    def connected(_):
        conn=MagicMock();conn.execute.return_value.fetchall.return_value=[]
        yield conn
    outcome=dict(state='hermes_completed_requires_review',ready=False,checks=[])
    with patch.object(wb,'_authenticate',return_value=principal),patch('gabriel.identity.workbench.connection',connected),\
            patch('gabriel.identity.workbench.source_health',return_value={'sources':[]}),\
            patch.object(hermes,'readiness',return_value=dict(model='fixture',qualification='qualification_pending')),\
            patch.object(hermes,'history',return_value=[]),patch.object(wb,'_page',return_value=b'page'),\
            patch.object(browser_hermes,'prepare',return_value={'facts_evidence_id':str(UUID(int=33))}) as prepare,\
            patch.object(hermes,'preflight',return_value=outcome) as preflight,patch.object(hermes,'start',return_value=outcome) as start:
        assert wb._route(env)[0]=='200 OK'
        if automatic:prepare.assert_called_once_with(wb.service,wb._token,CASE,TABS)
        else:prepare.assert_not_called()
        dispatched=start if operation=='start' else preflight
        assert dispatched.call_args.kwargs['lease_ids']==(TABS if automatic else [])
        assert str(UUID(int=33 if automatic else 44)) in dispatched.call_args.args
        if operation=='start':assert dispatched.call_args.kwargs['approved'] is True
        else:start.assert_not_called()


def test_missing_start_consent_prevents_snapshot_creation_and_dispatch():
    from gabriel.identity import browser_hermes,hermes_supervisor as hermes
    wb=app();env=form(fields('start',False));env.update(REQUEST_METHOD='POST',HTTP_HOST='localhost:9443',HTTP_ORIGIN=wb.target,**{'wsgi.url_scheme':'https'})
    with patch.object(wb,'_authenticate',return_value=SimpleNamespace(role='analyst')),\
            patch.object(hermes,'readiness',return_value=dict(model='fixture',qualification='qualification_pending')),\
            patch.object(browser_hermes,'prepare') as prepare,patch.object(hermes,'start') as start:
        with pytest.raises(AccessDenied,match='hermes_ai_export_consent_required'):wb._route(env)
        prepare.assert_not_called();start.assert_not_called()


@pytest.mark.parametrize('operation,approved',[('preflight',False),('start',True)])
def test_automatic_snapshot_requires_tabs_before_preparation(operation,approved):
    from gabriel.identity import browser_hermes,hermes_supervisor as hermes
    submitted=[(k,v) for k,v in fields(operation,approved) if k!='selected_leases']
    wb=app();env=form(submitted);env.update(REQUEST_METHOD='POST',HTTP_HOST='localhost:9443',HTTP_ORIGIN=wb.target,**{'wsgi.url_scheme':'https'})
    with patch.object(wb,'_authenticate',return_value=SimpleNamespace(role='analyst')),\
            patch.object(hermes,'readiness',return_value=dict(model='fixture',qualification='qualification_pending')),\
            patch.object(browser_hermes,'prepare') as prepare,patch.object(hermes,'start') as start,patch.object(hermes,'preflight') as preflight:
        with pytest.raises(AccessDenied,match='hermes_selected_tabs_required'):wb._route(env)
        prepare.assert_not_called();start.assert_not_called();preflight.assert_not_called()
