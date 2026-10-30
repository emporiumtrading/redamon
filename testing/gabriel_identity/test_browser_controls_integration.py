"""Reviewed controls consume real PostgreSQL intents; a simulated claim is not a DOM test."""
from uuid import uuid4

import pytest

from gabriel.identity.browser_controls import VERSION,validate,load
from gabriel.identity.browser_gateway import prepare,BrowserGateway
from gabriel.identity.browser_navigation import BrowserNavigationService
from gabriel.identity.checkpoints import read_document
from gabriel.identity.service import AccessDenied,AuthenticationDenied
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case
from testing.gabriel_identity.test_browser_sessions_integration import context as base_context

pytestmark=pytest.mark.integration


@pytest.fixture
def context(base_context):
    return dict(base_context,extension_version='0.4.0')


def plan(context):
    page=context['page_url']
    return dict(version=VERSION,request_id=str(uuid4()),read_only_role_confirmed=True,query_keys=[],steps=[
        dict(kind='menu',target=dict(tag='button',id='sections',name='Open sections'),source_url=page,destination_url=page,
            expect=dict(id='menu',text='Investigation sections')),
        dict(kind='filter',target=dict(tag='select',id='severity',name='Severity'),value='high',source_url=page,destination_url=page,
            expect=dict(id='results',text='High severity results'))])


@pytest.fixture
def controls(tenant,cases,case,context,tmp_path):
    service=BrowserNavigationService(tenant.db.app,cases.store)
    task=service.create_browser_task(tenant.token,'Generated control steps',300,5)
    directory=tmp_path/'control-pair'
    approved=plan(context)
    enrollment=prepare(service,tenant.token,task['id'],case['id'],context,'https://localhost:8443',
        'chrome-extension://'+'a'*32,directory,share_observations=True,control_plan=approved)
    configuration=read_document(directory/'gateway.json',private=True)
    assert load(directory/'controls.json',configuration)==approved
    peer=read_document(directory/'peer.json',private=True)['token']
    app=BrowserGateway(service,tenant.token,peer,configuration,control_plan=approved)
    ticket=read_document(directory/'claim.json',private=True)['ticket']
    app.dispatch('claim',dict(ticket=ticket,context=context),None)
    return app,service,peer,enrollment,configuration,approved


def call(controls,operation,body):
    app,_,peer,*_=controls
    return app.dispatch(operation,body,'Bearer '+peer)


def test_control_plan_same_document_sequence_and_receipt_replay(controls,context,tenant):
    current=call(controls,'controls-plan',dict(context=context))
    assert current['next_step']==0 and len(current['steps'])==2
    import json
    assert json.loads(controls[1].read_evidence(controls[0]._human,current['plan_evidence_id']).reveal())==controls[-1]
    prepared=call(controls,'controls-prepare',dict(context=context,step=0,plan_digest=current['plan_digest']))
    assert prepared['intent']['destination_url']==context['page_url']
    body=dict(context=context,intent_id=prepared['intent']['id'],step=0,plan_digest=current['plan_digest'])
    completed=call(controls,'controls-complete',body)
    assert completed['next_step']==1 and completed['current'] and not completed['source_verified']
    replay=call(controls,'controls-complete',body)
    assert replay['replayed'] and replay['next_step']==1
    prepared=call(controls,'controls-prepare',dict(context=context,step=1,plan_digest=current['plan_digest']))
    assert call(controls,'controls-complete',dict(body,intent_id=prepared['intent']['id'],step=1))['next_step']==2
    with owner_connection(tenant.db) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.browser_navigation_commits WHERE organization_id=%s',(tenant.org,)).fetchone()['n']==2


def test_lost_prepare_is_never_redispatched_or_restarted(controls,context):
    current=call(controls,'controls-plan',dict(context=context))
    body=dict(context=context,step=0,plan_digest=current['plan_digest'])
    call(controls,'controls-prepare',body)
    with pytest.raises(AccessDenied):call(controls,'controls-prepare',body)
    app,service,peer,_,configuration,approved=controls
    restarted=BrowserGateway(service,app._human,peer,configuration,control_plan=approved)
    restarted._claimed=True;restarted.controls.activate(restarted)
    with pytest.raises(AccessDenied,match='already_dispatched'):
        restarted.dispatch('controls-prepare',body,'Bearer '+peer)


@pytest.mark.parametrize('change',['context','digest','order','url'])
def test_unreviewed_or_wrong_tab_steps_are_denied(controls,context,change):
    current=call(controls,'controls-plan',dict(context=context))
    body=dict(context=context,step=0,plan_digest=current['plan_digest'])
    if change=='context':body['context']=dict(context,tab_id=str(int(context['tab_id'])+1))
    elif change=='digest':body['plan_digest']='0'*64
    elif change=='order':body['step']=1
    else:body['destination_url']='https://outside.invalid/delete'
    with pytest.raises((AccessDenied,ValueError)):call(controls,'controls-prepare',body)


def test_control_authority_does_not_enable_legacy_untyped_navigation(controls,context):
    with pytest.raises(AccessDenied,match='typed_dispatch'):
        call(controls,'navigation-prepare',dict(context=context,request_id=str(uuid4()),destination_url=context['page_url']))


@pytest.mark.parametrize('ending',['stop','logout'])
def test_stop_and_original_logout_deny_completion(controls,context,ending):
    current=call(controls,'controls-plan',dict(context=context))
    prepared=call(controls,'controls-prepare',dict(context=context,step=0,plan_digest=current['plan_digest']))
    if ending=='stop':call(controls,'disconnect',{})
    else:controls[1].logout(controls[0]._human)
    with pytest.raises((AccessDenied,AuthenticationDenied)):
        call(controls,'controls-complete',dict(context=context,intent_id=prepared['intent']['id'],step=0,plan_digest=current['plan_digest']))


@pytest.mark.parametrize('change',['role','credential','mutation','post','query','origin','chain','oversize'])
def test_control_policy_rejects_unreviewed_semantics(context,change):
    value=plan(context)
    if change=='role':value['read_only_role_confirmed']=False
    elif change=='credential':value['steps'][0]['target']['name']='API token'
    elif change=='mutation':value['steps'][0]['target']['name']='Delete incident'
    elif change=='post':value['steps'][0]['method']='POST'
    elif change=='query':value['steps'][0]['destination_url']+='?unreviewed=value'
    elif change=='origin':value['steps'][0]['destination_url']='https://outside.invalid/view'
    elif change=='chain':value['steps'][1]['source_url']+='other'
    else:value['steps']*=21
    with pytest.raises((ValueError,AccessDenied)):validate(value,context)


def test_only_exact_reviewed_get_form_fields_are_accepted(context):
    value=plan(context);page=context['page_url'].split('#')[0]
    value['query_keys']=['q']
    value['steps']=[dict(kind='submit',target=dict(tag='form',id='search',name='Search events'),fields={'q':'generated'},
        source_url=context['page_url'],destination_url=page+'?q=generated',expect=dict(id='results',text='Generated results'))]
    assert validate(value,context)==[context['page_url'],page+'?q=generated']
    value['steps'][0]['fields']['q']='other'
    with pytest.raises(ValueError,match='form_destination'):validate(value,context)


def test_scope_receipt_cannot_complete_a_different_control(controls,context):
    current=call(controls,'controls-plan',dict(context=context))
    prepared=call(controls,'controls-prepare',dict(context=context,step=0,plan_digest=current['plan_digest']))
    with pytest.raises(AccessDenied):
        call(controls,'controls-complete',dict(context=dict(context,page_url='https://outside.invalid/view'),
            intent_id=prepared['intent']['id'],step=0,plan_digest=current['plan_digest']))


def test_expired_control_intent_cannot_complete_or_repeat(controls,context,tenant):
    current=call(controls,'controls-plan',dict(context=context))
    prepared=call(controls,'controls-prepare',dict(context=context,step=0,plan_digest=current['plan_digest']))
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.browser_navigation_intents SET created_at=statement_timestamp()-interval '2 minutes',expires_at=statement_timestamp()-interval '90 seconds' WHERE organization_id=%s",(tenant.org,))
    with pytest.raises(AccessDenied):
        call(controls,'controls-complete',dict(context=context,intent_id=prepared['intent']['id'],step=0,plan_digest=current['plan_digest']))
    with pytest.raises(AccessDenied):call(controls,'controls-prepare',dict(context=context,step=0,plan_digest=current['plan_digest']))
