"""Private, exact control plans reuse durable navigation intents and receipts."""
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl,urlsplit
from uuid import UUID,uuid5

from gabriel.identity.browser_navigation import OPERATOR_PAGES,readonly_page
from gabriel.identity.browser_sessions import approved_context
from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.service import AccessDenied
from gabriel.identity.specialist_contracts import digest

VERSION='gabriel-reviewed-controls-v1'
KINDS={'menu':{'button','summary'},'filter':{'select'},'fill':{'input','textarea'},
    'paginate':{'button','a'},'submit':{'form'}}
SENSITIVE=re.compile(r'password|passwd|secret|token|cookie|session|auth|credential|api.?key|otp|credit.?card',re.I)
MUTATION=re.compile(r'\b(delete|remove|disable|enable|execute|save|create|reset|reboot|shutdown|terminate|block|unblock|approve|revoke|edit|logout|signout)\b',re.I)


def text(value,limit=128):
    if not isinstance(value,str) or not value or len(value)>limit or re.search(r'[\x00-\x1f\x7f]',value):
        raise ValueError('invalid_control_text')
    return value


def field_value(value):
    if not isinstance(value,str) or len(value)>256 or re.search(r'[\x00-\x1f\x7f]',value):
        raise ValueError('invalid_control_field_value')
    return value


def validate(plan,context):
    context=approved_context(context)
    if (type(plan) is not dict or set(plan)!={'version','request_id','read_only_role_confirmed','query_keys','steps'}
            or plan['version']!=VERSION or plan['read_only_role_confirmed'] is not True
            or not isinstance(plan['request_id'],str) or str(UUID(plan['request_id']))!=plan['request_id']
            or type(plan['steps']) is not list or not 1<=len(plan['steps'])<=20
            or len(json.dumps(plan,separators=(',',':')).encode())>6000):
        raise ValueError('invalid_reviewed_control_plan')
    keys=plan['query_keys']
    if (type(keys) is not list or len(keys)>16 or any(not isinstance(k,str) for k in keys) or len(set(keys))!=len(keys)
            or any(not isinstance(k,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',k)
                   or SENSITIVE.search(k) or k.lower() in {'action','method','operation'} for k in keys)):
        raise ValueError('invalid_control_query_policy')
    original=urlsplit(context['page_url']);current=context['page_url'];destinations=[current]
    for step in plan['steps']:
        if type(step) is not dict or step.get('kind') not in KINDS:
            raise ValueError('unsupported_control_kind')
        kind=step['kind'];extra={'value'} if kind in {'filter','fill'} else {'fields'} if kind=='submit' else set()
        if set(step)!={'kind','target','source_url','destination_url','expect'}|extra:
            raise ValueError('invalid_control_step')
        target=step['target'];expect=step['expect']
        if (type(target) is not dict or set(target)!={'tag','id','name'} or target['tag'] not in KINDS[kind]
                or not isinstance(target['id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{0,80}',target['id'])
                or SENSITIVE.search(text(target['name'],80)) or MUTATION.search(target['name'])):
            raise ValueError('unsafe_control_target')
        if (type(expect) is not dict or set(expect)!={'id','text'}
                or not isinstance(expect['id'],str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,79}',expect['id'])):
            raise ValueError('invalid_control_postcondition')
        text(expect['text'],256)
        if step['source_url']!=current:raise ValueError('control_plan_source_chain')
        for url in (step['source_url'],step['destination_url']):
            approved_context(dict(context,page_url=url));readonly_page(url);parsed=urlsplit(url)
            pairs=parse_qsl(parsed.query,keep_blank_values=True)
            if ((parsed.scheme,parsed.netloc)!=(original.scheme,original.netloc)
                    or len({k for k,_ in pairs})!=len(pairs) or any(k not in keys for k,_ in pairs)
                    or parsed.fragment and '?' in parsed.fragment):
                raise ValueError('control_destination_policy')
        if kind in {'menu','filter','fill'} and step['destination_url']!=current:
            raise ValueError('control_requires_same_document')
        if kind in {'filter','fill'}:field_value(step['value'])
        if kind=='submit':
            fields=step['fields']
            if (type(fields) is not dict or not 1<=len(fields)<=16 or any(k not in keys for k in fields)
                    or any(SENSITIVE.search(k) for k in fields)):
                raise ValueError('unsafe_control_form_fields')
            for value in fields.values():field_value(value)
            if dict(parse_qsl(urlsplit(step['destination_url']).query,keep_blank_values=True))!=fields:
                raise ValueError('control_form_destination_mismatch')
        current=step['destination_url']
        if current not in destinations:destinations.append(current)
    if len(destinations)>20:raise ValueError('control_destination_limit')
    return destinations


def publish(directory,plan,configuration):
    directory=Path(directory)
    if (directory/'gateway.started').exists():raise ValueError('control_plan_requires_fresh_gateway')
    validate(plan,configuration['context'])
    write_document(directory/'controls.json',dict(purpose=VERSION,lease_id=configuration['lease_id'],
        context_digest=digest(configuration['context']),plan=plan))


def load(path,configuration):
    path=Path(path)
    if not path.exists():return None
    value=read_document(path,private=True)
    if (type(value) is not dict or set(value)!={'purpose','lease_id','context_digest','plan'}
            or value['purpose']!=VERSION or value['lease_id']!=configuration['lease_id']
            or value['context_digest']!=digest(configuration['context'])):
        raise ValueError('control_plan_scope_mismatch')
    validate(value['plan'],configuration['context'])
    return value['plan']


class Controls:
    def __init__(self,plan,context):
        self.destinations=validate(plan,context);self.plan=json.loads(json.dumps(plan))
        self.next=0;self.started=None;self.completed={};self.grant=None;self.evidence_id=None

    def activate(self,app):
        lease=app._bound()
        recorded=app.service.acquire(app._human,lease['case_id'],uuid5(UUID(self.plan['request_id']),'reviewed-controls-plan'),
            json.dumps(self.plan,sort_keys=True,separators=(',',':')),'Engineer-reviewed browser control plan; role attested, semantics unverified',approved=True)
        self.evidence_id=str(recorded['id'])
        request=uuid5(UUID(self.evidence_id),VERSION+'|'+app.lease_id)
        self.grant=app.service.grant_navigation(app._human,app._peer,request,OPERATOR_PAGES,
            self.destinations,max_moves=len(self.plan['steps']))

    def dispatch(self,app,operation,body):
        if not self.grant:raise AccessDenied('control_grant_not_active')
        if operation=='controls-plan':
            if set(body)!={'context'} or approved_context(body['context'])!=app.context:raise AccessDenied('control_scope_changed')
            return dict(version=VERSION,plan_digest=digest(self.plan),steps=self.plan['steps'],next_step=self.next,
                expires_at=self.grant['expires_at'],plan_evidence_id=self.evidence_id,source_verified=False)
        if operation=='controls-prepare':
            if (set(body)!={'context','step','plan_digest'} or type(body['step']) is not int
                    or body['step']!=self.next or self.next>=len(self.plan['steps'])
                    or body['plan_digest']!=digest(self.plan) or approved_context(body['context'])!=app.context
                    or self.started is not None):raise AccessDenied('control_dispatch_not_current')
            step=self.plan['steps'][self.next]
            if step['source_url']!=app.context['page_url']:raise AccessDenied('control_source_changed')
            # A lost prepare response never authorizes a second dispatch or a restart.
            self.started={'step':self.next,'intent':None}
            intent=app.service.prepare_navigation(app._human,app._peer,uuid5(UUID(self.grant['id']),str(self.next)),
                step['destination_url'],allow_same_page=True)
            if intent['state']!='prepared' or intent.get('replayed'):raise AccessDenied('control_already_dispatched')
            self.started['intent']=intent['id']
            return dict(intent=intent,step=step,step_index=self.next,plan_digest=digest(self.plan))
        if (operation!='controls-complete' or set(body)!={'context','intent_id','step','plan_digest'}
                or type(body['step']) is not int or body['plan_digest']!=digest(self.plan)):
            raise AccessDenied('invalid_control_completion')
        expected=self.completed.get(body['step']) or self.started
        if not expected or expected['step']!=body['step'] or expected['intent']!=body['intent_id']:
            raise AccessDenied('control_completion_not_current')
        result=app.service.complete_navigation(app._human,app._peer,body['intent_id'],body['context'])
        if self.started and self.started==expected:
            self.completed[body['step']]=dict(expected);self.next+=1;self.started=None
        app._bound()
        return dict(result,step=body['step'],next_step=self.next)
