"""Credential-free native Hermes request preparation and response replay."""
from hashlib import sha256
import http.client
import json
import logging
import re
from pathlib import Path

from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import AccessDenied

VERSION='gabriel-hermes-bridge-v1'
UPSTREAM='bf0203a794a07aac3ff764972ab9087baa4e4f4e'
IMAGE='nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d'
MODEL='openai/gpt-oss-120b'


def runtime_digest():
    return sha256(b''.join((Path(__file__).parents[1]/'hermes'/name).read_bytes() for name in ('runtime.py','server.py'))).hexdigest()


def request(path,packet=None):
    client=http.client.HTTPConnection('hermes',8451,timeout=40)
    try:
        client.request('GET' if packet is None else 'POST',path,
            body=canonical(packet) if packet is not None else None,headers={'Content-Type':'application/json'})
        response=client.getresponse();raw=response.read(32769)
        if len(raw)>32768:raise ValueError
        result=json.loads(raw)
        if response.status!=200:
            frames=[]
            for f in result.get('frames',[])[:12]:
                if (type(f) is dict and type(f.get('line')) is int and 0<f['line']<100000 and
                        type(f.get('file')) is str and re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}',f['file']) and
                        type(f.get('function')) is str and re.fullmatch(r'[a-zA-Z0-9_<>]{1,64}',f['function'])):
                    frames.append((f['file'],f['line'],f['function']))
            logging.getLogger(__name__).warning('Required Hermes runtime failure; static stack locations: %s',frames)
            code=result.get('code')
            if code in {'hermes_single_turn_limit','hermes_request_binding_failed','hermes_response_binding_failed','hermes_turn_deadline','unexpected_hermes_source'}:
                raise AccessDenied(code)
            raise ValueError
        if result.get('version')!=VERSION or result.get('upstream')!=UPSTREAM:raise ValueError
        return result
    except (OSError,http.client.HTTPException,ValueError,TypeError,AttributeError):
        raise AccessDenied('required_hermes_runtime_unavailable') from None
    finally:client.close()


def health():
    result=request('/health')
    if result.get('runtime_digest')!=runtime_digest():raise AccessDenied('hermes_runtime_version_mismatch')
    return dict(status='ready',version=VERSION,upstream=UPSTREAM,runtime_digest=runtime_digest())


def turn(model,messages,answer):
    health()
    result=request('/turn',dict(model=model,messages=messages,answer=answer))
    if result.get('messages')!=messages or result.get('answer')!=answer or result.get('native_turns')!=1:
        raise AccessDenied('hermes_native_turn_binding_failed')
    return result


def prepare(model,messages):
    # This sentinel is never evidence or a model verdict. It only makes the
    # isolated SDK expose its exact native request before budget reservation.
    return turn(model,messages,'{"gabriel_request_preparation":true}')['messages']


class Transport:
    def __init__(self,inner):self.inner=inner

    def request(self,method,path,body=None):
        if method=='POST':
            if path!='/api/v1/chat/completions':raise AccessDenied('hermes_transport_path_denied')
        reply=self.inner.request(method,path,body) if body is not None else self.inner.request(method,path)
        if method=='POST':
            choices=reply.get('choices') if type(reply) is dict else None
            if type(choices) is not list or len(choices)!=1 or choices[0].get('finish_reason')!='stop':
                raise AccessDenied('hermes_incomplete_provider_response')
            answer=choices[0].get('message',{}).get('content')
            if type(answer) is not str:raise AccessDenied('hermes_invalid_provider_response')
            turn(body['model'],body['messages'],answer)
        return reply
