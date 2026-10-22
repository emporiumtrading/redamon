"""Finite HTTPS browser gateway; original human credentials never cross into the extension."""
from datetime import datetime,timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
from threading import Lock
import time
from urllib.parse import urlsplit

from gabriel.identity.browser_sessions import approved_context,browser_digest
from gabriel.identity.browser_observations import BrowserObservationService
from gabriel.identity.browser_navigation import BrowserNavigationService
from gabriel.identity.checkpoints import read_document,write_document,_unique,_invalid_number
from gabriel.identity.cli import read_secret
from gabriel.identity.service import AccessDenied,IdentityError,IdentityUnavailable,_digest,connection

MAX_BODY = 262144
OPERATIONS = {'claim','heartbeat','observe','status','receipts','disconnect','navigation-plan','navigation-prepare','navigation-complete','events-review','specialists-review'}


def endpoint(value):
    if not isinstance(value,str):
        raise ValueError('invalid_gateway_endpoint')
    parsed=urlsplit(value)
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path not in {'','/'} or parsed.query or parsed.fragment or parsed.netloc!=parsed.netloc.lower()
            or any(ord(c)<33 or ord(c)>126 for c in value) or '\\' in value or '%' in value):
        raise ValueError('invalid_gateway_endpoint')
    parsed.port
    return 'https://'+parsed.netloc


def extension_origin(value):
    if not isinstance(value,str) or not re.fullmatch(r'chrome-extension://[a-p]{32}',value):
        raise ValueError('invalid_extension_origin')
    return value


def ticket_digest(value):
    if not isinstance(value,str) or not re.fullmatch(r'gbc1_[A-Za-z0-9_-]{43}',value):
        raise AccessDenied('invalid_claim_ticket')
    return sha256(('gabriel-browser-claim-v1|'+value).encode()).hexdigest()


def prepare(service,human_token,task_id,case_id,context,target,origin,directory,*,share_observations=False):
    """Private operator enrollment, never exposed as a network operation."""
    target,origin=endpoint(target),extension_origin(origin)
    context=approved_context(context)
    directory=Path(directory)
    if not directory.is_absolute() or '..' in directory.parts:
        raise ValueError('private_directory_required')
    directory.mkdir(mode=0o700)
    ticket='gbc1_'+secrets.token_urlsafe(32)
    grant=service.issue_browser_lease(human_token,task_id,case_id,context,share_observations=share_observations)
    try:
        write_document(directory/'human.json',{'token':human_token})
        write_document(directory/'peer.json',{'token':grant.token,'lease_id':str(grant.id),'expires_at':str(grant.expires_at)})
        write_document(directory/'claim.json',{'ticket':ticket})
        write_document(directory/'gateway.json',{'schema_version':1,'purpose':'gabriel-browser-gateway-v1',
            'endpoint':target,'extension_origin':origin,'context':context,'ticket_digest':ticket_digest(ticket),
            'lease_id':str(grant.id),'expires_at':str(grant.expires_at)})
    except (OSError,ValueError):
        service.revoke_browser_lease(human_token,grant.id)
        raise
    return {'lease_id':str(grant.id),'configuration_written':True,'claim_file':str(directory/'claim.json'),
        'expires_at':str(grant.expires_at),'endpoint':target}


class BrowserGateway:
    def __init__(self,service,human_token,peer_token,configuration):
        if not isinstance(service,BrowserObservationService):
            raise ValueError('observation_service_required')
        self.service=service
        self._human=human_token
        self._peer=peer_token
        self.context=approved_context(configuration['context'])
        self._initial_context=dict(self.context)
        self.target=endpoint(configuration['endpoint'])
        self.origin=extension_origin(configuration['extension_origin'])
        self.lease_id=configuration['lease_id']
        self._ticket=configuration['ticket_digest']
        if not isinstance(self._ticket,str) or not re.fullmatch('[a-f0-9]{64}',self._ticket):
            raise ValueError('invalid_ticket_digest')
        self._started=time.monotonic()
        self._claimed=False
        self._lock=Lock()
        self._window=time.monotonic()
        self._calls=0

    def _bound(self,*,pending=False,sync_context=True):
        with connection(self.service._dsn) as conn:
            p=self.service._principal(conn,self._human)
            hint=conn.execute('SELECT organization_id,human_session_digest FROM gabriel_identity.browser_leases WHERE token_digest=%s',
                (browser_digest(self._peer),)).fetchone()
            if not hint or hint['organization_id']!=p.organization_id or hint['human_session_digest']!=_digest(self._human):
                raise AccessDenied('gateway_original_session_required')
            principal,lease=self.service._browser(conn,self._peer,pending=pending)
            if str(lease['id'])!=self.lease_id:
                raise AccessDenied('gateway_lease_mismatch')
            if sync_context:
                if isinstance(self.service,BrowserNavigationService):
                    self.context=self.service.gateway_context(conn,principal,lease,self._initial_context)
                else: self.service._browser_context(lease,self.context)
            return lease

    def dispatch(self,operation,body,authorization):
        if operation not in OPERATIONS or not isinstance(body,dict):
            raise ValueError('unsupported_gateway_operation')
        with self._lock:
            now=time.monotonic()
            if now-self._window>=60:
                self._window,self._calls=now,0
            self._calls+=1
            if self._calls>120:
                raise AccessDenied('gateway_request_budget')
            if operation=='claim':
                if set(body)!={'ticket','context'} or self._claimed or now-self._started>60:
                    raise AccessDenied('claim_unavailable')
                if approved_context(body['context'])!=self.context or not hmac.compare_digest(ticket_digest(body['ticket']),self._ticket):
                    raise AccessDenied('claim_scope_mismatch')
                self._bound(pending=True)
                paired=self.service.connect_browser(self._peer,self.context)
                lease=self._bound()
                self._claimed=True
                return dict(paired,token=self._peer,context=self.context,organization_id=str(lease['organization_id']),
                    case_id=str(lease['case_id']),task_id=str(lease['task_id']))
            if not self._claimed or not isinstance(authorization,str) or not hmac.compare_digest(authorization,'Bearer '+self._peer):
                raise AccessDenied('gateway_peer_required')
            self._bound(sync_context=operation!='disconnect')
            if operation=='disconnect':
                if body!={}: raise ValueError('invalid_disconnect')
                self.service.disconnect_browser(self._peer)
                self._claimed=False
                return {'disconnected':True}
            if operation in {'navigation-plan','navigation-prepare','navigation-complete'}:
                if not isinstance(self.service,BrowserNavigationService):
                    raise AccessDenied('navigation_service_required')
                if operation=='navigation-plan':
                    if set(body)!={'context'}: raise ValueError('invalid_navigation_plan_request')
                    return self.service.navigation_plan(self._human,self._peer,body['context'])
                if operation=='navigation-prepare':
                    if set(body)!={'context','request_id','destination_url'} or approved_context(body['context'])!=self.context:
                        raise AccessDenied('gateway_scope_changed')
                    return self.service.prepare_navigation(self._human,self._peer,body['request_id'],body['destination_url'])
                if set(body)!={'intent_id','context'}: raise ValueError('invalid_navigation_completion')
                result=self.service.complete_navigation(self._human,self._peer,body['intent_id'],body['context'])
                self._bound()
                return result
            if operation=='observe':
                if body.get('context')!=self.context: raise AccessDenied('gateway_scope_changed')
                return self.service.observe_browser(self._human,self._peer,body)
            if operation in {'events-review','specialists-review'}:
                if (not isinstance(self.service,BrowserNavigationService) or set(body)!={'context','observation_id'}
                        or approved_context(body['context'])!=self.context): raise AccessDenied('gateway_scope_changed')
                method=self.service.review_browser_events if operation=='events-review' else self.service.review_browser_specialists
                return method(self._human,self._peer,body['context'],body['observation_id'])
            if set(body)!={'context'} or approved_context(body['context'])!=self.context:
                raise AccessDenied('gateway_scope_changed')
            if operation=='heartbeat': return self.service.heartbeat_browser(self._peer,self.context)
            # Metadata retrieval also proves freshness; stored state alone does not grant authority.
            self.service.heartbeat_browser(self._peer,self.context)
            if operation=='status': return self.service.get_browser_lease(self._human,self.lease_id)
            return self.service.list_browser_observations(self._human,self.lease_id)

    def __call__(self,environ,start_response):
        origin=environ.get('HTTP_ORIGIN','')
        headers=[('Content-Type','application/json'),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),
            ('Referrer-Policy','no-referrer'),('Vary','Origin')]
        if origin==self.origin:
            headers.extend([('Access-Control-Allow-Origin',origin),('Access-Control-Allow-Headers','Authorization, Content-Type'),
                ('Access-Control-Allow-Methods','POST, OPTIONS')])
        status='403 Forbidden'
        operation=environ.get('PATH_INFO','').removeprefix('/v1/browser/')
        result={'status':'denied','outcome':'not_confirmed' if operation in {'observe','navigation-complete','events-review','specialists-review'} else 'denied'}
        try:
            if (environ.get('wsgi.url_scheme')!='https' or environ.get('HTTP_HOST')!=urlsplit(self.target).netloc
                    or origin!=self.origin or environ.get('QUERY_STRING') or environ.get('HTTP_FORWARDED')
                    or any(k.startswith('HTTP_X_FORWARDED_') for k in environ)
                    or environ.get('PATH_INFO')!='/v1/browser/'+operation or operation not in OPERATIONS):
                raise AccessDenied('gateway_boundary_denied')
            if environ.get('REQUEST_METHOD')=='OPTIONS':
                if environ.get('HTTP_ACCESS_CONTROL_REQUEST_METHOD')!='POST': raise ValueError('invalid_preflight')
                requested={x.strip().lower() for x in environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS','').split(',') if x.strip()}
                if not requested<={'authorization','content-type'}: raise ValueError('invalid_preflight')
                status,result='200 OK',{'status':'preflight'}
            else:
                raw_length=environ.get('CONTENT_LENGTH','')
                if (environ.get('REQUEST_METHOD')!='POST' or environ.get('CONTENT_TYPE')!='application/json'
                        or environ.get('HTTP_CONTENT_ENCODING') or environ.get('HTTP_TRANSFER_ENCODING')
                        or not re.fullmatch('[0-9]{1,6}',raw_length) or not 2<=int(raw_length)<=MAX_BODY):
                    raise ValueError('invalid_gateway_request')
                raw=environ['wsgi.input'].read(int(raw_length))
                if len(raw)!=int(raw_length): raise ValueError('incomplete_body')
                body=json.loads(raw,object_pairs_hook=_unique,parse_constant=_invalid_number)
                result={'status':'ok','result':self.dispatch(operation,body,environ.get('HTTP_AUTHORIZATION'))}
                status='200 OK'
        except IdentityUnavailable:
            status='503 Service Unavailable'
        except (IdentityError,ValueError,TypeError,KeyError,UnicodeError,OSError,RecursionError):
            pass
        except Exception:
            status='500 Internal Server Error'
        data=json.dumps(result,default=str,allow_nan=False).encode()
        start_response(status,headers+[('Content-Length',str(len(data)))])
        return [data]


def load_gateway(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('absolute_private_configuration_required')
    configuration=read_document(path,private=True)
    if (not isinstance(configuration,dict) or set(configuration)!={'schema_version','purpose','endpoint','extension_origin',
            'context','ticket_digest','lease_id','expires_at'} or type(configuration['schema_version']) is not int
            or configuration['schema_version']!=1 or configuration['purpose']!='gabriel-browser-gateway-v1'):
        raise ValueError('invalid_gateway_configuration')
    human=read_document(path.parent/'human.json',private=True)['token']
    peer=read_document(path.parent/'peer.json',private=True)
    if peer['lease_id']!=configuration['lease_id']: raise ValueError('gateway_lease_mismatch')
    from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
    store=LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']))
    service=BrowserNavigationService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),store)
    app=BrowserGateway(service,human,peer['token'],configuration)
    app._bound(pending=True)
    # Worker/process restart cannot reuse a bootstrap or resurrect its original claim authority.
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if os.fstat(parent).st_mode & 0o077: raise ValueError('private_gateway_directory_required')
        fd=os.open(path.with_suffix('.started').name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try: os.fsync(fd)
        finally: os.close(fd)
        os.fsync(parent)
    finally: os.close(parent)
    return app


def serve(configuration,certificate,key,bind='127.0.0.1:8443'):
    from gunicorn.app.base import BaseApplication
    probe=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    probe.load_cert_chain(certificate,key)
    class Application(BaseApplication):
        def load_config(self):
            options={'bind':bind,'workers':1,'threads':4,'certfile':certificate,'keyfile':key,'accesslog':None,
                'errorlog':'-','capture_output':False,'forwarded_allow_ips':'','secure_scheme_headers':{},
                'timeout':30,'limit_request_line':2048,'limit_request_fields':32,'limit_request_field_size':4096}
            for name,value in options.items(): self.cfg.set(name,value)
        def load(self): return load_gateway(configuration)
    Application().run()
