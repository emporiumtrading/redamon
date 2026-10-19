"""Server-rendered analyst workbench bound to one operator's live Gabriel session."""
import base64
from hashlib import sha256
from html import escape
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
from threading import Lock
import time
from urllib.parse import parse_qsl,urlsplit

from gabriel.identity.browser_gateway import endpoint
from gabriel.identity.analyst_views import audit_history,source_health
from gabriel.identity.cases import CaseService
from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import AccessDenied,IdentityError,IdentityUnavailable,_audit,connection

COOKIE='__Host-gabriel_workbench'
STYLE='''body{margin:0;background:#101822;color:#e7edf5;font:16px/1.5 system-ui,sans-serif}header,main{max-width:1100px;margin:auto;padding:24px}header{border-bottom:1px solid #456}h1{font-size:26px}h2{font-size:21px}a{color:#89d5ff}nav{display:flex;gap:22px;align-items:center;flex-wrap:wrap}button,input{font:inherit;padding:10px;border:1px solid #89a;border-radius:5px}button{cursor:pointer;background:#b5e3ff;color:#102132}label{display:block;margin:18px 0}input{display:block;max-width:90%;width:460px}table{border-collapse:collapse;width:100%;margin:22px 0}th,td{padding:12px;text-align:left;border-bottom:1px solid #456;vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;background:#1c2938}small,.muted{color:#bbc9d8}.notice{padding:14px;border-left:4px solid #e8b85e;background:#30291b}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #ffc86b;outline-offset:4px}form{margin:18px 0}caption{text-align:left;font-weight:bold}code{overflow-wrap:anywhere}'''
STYLE_HASH=base64.b64encode(sha256(STYLE.encode()).digest()).decode()
ID=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def ticket_hash(ticket):
    if not isinstance(ticket,str) or not re.fullmatch(r'gwt1_[A-Za-z0-9_-]{43}',ticket):
        raise AccessDenied('workbench_ticket_denied')
    return sha256(('gabriel-workbench-v1|'+ticket).encode()).hexdigest()


def prepare_workbench(service,token,target,directory):
    target=endpoint(target)
    directory=Path(directory)
    if not directory.is_absolute() or '..' in directory.parts:
        raise ValueError('absolute_private_directory_required')
    with connection(service._dsn) as conn:
        p=service._principal(conn,token,lock=True)
        _audit(conn,'workbench.prepared',p)
    directory.mkdir(mode=0o700)
    ticket='gwt1_'+secrets.token_urlsafe(32)
    write_document(directory/'human.json',{'token':token})
    write_document(directory/'claim.json',{'ticket':ticket})
    write_document(directory/'workbench.json',dict(schema_version=1,purpose='gabriel-workbench-v1',endpoint=target,ticket_digest=ticket_hash(ticket)))
    return dict(configuration_written=True,endpoint=target,claim_file=str(directory/'claim.json'))


def e(value): return escape(str(value),quote=True)


def table(columns,rows):
    return '<table><thead><tr>'+''.join('<th scope="col">'+e(c)+'</th>' for c in columns)+'</tr></thead><tbody>'+''.join(
        '<tr>'+''.join('<td>'+value+'</td>' for value in row)+'</tr>' for row in rows)+'</tbody></table>'


class Workbench:
    def __init__(self,service,token,configuration):
        if not isinstance(service,CaseService): raise ValueError('case_service_required')
        self.service,self._token=service,token
        self.target=endpoint(configuration['endpoint'])
        self._ticket=configuration['ticket_digest']
        if not isinstance(self._ticket,str) or not re.fullmatch('[a-f0-9]{64}',self._ticket): raise ValueError('invalid_ticket_digest')
        self._started=time.monotonic()
        self._cookie=None
        self._claimed=False
        self._csrf=secrets.token_urlsafe(32)
        self._create=None
        self._lock=Lock()
        self._window=self._started
        self._calls=0

    def _audit(self,event):
        with connection(self.service._dsn) as conn:
            p=self.service._principal(conn,self._token,lock=True)
            _audit(conn,event,p)
            return p

    def _form(self,path,label,fields=''):
        return '<form method="post" action="'+path+'"><input type="hidden" name="csrf" value="'+e(self._csrf)+'">'+fields+'<button type="submit">'+e(label)+'</button></form>'

    def _page(self,title,body,principal=None):
        navigation=''
        if principal:
            navigation='<p id="team-scope">Organization '+e(principal.organization_id)+' · Role '+e(principal.role)+'</p><nav><a href="/cases">Cases</a><a href="/sources">Browser health</a>'
            if principal.role!='viewer': navigation+='<a href="/cases/new">New case</a>'
            if principal.role!='viewer': navigation+='<a href="/audit">Audit</a>'
            navigation+=self._form('/disconnect','Disconnect workbench')+'</nav>'
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+e(title)+' · Gabriel</title><style>'+STYLE+'</style></head><body><header><a href="/cases">Gabriel — The Defender</a>'+navigation+'</header><main id="main"><h1>'+e(title)+'</h1>'+body+'</main></body></html>').encode()

    def _fields(self,environ):
        length=environ.get('CONTENT_LENGTH','')
        if (environ.get('CONTENT_TYPE')!='application/x-www-form-urlencoded' or not re.fullmatch('[0-9]{1,4}',length)
                or not 1<=int(length)<=4096 or environ.get('HTTP_CONTENT_ENCODING') or environ.get('HTTP_TRANSFER_ENCODING')):
            raise AccessDenied('invalid_workbench_form')
        raw=environ['wsgi.input'].read(int(length))
        if len(raw)!=int(length): raise AccessDenied('invalid_workbench_form')
        pairs=parse_qsl(raw.decode('utf-8'),keep_blank_values=True,strict_parsing=True,encoding='utf-8',errors='strict',max_num_fields=8)
        if len(dict(pairs))!=len(pairs): raise AccessDenied('duplicate_form_field')
        fields=dict(pairs)
        if not hmac.compare_digest(fields.get('csrf',''),self._csrf): raise AccessDenied('csrf_required')
        return fields

    def _authenticate(self,environ):
        raw=environ.get('HTTP_COOKIE','')
        if len(raw)>2048: raise AccessDenied('workbench_session_required')
        cookies=[part.strip().split('=',1)[1] for part in raw.split(';') if part.strip().startswith(COOKIE+'=')]
        if (not self._cookie or len(cookies)!=1 or not hmac.compare_digest(cookies[0],self._cookie)
                or time.monotonic()-self._started>600): raise AccessDenied('workbench_session_required')
        return self.service.whoami(self._token)

    def _route(self,environ):
        method,path=environ['REQUEST_METHOD'],environ['PATH_INFO']
        if (environ.get('wsgi.url_scheme')!='https' or environ.get('HTTP_HOST')!=urlsplit(self.target).netloc
                or environ.get('QUERY_STRING') or environ.get('HTTP_FORWARDED') or any(k.startswith('HTTP_X_FORWARDED_') for k in environ)
                or environ.get('HTTP_CONTENT_ENCODING') or environ.get('HTTP_TRANSFER_ENCODING')
                or (method=='GET' and environ.get('CONTENT_LENGTH','') not in {'','0'})
                or environ.get('HTTP_SEC_FETCH_SITE') in {'cross-site','same-site'} or method not in {'GET','POST'}):
            raise AccessDenied('workbench_boundary_denied')
        fields={}
        if method=='POST':
            if environ.get('HTTP_ORIGIN')!=self.target: raise AccessDenied('workbench_origin_required')
            fields=self._fields(environ)
        if path=='/claim':
            if self._claimed or time.monotonic()-self._started>60: raise AccessDenied('workbench_claim_unavailable')
            if method=='GET':
                return '200 OK',self._page('Connect to your workbench','<p>Enter the short-lived access ticket from your authenticated Gabriel operator.</p>'+self._form('/claim','Connect','<label>Access ticket<input name="ticket" type="password" autocomplete="off" required></label>')),[]
            if set(fields)!={'csrf','ticket'} or not hmac.compare_digest(ticket_hash(fields['ticket']),self._ticket): raise AccessDenied('workbench_ticket_denied')
            self._audit('workbench.claimed')
            self._cookie='gwu1_'+secrets.token_urlsafe(32)
            self._claimed=True
            return '303 See Other',b'',[('Location','/cases'),('Set-Cookie',COOKIE+'='+self._cookie+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600')]
        principal=self._authenticate(environ)
        if method=='GET' and path=='/sources':
            result=source_health(self.service,self._token)
            body='<p class="notice">Partial coverage. A recent heartbeat does not establish current page visibility or uninterrupted monitoring. Sources are sampled individually.</p>'
            body+=table(['Browser','Health','Last heartbeat','Expires','Case'],[(e(row['browser']),e(row['health']),e(row['last_seen'] or 'Never recorded'),e(row['expires_at']),'<a href="/cases/'+e(row['case_id'])+'">'+e(row['case_id'])+'</a>') for row in result['sources']]) if result['sources'] else '<p>No browser sessions recorded.</p>'
            body+='<p>Showing up to 32 most recent sessions.'+(' Older sessions are omitted.' if result['truncated'] else '')+'</p>'
            return '200 OK',self._page('Browser health and coverage',body,principal),[]
        if method=='GET' and path=='/audit':
            result=audit_history(self.service,self._token)
            body=table(['Server time','Event','Actor','Target'],[(e(row['created_at']),e(row['event']),e(row['actor_id'] or ''),e(row['target_id'] or '')) for row in result['events']])
            body+='<p>Showing up to 200 most recent tenant events.'+(' Older events are omitted.' if result['truncated'] else '')+'</p>'
            return '200 OK',self._page('Audit activity',body,principal),[]
        if method=='POST' and path=='/disconnect' and set(fields)=={'csrf'}:
            self._cookie=None
            self._create=None
            self._audit('workbench.disconnected')
            return '200 OK',self._page('Disconnected','<p>Workbench access has ended. Obtain a fresh operator ticket to reconnect.</p>'),[('Set-Cookie',COOKIE+'=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0')]
        if method=='GET' and path in {'/','/cases'}:
            rows=self.service.list_cases(self._token)
            body='<p class="notice">Collection coverage is partial. Incident assessment has not been performed.</p>'
            body+=table(['Case','State','Created'],[(f'<a href="/cases/{e(row["id"])}">{e(row["title"])}</a>',e(row['state']),e(row['created_at'])) for row in rows]) if rows else '<p id="empty">No cases yet.</p>'
            body+='<p class="muted">Showing up to 100 most recently created cases.</p>'
            return '200 OK',self._page('Investigations',body,principal),[]
        if path=='/cases/new' and method=='GET':
            if principal.role=='viewer': raise AccessDenied('operation_not_permitted')
            self._create=secrets.token_urlsafe(32)
            body=self._form('/cases','Create case','<input type="hidden" name="nonce" value="'+self._create+'"><label>Case title<input name="title" maxlength="160" required></label>')
            return '200 OK',self._page('New investigation',body,principal),[]
        if path=='/cases' and method=='POST':
            if set(fields)!={'csrf','nonce','title'} or not self._create or not hmac.compare_digest(fields['nonce'],self._create): raise AccessDenied('fresh_case_form_required')
            self._create=None
            case=self.service.create_case(self._token,fields['title'])
            return '303 See Other',b'',[('Location','/cases/'+str(case['id']))]
        match=re.fullmatch('/cases/('+ID+')(?:/(report)|/evidence/('+ID+')(?:/(content))?)?',path)
        if not match: raise AccessDenied('workbench_route_denied')
        case_id,report,evidence_id,content=match.groups()
        case=self.service.get_case(self._token,case_id)
        if evidence_id:
            artifact=next((row for row in case['evidence'] if str(row['id'])==evidence_id),None)
            if not artifact: raise AccessDenied('case_evidence_not_accessible')
            if content:
                if method!='POST' or set(fields)!={'csrf'}: raise AccessDenied('explicit_content_view_required')
                bundle=self.service.read_evidence(self._token,evidence_id)
                body='<p class="notice">Stored content integrity verified on this read. Source authenticity remains unverified.</p><pre id="evidence-content">'+e(bundle.reveal().decode('utf-8'))+'</pre>'
            else:
                if method!='GET': raise AccessDenied('workbench_route_denied')
                chain=self.service.custody(self._token,evidence_id)
                body='<p>Source: '+e(artifact['source_label'])+' · Storage: '+e(artifact['storage_state'])+'</p>'
                body+=table(['Sequence','Custody event','Server time','Event hash'],[(e(row['sequence']),e(row['event']),e(row['created_at']),e(row['event_hash'])) for row in chain])
                if principal.role!='viewer' and artifact['storage_state']=='active': body+=self._form(path+'/content','View evidence content')
            return '200 OK',self._page('Evidence and custody',body,principal),[]
        if method!='GET': raise AccessDenied('workbench_route_denied')
        result=self.service.case_report(self._token,case_id)
        if report:
            return '200 OK',json.dumps(result,ensure_ascii=False,allow_nan=False).encode(),[('Content-Type','application/json'),('Content-Disposition','attachment; filename="gabriel-case-'+case_id+'.json"')]
        snapshot=result['snapshot']
        body='<p>State: '+e(snapshot['case']['state'])+' · Coverage: partial · Assessment: not performed</p><p><a href="'+path+'/report">Download metadata report</a></p>'
        body+='<h2>Evidence</h2>'+table(['Artifact','Source','Storage'],[(f'<a href="{path}/evidence/{e(row["id"])}">{e(row["id"])}</a>',e(row['source_label']),e(row['storage_state'])) for row in snapshot['evidence']])
        body+='<h2>Timeline</h2><p>Source and client clocks are unverified. Times do not establish causal ordering.</p>'+table(['Time','Time basis','Event','Evidence'],[(e(row['time']),e(row['time_basis']),e(row['kind']),e(row['evidence_id'] or '')) for row in snapshot['timeline']])
        body+='<h2>Browser observations</h2>'+table(['Observation','State','Visibility'],[(e(row['id']),e(row['state']),e(row['coverage'])) for row in snapshot['browser_observations']])
        return '200 OK',self._page(snapshot['case']['title'],body,principal),[]

    def __call__(self,environ,start_response):
        # Preserve the same-origin form Origin; suppress referrers to external destinations.
        headers=[('Content-Type','text/html; charset=utf-8'),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('Referrer-Policy','same-origin'),('X-Frame-Options','DENY'),('Content-Security-Policy',"default-src 'none'; style-src 'sha256-"+STYLE_HASH+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),('Cross-Origin-Resource-Policy','same-origin')]
        status='403 Forbidden'
        body=self._page('Access unavailable','<p>Check your access, scope and ticket expiry with your Gabriel operator.</p>')
        try:
            with self._lock:
                now=time.monotonic()
                if now-self._window>=60: self._window,self._calls=now,0
                self._calls+=1
                if self._calls>120: raise AccessDenied('workbench_request_budget')
                candidate_status,candidate_body,extra=self._route(environ)
                if len(candidate_body)>2*1024*1024: raise AccessDenied('workbench_response_limit')
                status,body=candidate_status,candidate_body
                for key,value in extra:
                    headers=[(k,v) for k,v in headers if k.lower()!=key.lower()]
                    headers.append((key,value))
        except IdentityUnavailable:
            status='503 Service Unavailable'
            body=self._page('Temporarily unavailable','<p>The request could not be confirmed. Review the case queue before retrying a change.</p>')
        except (IdentityError,ValueError,TypeError,KeyError,UnicodeError,OSError,RecursionError): pass
        except Exception:
            status='500 Internal Server Error'
        start_response(status,headers+[('Content-Length',str(len(body)))])
        return [body]


def load_workbench(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('absolute_private_configuration_required')
    config=read_document(path,private=True)
    if (not isinstance(config,dict) or set(config)!={'schema_version','purpose','endpoint','ticket_digest'}
            or type(config['schema_version']) is not int or config['schema_version']!=1 or config['purpose']!='gabriel-workbench-v1'):
        raise ValueError('invalid_workbench_configuration')
    token=read_document(path.parent/'human.json',private=True)['token']
    store=LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']))
    app=Workbench(CaseService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),store),token,config)
    app.service.whoami(token)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if os.fstat(parent).st_mode & 0o077: raise ValueError('private_workbench_directory_required')
        fd=os.open('workbench.started',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try: os.fsync(fd)
        finally: os.close(fd)
        os.fsync(parent)
    finally: os.close(parent)
    return app


def serve_workbench(configuration,certificate,key,bind='127.0.0.1:8444'):
    from gunicorn.app.base import BaseApplication
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate,key)
    class Application(BaseApplication):
        def load_config(self):
            for name,value in dict(bind=bind,workers=1,threads=4,certfile=certificate,keyfile=key,accesslog=None,errorlog='-',
                    forwarded_allow_ips='',secure_scheme_headers={},timeout=30,limit_request_line=2048,limit_request_fields=32,limit_request_field_size=4096).items():
                self.cfg.set(name,value)
        def load(self): return load_workbench(configuration)
    Application().run()
