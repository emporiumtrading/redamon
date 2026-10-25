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
from uuid import uuid4

from gabriel.identity.browser_gateway import endpoint
from gabriel.identity.analyst_views import audit_history,source_health
from gabriel.identity.cases import CaseService
from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.model_budget import ModelBudgetService
from gabriel.identity.service import AccessDenied,IdentityError,IdentityUnavailable,_audit,connection

COOKIE='__Host-gabriel_workbench'
STYLE='''
:root{color-scheme:dark;--bg:#0a1019;--surface:#111c2a;--raised:#162333;--line:#2b3c50;--text:#f4f0e8;--muted:#a9bacd;--accent:#e7c88a;--blue:#b7d5fa;--gold:#f3ca87;--radius:16px}
*{box-sizing:border-box}html{scroll-padding-top:24px}body{margin:0;background:radial-gradient(ellipse at 95% 0,#75613d30,transparent 52%),var(--bg);color:var(--text);font:15px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--blue);text-underline-offset:4px;overflow-wrap:anywhere}a:hover{color:var(--accent)}button,input,select,textarea{font:inherit}button,a,input,select,textarea{touch-action:manipulation}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,[tabindex]:focus-visible{outline:3px solid var(--gold);outline-offset:4px}.skip-link{position:fixed;top:8px;left:12px;transform:translateY(-180%);z-index:100;background:var(--accent);color:#292011;padding:10px 18px;border-radius:8px}.skip-link:focus{transform:none}
.shell{min-height:100vh;display:grid;grid-template-columns:250px minmax(0,1fr)}.sidebar{position:sticky;top:0;height:100vh;overflow-y:auto;border-right:1px solid var(--line);padding:32px 20px;background:#0c1521eF;display:flex;flex-direction:column;gap:30px}.brand{display:flex;align-items:center;gap:12px;color:var(--text);text-decoration:none}.brand-mark{display:grid;place-items:center;width:54px;height:54px;flex-shrink:0;color:var(--accent)}.brand-mark svg{width:100%;height:100%;filter:drop-shadow(0 0 12px #e7c88a20)}.brand-name{display:block;font-size:21px;letter-spacing:2.5px;font-weight:650}.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase}.nav-label,.eyebrow{color:var(--accent);font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:2px}.sidebar nav{display:grid;gap:7px;margin-top:12px}.sidebar nav a{display:flex;align-items:center;gap:12px;padding:11px 13px;border:1px solid transparent;border-radius:10px;color:var(--muted);text-decoration:none;font-weight:550}.nav-icon{display:grid;place-items:center;width:24px;font-size:17px;color:var(--accent)}.sidebar nav a:hover{background:var(--raised);color:var(--text)}.sidebar nav a[aria-current=page]{background:#e7c88a12;border-color:#e7c88a45;color:var(--accent)}.team-card{margin-top:auto;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px}.team-card p{font-size:11px;color:var(--muted);overflow-wrap:anywhere;margin:8px 0}.team-card form{padding:0;border:0;background:none;margin:14px 0 0;box-shadow:none}.team-card button{width:100%;background:transparent;color:#ffd0cf;border-color:#815356;font-size:12px;padding:9px}.team-card button:hover{background:#41252d}
.workspace{min-width:0}.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:20px 38px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}.workspace-label{letter-spacing:1.3px;text-transform:uppercase;font-size:10px;font-weight:700}.mode-tag{border:1px solid #60765b;color:#d0e0bd;background:#b5d5930b;padding:5px 10px;border-radius:30px;font-size:11px}main{width:100%;max-width:1440px;margin:auto;padding:38px;min-width:0}.page-heading{position:relative;isolation:isolate;overflow:hidden;margin-bottom:30px;padding:30px;border:1px solid #e7c88a30;border-radius:18px;background:radial-gradient(ellipse at 100% 0,#b2935524,transparent 65%),linear-gradient(120deg,#172333,#101a28)}.page-heading:after{content:"";position:absolute;z-index:-1;right:-65px;top:-165px;width:350px;height:350px;border:1px solid #e7c88a1c;border-radius:50%;box-shadow:0 0 0 28px #e7c88a05,0 0 0 58px #e7c88a04;pointer-events:none}h1{font-family:ui-serif,Georgia,"Times New Roman",serif;font-size:clamp(27px,3vw,40px);line-height:1.2;font-weight:650;letter-spacing:-1px;margin:10px 0 12px;overflow-wrap:anywhere}.page-heading p{color:var(--muted);max-width:720px;margin:0}h2{font-size:19px;line-height:1.4;letter-spacing:-.3px;margin:34px 0 16px;display:flex;align-items:center;gap:12px}h2:before{content:"";height:18px;width:3px;flex-shrink:0;border-radius:3px;background:var(--accent)}h3{font-size:16px;margin:0 0 14px}p{overflow-wrap:anywhere}small,.muted{color:var(--muted)}.content>p:first-child{color:var(--muted)}.notice{padding:17px 20px;border:1px solid #a2814b66;border-left:3px solid var(--gold);border-radius:0 12px 12px 0;background:#f3ca8708;color:#eed7b5;margin:20px 0}.content>section{padding:24px;background:linear-gradient(145deg,#162333,#101b29);border:1px solid var(--line);border-radius:var(--radius);margin:18px 0}.content>section h2:first-child{margin-top:0}
form{padding:22px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);margin:20px 0;box-shadow:0 8px 25px #00000015}label{display:block;color:var(--muted);font-size:13px;font-weight:550;margin:0 0 18px;overflow-wrap:anywhere}input:not([type=hidden]):not([type=checkbox]),select,textarea{display:block;width:100%;max-width:660px;margin-top:8px;padding:12px 14px;border:1px solid #42566d;border-radius:9px;background:#0a1421;color:var(--text);min-height:46px}input[type=checkbox]{accent-color:var(--accent);width:18px;height:18px;vertical-align:middle;margin-right:9px}select{white-space:normal}textarea{resize:vertical;min-height:110px}button{padding:11px 19px;border:1px solid #e7c88a;border-radius:9px;background:linear-gradient(135deg,#f5dfb1,#d2af6c);color:#292011;font-weight:700;cursor:pointer;min-height:44px;max-width:100%;white-space:normal}button:hover{background:#fff0d1;box-shadow:0 3px 18px #e7c88a20}button:disabled{opacity:.55;cursor:not-allowed}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:22px;background:#080f19;border:1px solid var(--line);border-radius:12px;font:13px/1.8 ui-monospace,SFMono-Regular,Consolas,monospace}code{overflow-wrap:anywhere;font-size:.9em}.table-scroll{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:var(--radius);margin:20px 0;background:var(--surface)}table{border-collapse:collapse;width:100%;table-layout:fixed}th,td{text-align:left;padding:16px 18px;vertical-align:top;overflow-wrap:anywhere;border-bottom:1px solid var(--line)}th{background:#1b2a3b;color:#c1d2e5;font-size:11px;letter-spacing:1px;text-transform:uppercase;font-weight:700}td{font-size:13px}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#e7c88a05}td a{font-weight:550}caption{text-align:left;padding:16px}.empty-state{padding:48px 25px;text-align:center;border:1px dashed #496176;border-radius:var(--radius);background:linear-gradient(145deg,#132331,#101a28)}.empty-state h2{display:block;margin:10px 0}.empty-state h2:before{display:none}.empty-state p{color:var(--muted);max-width:450px;margin:12px auto}.empty-mark{display:inline-grid;place-items:center;font-size:25px;color:var(--accent);width:58px;height:58px;background:#e7c88a12;border:1px solid #e7c88a50;border-radius:16px}.case-state{padding:15px 18px;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--muted)}.case-links{display:flex;flex-wrap:wrap;gap:9px;align-items:center;color:transparent;font-size:0}.case-links a{font-size:12px;text-decoration:none;padding:9px 13px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--blue)}.case-links a:hover{border-color:var(--accent);color:var(--accent)}.footer{padding:25px 0;color:var(--muted);font-size:11px;letter-spacing:.3px;border-top:1px solid var(--line);margin-top:38px}.auth-shell .sidebar{height:auto;position:relative;overflow:hidden;background:radial-gradient(ellipse at 50% 35%,#a4874520,transparent 65%),#0c1521}.guardian-art{margin:auto 0;color:var(--accent);text-align:center}.guardian-art svg{width:100%;max-width:200px;opacity:.75}.guardian-art p{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--muted);line-height:2.4}.auth-shell .workspace{display:flex;flex-direction:column;justify-content:center}.auth-shell main{max-width:850px}.auth-shell .topbar{display:none}
@media(min-width:1500px){main{padding:48px 58px}.topbar{padding-left:58px;padding-right:58px}}
@media(max-width:900px){.shell{grid-template-columns:210px minmax(0,1fr)}.sidebar{padding:26px 14px}.topbar{padding:18px 24px}main{padding:28px 24px}.brand-name{font-size:18px}}
@media(max-width:640px){.shell{display:block}.sidebar{position:relative;height:auto;gap:18px;padding:20px;border-right:0;border-bottom:1px solid var(--line)}.sidebar nav{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.sidebar nav a{padding:10px;font-size:12px}.nav-label{display:none}.team-card{margin-top:0;padding:12px}.team-card p{margin:4px 0}.team-card form{margin-top:10px}.team-card button{width:auto}.topbar{padding:15px 20px;flex-wrap:wrap}main{padding:26px 20px}.page-heading{margin-bottom:22px}th,td{padding:12px 9px;font-size:12px}th{font-size:10px;letter-spacing:.3px}.table-scroll table{min-width:420px}form,.content>section{padding:18px}h1{letter-spacing:-.6px}.auth-shell .sidebar{padding:24px 20px}.guardian-art{display:none}.auth-shell main{padding-top:38px}.mode-tag{font-size:10px}}
@media(prefers-reduced-motion:no-preference){a,button{transition:background .15s,color .15s,box-shadow .15s}}
@media(forced-colors:active){.brand-mark{clip-path:none;border:2px solid ButtonText}.nav-icon,.eyebrow{color:LinkText}button{border:2px solid ButtonText}.sidebar nav a[aria-current=page]{border:2px solid Highlight}}
@media print{body{background:white;color:black}.sidebar,.topbar,.skip-link,form{display:none}.shell{display:block}main{padding:0;max-width:none}.page-heading,.table-scroll,th,td,pre,.content>section{background:white;color:black;box-shadow:none;border-color:#999}a{color:black}.footer{color:#444}}
'''
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


def dollars(value):
    return str(value//1000000)+'.'+str(value%1000000).zfill(6)


def budget_amount(value):
    if not isinstance(value,str) or re.fullmatch(r'(?:0|[1-9][0-9]?)(?:\.[0-9]{1,6})?',value) is None:
        raise AccessDenied('invalid_spending_amount')
    whole,_,fraction=value.partition('.')
    return int(whole)*1000000+int(fraction.ljust(6,'0'))


def table(columns,rows):
    return '<div class="table-scroll" role="region" aria-label="'+e(' / '.join(columns))+'" tabindex="0"><table><thead><tr>'+''.join('<th scope="col">'+e(c)+'</th>' for c in columns)+'</tr></thead><tbody>'+''.join(
        '<tr>'+''.join('<td>'+value+'</td>' for value in row)+'</tr>' for row in rows)+'</tbody></table></div>'


class Workbench:
    def __init__(self,service,token,configuration,*,provider_vault=None):
        if not isinstance(service,CaseService): raise ValueError('case_service_required')
        self.service,self._token=service,token
        if provider_vault is not None and provider_vault._dsn!=service._dsn:
            raise ValueError('same_backend_provider_vault_required')
        self._provider_vault=provider_vault
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
        descriptions={
            'Investigations':'Follow the evidence. Keep decisions grounded in what has been observed.',
            'New investigation':'Start with a clear question. Build the evidence trail as your investigation develops.',
            'Connect to your workbench':'Your private workspace for evidence-led investigation.',
            'Browser health and coverage':'Understand which sources are connected and where visibility is limited.',
            'AI spending':'Review reservations, set allowances and keep costs within your control.',
            'Audit activity':'Trace recorded actions across your organization.',
            'Your AI keys':'Manage your organization’s private provider connections.',
            'Case provenance':'Follow the recorded links between your case, evidence and observations.',
            'Specialist assessments':'Review specialist findings alongside their evidence and limitations.',
            'Memory review':'Control what is proposed, reviewed and retained for later investigations.',
            'Local investigation plan':'Step through local checks and inspect the receipts behind each result.',
            'Environment and control profile':'Review reported assets, identities and the gaps in available evidence.',
            'Evidence and custody':'Inspect the evidence record and its chain of custody.',
        }
        navigation=''
        if principal:
            items=[('/cases','Cases','▦'),('/sources','Browser health','◎'),('/spending','AI spending','$')]
            if principal.role!='viewer': items.extend([('/cases/new','New case','+'),('/audit','Audit','≡')])
            if principal.role in {'owner','admin'}: items.append(('/providers','Your AI keys','◇'))
            active={'Browser health and coverage':'/sources','AI spending':'/spending','New investigation':'/cases/new',
                'Audit activity':'/audit','Your AI keys':'/providers'}.get(title,'/cases')
            navigation='<div><span class="nav-label">Workspace</span><nav aria-label="Main navigation">'+''.join(
                '<a href="'+path+'"'+(' aria-current="page"' if path==active else '')+'><span class="nav-icon" aria-hidden="true">'+icon+'</span>'+label+'</a>'
                for path,label,icon in items)+'</nav></div>'
            navigation+='<div class="team-card"><span class="eyebrow">Team scope</span><p id="team-scope">Organization '+e(principal.organization_id)+' · Role '+e(principal.role)+'</p>'+self._form('/disconnect','Disconnect workbench')+'</div>'
        emblem='<svg viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="40" cy="12" rx="11" ry="4"/><path d="M32 30C23 31 15 22 5 20c1 17 8 28 24 31M31 37 10 28m20 15L15 36m14 13-8-5M48 30c9 1 17-8 27-10-1 17-8 28-24 31m-2-14 21-9M50 43l15-7m-14 13 8-5"/><path d="m40 25 13 7v17c0 10-7 17-13 21-6-4-13-11-13-21V32l13-7Z"/><path d="m40 35 5 9-5 13-5-13 5-9Z"/></svg>'
        brand='<a class="brand" href="/cases" aria-label="Gabriel — The Defender"><span class="brand-mark">'+emblem+'</span><span><span class="brand-name">GABRIEL</span><small>The Defender</small></span></a>'
        if not principal: navigation='<div class="guardian-art">'+emblem+'<p>Clarity in the evidence.<br>Care in every decision.</p></div>'
        description=descriptions.get(title,'Review the record, inspect its sources and document the next step.')
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+e(title)+' · Gabriel</title><style>'+STYLE+'</style></head><body><a class="skip-link" href="#main">Skip to content</a><div class="shell'+(' auth-shell' if not principal else '')+'"><aside class="sidebar">'+brand+navigation+'</aside><div class="workspace"><header class="topbar"><span class="workspace-label">Analyst workbench</span><span class="mode-tag">Evidence-led · Human review</span></header><main id="main" tabindex="-1"><div class="page-heading"><span class="eyebrow">Gabriel / Investigation workspace</span><h1>'+e(title)+'</h1><p>'+e(description)+'</p></div><div class="content">'+body+'</div><footer class="footer">Gabriel — The Defender · Source evidence and coverage limits remain visible throughout your review.</footer></main></div></div></body></html>').encode()

    def _fields(self,environ):
        length=environ.get('CONTENT_LENGTH','')
        if (environ.get('CONTENT_TYPE')!='application/x-www-form-urlencoded' or not re.fullmatch('[0-9]{1,5}',length)
                or not 1<=int(length)<=16384 or environ.get('HTTP_CONTENT_ENCODING') or environ.get('HTTP_TRANSFER_ENCODING')):
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
        if path in {'/providers','/providers/save','/providers/revoke'}:
            if principal.role not in {'owner','admin'}: raise AccessDenied('provider_admin_required')
            if self._provider_vault is None:
                if method!='GET' or path!='/providers': raise AccessDenied('provider_vault_not_configured')
                return '200 OK',self._page('Your AI keys','<p class="notice">Private key storage must be configured on this Gabriel host before adding your own provider keys. No shared development key is available.</p>',principal),[]
            from gabriel.identity.provider_onboarding import CustomerProviders
            providers=CustomerProviders(self._provider_vault)
            if method=='POST':
                expected={'csrf','provider','api_key'} if path=='/providers/save' else {'csrf','provider'}
                if path=='/providers' or set(fields)!=expected or fields['provider'] not in {'openrouter','nvidia'}:
                    raise AccessDenied('invalid_provider_form')
                if path=='/providers/save': providers.configure(self._token,fields['provider'],fields['api_key'])
                else: self._provider_vault.revoke(self._token,fields['provider'])
                return '303 See Other',b'',[('Location','/providers')]
            if method!='GET' or path!='/providers': raise AccessDenied('workbench_route_denied')
            rows=providers.status(self._token)
            body='<p>Use your organization’s own provider accounts. Gabriel has no shared API key and does not top up accounts automatically.</p>'
            body+='<p>OpenRouter setup requires at least $18 account credit and $18 remaining on a dedicated inference key capped at $18 per month. After setup, normal usage may reduce the balance; daily and investigation limits still apply.</p>'
            body+='<p class="notice">Adding a key does not enable an unqualified model. NVIDIA validation and production routing remain pending. Balance checks show historical provider reports.</p>'
            body+=table(['Provider','Setup status','Last checked'],[(e(r['provider']),e(r['status'].replace('_',' ')),e(r['checked_at'] or 'Not checked')) for r in rows])
            for provider,label in [('openrouter','OpenRouter'),('nvidia','NVIDIA')]:
                body+='<h2>'+label+'</h2>'+self._form('/providers/save','Save your '+label+' key',
                    '<input type="hidden" name="provider" value="'+provider+'"><label>Your '+label+' API key<input type="password" name="api_key" autocomplete="off" spellcheck="false" maxlength="512" required></label>')
                body+=self._form('/providers/revoke','Remove '+label+' key','<input type="hidden" name="provider" value="'+provider+'">')
            return '200 OK',self._page('Your AI keys',body,principal),[]
        if path in {'/spending','/spending/limits'}:
            budget=ModelBudgetService(self.service._dsn)
            if method=='POST' and path=='/spending/limits':
                if set(fields)!={'csrf','month','day','investigation','enabled'} or fields['enabled'] not in {'yes','no'}:
                    raise AccessDenied('invalid_spending_form')
                budget.configure(self._token,enabled=fields['enabled']=='yes',
                    month_microusd=budget_amount(fields['month']),day_microusd=budget_amount(fields['day']),
                    investigation_microusd=budget_amount(fields['investigation']))
                return '303 See Other',b'',[('Location','/spending')]
            if method!='GET' or path!='/spending': raise AccessDenied('workbench_route_denied')
            result=budget.status(self._token)
            policy,used=result['limits'],result['usage']
            body='<p class="notice">Models are not active. These controls manage local cost reservations; provider billing has not been independently verified.</p>'
            body+='<p id="spending-state">New reservations '+('allowed' if policy['enabled'] else 'paused')+'</p>'
            body+=table(['Budget','Used or reserved','Limit'],[(e('Month (UTC)'),e('$'+dollars(used['month_used'])),e('$'+dollars(policy['month_microusd']))),
                (e('Day (UTC)'),e('$'+dollars(used['day_used'])),e('$'+dollars(policy['day_microusd']))),
                (e('Per investigation'),e('Varies by investigation'),e('$'+dollars(policy['investigation_microusd'])))])
            body+='<p id="spending-held">Unresolved reservations: '+e(used['held_slots'])+' of 2. Unknown costs remain reserved until reconciled.</p>'
            body+='<p>The monthly dispatch allowance is at most $18 within your $20 envelope. Other applications using the same provider account are outside this ledger. Automatic top-up is disabled.</p>'
            if principal.role in {'owner','admin'}:
                form=''
                for name,label,key,maximum in [('month','Monthly allowance (USD)','month_microusd','18'),('day','Daily allowance (USD)','day_microusd','0.50'),('investigation','Per-investigation allowance (USD)','investigation_microusd','0.05')]:
                    form+='<label>'+label+'<input type="number" name="'+name+'" min="0.000001" max="'+maximum+'" step="0.000001" value="'+dollars(policy[key])+'" required></label>'
                form+='<label>New reservations<select name="enabled"><option value="yes"'+(' selected' if policy['enabled'] else '')+'>Allow within limits</option><option value="no"'+(' selected' if not policy['enabled'] else '')+'>Pause</option></select></label>'
                body+=self._form('/spending/limits','Save spending controls',form)
            else:
                body+='<p>Ask your owner or administrator to change spending controls.</p>'
            return '200 OK',self._page('AI spending',body,principal),[]
        if method=='GET' and path=='/sources':
            result=source_health(self.service,self._token)
            body='<p class="notice">Partial coverage. A recent heartbeat does not establish current page visibility or uninterrupted monitoring. Sources are sampled individually.</p>'
            body+=table(['Browser','Health','Last heartbeat','Captured','Last capture','Scheduled permission','Expires','Case'],[(e(row['browser']),e(row['health']),e(row['last_seen'] or 'Never recorded'),e(row['captured_observations']),e(row['last_capture'] or 'None'),e('Approved; activity unverified' if row['scheduled_permission'] else 'Not approved'),e(row['expires_at']),'<a href="/cases/'+e(row['case_id'])+'">'+e(row['case_id'])+'</a>') for row in result['sources']]) if result['sources'] else '<p>No browser sessions recorded.</p>'
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
            body+=table(['Case','State','Created'],[(f'<a href="/cases/{e(row["id"])}">{e(row["title"])}</a>',e(row['state']),e(row['created_at'])) for row in rows]) if rows else '<div class="empty-state"><span class="empty-mark" aria-hidden="true">◇</span><h2>Your investigation workspace</h2><p id="empty">No cases yet.</p><p>Cases bring evidence, questions and review history together in one place.</p></div>'
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
        action=re.fullmatch('/cases/('+ID+')/(assign|question|answer)',path)
        if method=='POST' and action:
            case_id,operation=action.groups()
            if operation=='assign' and set(fields)=={'csrf','request_id','assigned_to'}:
                self.service.assign_case(self._token,case_id,fields['request_id'],fields['assigned_to'] or None)
            elif operation=='question' and set(fields)=={'csrf','request_id','question'}:
                self.service.add_question(self._token,case_id,fields['request_id'],fields['question'])
            elif operation=='answer' and set(fields)=={'csrf','question_id','evidence_id','answer'}:
                self.service.answer_question(self._token,case_id,fields['question_id'],fields['evidence_id'],fields['answer'])
            else: raise AccessDenied('invalid_case_workflow_form')
            return '303 See Other',b'',[('Location','/cases/'+case_id)]
        memory=re.fullmatch('/cases/('+ID+')/memory(?:/(propose|review|forget|reset))?',path)
        if memory:
            case_id,operation=memory.groups()
            path='/cases/'+case_id+'/memory'
            case=self.service.get_case(self._token,case_id)
            history=self.service.list_memory(self._token,case_id)
            if method=='POST':
                if operation=='propose' and set(fields)=={'csrf','request_id','evidence_id','kind','scope','topic','supersedes'}:
                    self.service.propose_memory(self._token,case_id,fields['evidence_id'],fields['request_id'],fields['kind'],fields['scope'],fields['topic'],supersedes=fields['supersedes'] or None)
                elif operation in {'review','forget'}:
                    if fields.get('memory_id') not in {row['id'] for row in history['records']}: raise AccessDenied('memory_not_on_page')
                    if operation=='review' and set(fields)=={'csrf','memory_id','decision','expected_digest','acknowledged'}:
                        self.service.review_memory(self._token,fields['memory_id'],fields['decision'],fields['expected_digest'],fields['acknowledged']=='yes')
                    elif operation=='forget' and set(fields)=={'csrf','memory_id'}:
                        self.service.forget_memory(self._token,fields['memory_id'])
                    else: raise AccessDenied('invalid_memory_form')
                elif operation=='reset' and set(fields)=={'csrf','epoch'}:
                    self.service.reset_memory(self._token,int(fields['epoch']))
                else: raise AccessDenied('invalid_memory_form')
                return '303 See Other',b'',[('Location',path)]
            if method!='GET' or operation: raise AccessDenied('workbench_route_denied')
            writable=principal.role!='viewer' and case['case']['state']=='open'
            body='<p class="notice">Reviewed reference data grants no authority and does not establish source truth. Forget and reset remove retrieval; encrypted source evidence and audit history remain under case retention and legal holds.</p>'
            if writable:
                options=''.join('<option value="'+e(row['id'])+'">'+e(row['id'])+'</option>' for row in case['evidence'] if row['state']=='ready' and row['storage_state']=='active' and row['byte_length']<=4096)
                if options:
                    scopes='<option value="case">This case</option>'+('<option value="organization">Organization</option>' if principal.role in {'owner','admin'} else '')
                    body+=self._form(path+'/propose','Propose reference','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><label>Source evidence<select name="evidence_id">'+options+'</select></label><label>Kind<select name="kind"><option value="fact">Fact</option><option value="preference">Preference</option></select></label><label>Scope<select name="scope">'+scopes+'</select></label><label>Topic identifier<input name="topic" pattern="[a-z][a-z0-9_.-]{0,63}" required></label><label>Correct a prior record (optional UUID)<input name="supersedes"></label><p>Internal classification; expires 24 hours after proposal. Review is a separate step.</p>')
            for row in history['records']:
                labels={'proposed':'Needs review','eligible_pending_content_check':'Reviewed; source content will be verified before use',
                    'forgotten':'Excluded from retrieval','reset':'Excluded by organization reset','superseded':'Superseded by a proposed correction',
                    'expired':'Expired','rejected':'Rejected','authority_unavailable':'Excluded: contributor or reviewer access changed',
                    'source_unavailable':'Excluded: source evidence is unavailable'}
                body+='<section><h2>'+e(row['topic'])+'</h2><p data-memory-status="'+e(row['status'])+'">'+e(labels[row['status']])+'</p><p>'+e(row['id'])+' · '+e(row['scope'])+' · '+e(row['sensitivity'])+' · Expires '+e(row['expires_at'])+'</p><p><a href="/cases/'+e(row['case_id'])+'/evidence/'+e(row['evidence_id'])+'">Review source evidence</a></p>'
                if writable and row['status']=='proposed' and (row['scope']=='case' or principal.role in {'owner','admin'}):
                    body+=self._form(path+'/review','Record review','<input type="hidden" name="memory_id" value="'+e(row['id'])+'"><input type="hidden" name="expected_digest" value="'+e(row['source_digest'])+'"><label>Decision<select name="decision"><option value="approved">Approve as reference data</option><option value="rejected">Reject</option></select></label><label><input type="checkbox" name="acknowledged" value="yes" required>I reviewed this source and decision; approval is not proof of source truth.</label>')
                if principal.role!='viewer' and row['status'] not in {'forgotten','reset'} and (row['scope']=='case' or principal.role in {'owner','admin'}):
                    body+=self._form(path+'/forget','Forget from retrieval','<input type="hidden" name="memory_id" value="'+e(row['id'])+'">')
                body+='</section>'
            if not history['records']: body+='<p>No memory references recorded.</p>'
            if principal.role in {'owner','admin'}:
                body+=self._form(path+'/reset','Reset all organization memory retrieval','<input type="hidden" name="epoch" value="'+str(history['current_epoch'])+'"><p>This removes all current reference retrieval for the organization; source evidence is retained.</p>')
            body+='<p>Showing up to 128 latest applicable records.'+(' Older records are omitted.' if history['truncated'] else '')+'</p>'
            return '200 OK',self._page('Memory review',body,principal),[]
        coordinator=re.fullmatch('/cases/('+ID+')/coordinator(?:/(new|'+ID+')(?:/(next|run|stop))?)?',path)
        if coordinator:
            case_id,run_id,operation=coordinator.groups()
            path='/cases/'+case_id+'/coordinator'
            case=self.service.get_case(self._token,case_id)['case']
            if run_id=='new':
                if method!='POST' or operation or set(fields) not in ({'csrf','request_id'},{'csrf','request_id','input_evidence_id'}):
                    raise AccessDenied('invalid_coordinator_form')
                run=self.service.begin_coordinator(self._token,case_id,fields['request_id'],input_evidence_id=fields.get('input_evidence_id'))
                return '303 See Other',b'',[('Location',path+'/'+run['id'])]
            run=None
            if run_id:
                run=self.service.get_coordinator(self._token,run_id)
                if run['case_id']!=case_id: raise AccessDenied('coordinator_case_mismatch')
            if method=='POST':
                expected={'csrf','sequence'} if operation=='next' else {'csrf'}
                if not run or operation not in {'next','run','stop'} or set(fields)!=expected:
                    raise AccessDenied('invalid_coordinator_form')
                if operation in {'next','run'}:
                    if operation=='next' and fields['sequence'] not in {str(n) for n in range(1,run['max_steps']+1)}: raise AccessDenied('invalid_coordinator_form')
                    try:
                        if operation=='run': self.service.complete_coordinator(self._token,run_id)
                        else: self.service.advance_coordinator(self._token,run_id,expected_sequence=int(fields['sequence']))
                    except AccessDenied as error:
                        if str(error)!='coordinator_source_scope_changed': raise
                        body='<p>The evidence set changed. This plan cannot continue. Stop it and create a new plan for the current evidence.</p><p><a href="'+path+'/'+run_id+'">Review this plan</a> · <a href="'+path+'">Local plan history</a></p>'
                        return '409 Conflict',self._page('Evidence changed',body,principal),[]
                else: self.service.stop_coordinator(self._token,run_id)
                return '303 See Other',b'',[('Location',path+'/'+run_id)]
            if method!='GET' or operation: raise AccessDenied('workbench_route_denied')
            labels={'pending_local_steps':'Waiting for the next local step','local_plan_complete':'Local checks complete',
                'stopped':'Stopped','expired':'Expired','authority_lost':'Creator access changed'}
            body='<p class="notice">The two-step plan does not assess an attack. Twelve-specialist plans review rules over a selected typed facts artifact. Coverage is partial and confidence is unqualified. No AI model or external action is enabled.</p>'
            if run:
                body+='<p id="coordinator-status">'+e(labels[run['status']])+'</p><p id="coordinator-progress">'+e(run['completed_steps'])+' of '+e(run['max_steps'])+' local steps complete</p><p>Created '+e(run['created_at'])+' · Expires '+e(run['expires_at'])+'</p>'
                body+='<p>Stored results are historical. Current source availability and access have not been checked by viewing this page. They are checked again when a step runs. A changed evidence set requires a new plan.</p>'
                controllable=principal.role in {'owner','admin'} or (principal.role=='analyst' and str(principal.user_id)==run['requested_by'])
                if controllable and run['status']!='stopped':
                    body+=self._form(path+'/'+run_id+'/stop','Stop this plan')
                if controllable and case['state']=='open' and run['status']=='pending_local_steps':
                    body+=self._form(path+'/'+run_id+'/next','Run next local step','<input type="hidden" name="sequence" value="'+str(run['completed_steps']+1)+'">')
                    if run['input_evidence_id']:
                        body+=self._form(path+'/'+run_id+'/run','Run remaining specialist reviews','<p>Runs up to twelve local reviews. Access, Stop and evidence scope are checked between reviews.</p>')
                if run['input_evidence_id']:
                    body+='<p>Typed facts artifact <a href="/cases/'+case_id+'/evidence/'+e(run['input_evidence_id'])+'">'+e(run['input_evidence_id'])+'</a></p>'
                for step in run['steps']:
                    name={'evidence_inventory':'Evidence record inventory','telemetry_health':'Telemetry coverage check'}.get(step['operation'],step['operation'].replace('_',' ').title())
                    state='Complete' if step['completed_at'] else 'Interrupted or in progress; safe to retry' if step['claimed_at'] else 'Waiting'
                    body+='<section><h2>'+e(name)+'</h2><p>'+e(state)+'</p>'
                    if step['result'] is not None:
                        body+='<p>Completed '+e(step['completed_at'])+' · Receipt checksum '+e(step['result_digest'])+'</p>'
                        if step['operation']=='evidence_inventory':
                            body+='<p>Content integrity was not checked. Source authenticity and independent corroboration remain unverified.</p>'
                            body+=table(['Evidence record','Stored checksum'],[('<a href="/cases/'+case_id+'/evidence/'+e(item['evidence_id'])+'">'+e(item['evidence_id'])+'</a>',e(item['digest'])) for item in step['result']['sources']])
                        else:
                            body+='<p><a href="/cases/'+case_id+'/specialists/'+e(step['result']['specialist_id'])+'">'+('Review specialist assessment' if run['input_evidence_id'] else 'Review telemetry assessment')+'</a></p>'
                    body+='</section>'
                body+='<p>Evidence set checksum '+e(run['source_digest'])+'</p><p><a href="'+path+'">Local plan history</a></p>'
            else:
                if principal.role!='viewer' and case['state']=='open':
                    body+=self._form(path+'/new','Create local plan','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><p>Two steps maximum. Expires after fifteen minutes. Each step runs only when you request it.</p>')
                    evidence=self.service.get_case(self._token,case_id)['evidence']
                    options=''.join('<option value="'+e(row['id'])+'">'+e(row['id'])+'</option>' for row in evidence if row['state']=='ready' and row['storage_state']=='active')
                    if options:
                        body+=self._form(path+'/new','Create twelve-specialist plan','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><label>Typed facts artifact<select name="input_evidence_id" required>'+options+'</select></label><p>Select an approved specialist-facts-v1 artifact with source evidence in this case. Unsupported formats are rejected.</p>')
                history=self.service.list_coordinator_runs(self._token,case_id)
                body+=table(['Created','Status','Progress'],[('<a href="'+path+'/'+e(row['id'])+'">'+e(row['created_at'])+'</a>',e(labels[row['status']]),e(str(row['completed_steps'])+' of '+str(row['max_steps']))) for row in history['runs']]) if history['runs'] else '<p>No local plans recorded.</p>'
                body+='<p>Showing up to 32 most recent plans.'+(' Older plans are omitted.' if history['truncated'] else '')+'</p>'
            body+='<p><a href="/cases/'+case_id+'">Back to case</a></p>'
            return '200 OK',self._page('Local investigation plan',body,principal),[]
        attack=re.fullmatch('/cases/('+ID+')/attack-reviews(?:/('+ID+'))?',path)
        if attack:
            case_id,run_id=attack.groups()
            base='/cases/'+case_id+'/attack-reviews'
            if method=='POST':
                if run_id or set(fields)!={'csrf','request_id','input_evidence_id'}: raise AccessDenied('invalid_attack_review_form')
                run=self.service.run_attack_review(self._token,case_id,fields['request_id'],fields['input_evidence_id'])
                return '303 See Other',b'',[('Location',base+'/'+run['id'])]
            if method!='GET': raise AccessDenied('workbench_route_denied')
            body='<p class="notice">Historical review of supplied events. Patterns are hypotheses that need investigation. Source authenticity, current visibility and detection quality remain unverified. No model or response action is enabled here.</p>'
            if run_id:
                run=self.service.get_attack_review(self._token,case_id,run_id)
                result=run['result']
                body+='<p>Recorded '+e(run['created_at'])+' · Supplied event snapshot '+e(run['packet']['as_of'])+'</p>'
                body+='<p id="attack-review-priority">'+('Candidate patterns need urgent review.' if result['findings'] else 'No candidate pattern matched. This does not establish that activity is safe.')+'</p>'
                body+='<p>'+e(result['unique_event_count'])+' distinct supplied events; '+e(result['forwarded_duplicate_count'])+' repeated copies excluded.</p>'
                for finding in result['findings']:
                    body+='<section><h2>'+e(finding['family'].replace('_',' '))+'</h2><p>Suspected; needs review. Confidence is unqualified.</p>'
                    body+='<p>'+e(finding['observed_event_count'])+' events across '+e(finding['affected_asset_count'])+' supplied assets.</p>'
                    body+='<p>Reported interval: '+e(finding['first_event_time'])+' to '+e(finding['last_event_time'])+'. Source clocks are unverified.</p>'
                    body+='<p>Alternative explanation: '+e(finding['alternative'])+'</p>'
                    body+='<p>Evidence: '+', '.join('<a href="/cases/'+case_id+'/evidence/'+e(ref.removeprefix('evidence/'))+'">'+e(ref)+'</a>' for ref in finding['references'])+'</p></section>'
                body+='<h2>Missing source coverage</h2><p>'+e(', '.join(result['missing_sources']) or 'No gaps were declared; completeness is unverified.')+'</p>'
                body+='<h2>Limitations</h2>'+''.join('<p>'+e(item)+'</p>' for item in result['limitations'])
                body+='<p>Result checksum '+e(run['result_digest'])+' · Model cost $0</p><p><a href="'+base+'">Review history</a></p>'
            else:
                snapshot=self.service.get_case(self._token,case_id)
                if principal.role!='viewer' and snapshot['case']['state']=='open':
                    options=''.join('<option value="'+e(row['id'])+'">'+e(row['id'])+'</option>' for row in snapshot['evidence'] if row['state']=='ready' and row['storage_state']=='active')
                    if options:
                        body+=self._form(base,'Review event snapshot','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><label>Event snapshot<select name="input_evidence_id" required>'+options+'</select></label>')
                        body+='<p>Accepts an approved security-events-v1 document whose source evidence belongs to this case. Other formats are rejected.</p>'
                history=self.service.list_attack_reviews(self._token,case_id)
                body+=table(['Recorded review'],[(f'<a href="{base}/{e(row["id"])}">{e(row["created_at"])}</a>',) for row in history['runs']]) if history['runs'] else '<p>No attack-pattern reviews recorded.</p>'
                if history['truncated']: body+='<p>Showing the latest 32 reviews.</p>'
            body+='<p><a href="/cases/'+case_id+'">Back to case</a></p>'
            return '200 OK',self._page('Attack pattern review',body,principal),[]
        specialist=re.fullmatch('/cases/('+ID+')/specialists(?:/('+ID+'))?',path)
        if specialist:
            case_id,run_id=specialist.groups()
            path='/cases/'+case_id+'/specialists'
            if method=='POST':
                if run_id or set(fields) not in ({'csrf','request_id','role'},{'csrf','request_id','role','input_evidence_id'}):
                    raise AccessDenied('invalid_specialist_form')
                run=self.service.run_specialist(self._token,case_id,fields['request_id'],fields['role'],input_evidence_id=fields.get('input_evidence_id'))
                return '303 See Other',b'',[('Location',path+'/'+run['id'])]
            if method!='GET': raise AccessDenied('workbench_route_denied')
            body='<p class="notice">Local evidence review. Stored results are historical and partial; specialist quality is unqualified. A heartbeat does not prove page visibility. No model, search or external action is enabled here.</p>'
            if run_id:
                run=self.service.get_specialist_run(self._token,case_id,run_id)
                result=run['result']
                body+='<p id="specialist-attack-status">Attacker status: '+e(result['attack_status'])+'</p><p>Recorded '+e(run['created_at'])+' · No model was called.</p>'
                body+='<h2>Observations</h2>'+table(['Observation','Recorded reference'],[(e(row['statement']),e(', '.join(row['references']))) for row in result['observations']])
                body+='<h2>Hypotheses for review</h2>'+table(['Hypothesis','Recorded reference'],[(e(row['statement']),e(', '.join(row['references']))) for row in result['hypotheses']])
                body+='<h2>Contradictions</h2>'+table(['Discrepancy','Recorded reference'],[(e(row['statement']),e(', '.join(row['references']))) for row in result['contradictions']])
                body+='<h2>Alternative explanation</h2>'+''.join('<p>'+e(row['statement'])+'</p>' for row in result['alternatives'])
                body+='<h2>Uncertainty</h2>'+''.join('<p>'+e(item)+'</p>' for item in result['uncertainty'])
                if result.get('schema_version')==2:
                    body+='<p id="specialist-urgency">Review priority: '+e(result['urgency'].replace('_',' '))+' · Confidence: unqualified</p>'
                body+='<h2>Suggested review steps</h2>'+''.join('<p>'+e(item.replace('_',' '))+'</p>' for item in result['next_steps'])
                body+='<p>Result checksum '+e(run['result_digest'])+'</p><p><a href="'+path+'">Assessment history</a></p>'
            else:
                history=self.service.list_specialist_runs(self._token,case_id)
                snapshot=self.service.get_case(self._token,case_id)
                case=snapshot['case']
                if principal.role!='viewer' and case['state']=='open':
                    body+=self._form(path,'Check telemetry coverage','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><input type="hidden" name="role" value="telemetry_health">')
                    options=''.join('<option value="'+e(row['id'])+'">'+e(row['id'])+'</option>' for row in snapshot['evidence'] if row['state']=='ready' and row['storage_state']=='active')
                    if options:
                        from gabriel.identity.specialist_contracts import ROLES
                        body+=self._form(path,'Review typed evidence','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><label>Specialist<select name="role">'+''.join('<option value="'+role+'">'+e(role.replace('_',' '))+'</option>' for role in ROLES)+'</select></label><label>Typed facts artifact<select name="input_evidence_id" required>'+options+'</select></label>')
                        body+='<p>Select an approved specialist-facts-v1 artifact whose cited source evidence belongs to this case. Unsupported formats are rejected.</p>'
                body+=table(['Recorded','Specialty'],[(f'<a href="{path}/{e(row["id"])}">{e(row["created_at"])}</a>',e(row['role'].replace('_',' '))) for row in history['runs']]) if history['runs'] else '<p>No specialist assessments recorded.</p>'
                body+='<p>Showing up to 50 most recent assessments.'+(' Older records are omitted.' if history['truncated'] else '')+'</p>'
            return '200 OK',self._page('Specialist assessments',body,principal),[]
        environment=re.fullmatch('/cases/('+ID+')/environment(?:/(content))?',path)
        if environment:
            case_id,content=environment.groups()
            base='/cases/'+case_id+'/environment'
            if content:
                if method!='POST' or set(fields)!={'csrf'}: raise AccessDenied('explicit_environment_content_view_required')
            elif method!='GET': raise AccessDenied('workbench_route_denied')
            bundle=self.service.environment_profile(self._token,case_id,include_identifiers=bool(content))
            profile=bundle['profile'];snapshot=profile['snapshot']
            body='<p class="notice">Partial historical view from the latest reviewed event snapshot. Reported identifiers do not verify an asset, identity, owner or live connection.</p>'
            body+='<p id="environment-security">Security-control effectiveness: Not validated</p><p id="environment-compliance">Compliance coverage: Not assessed</p>'
            body+='<p>Control configuration, ownership and recovery dependencies remain unknown.</p>'
            if snapshot:
                body+='<p>Supplied snapshot time '+e(snapshot['supplied_as_of'])+' · Recorded review '+e(snapshot['review_created_at'])+'</p>'
                if profile['source_clock_ahead']: body+='<p class="notice">The supplied snapshot time is ahead of Gabriel’s server clock. Time-based interpretation needs review.</p>'
                body+='<p>'+e(snapshot['unique_event_count'])+' distinct supplied events; '+e(snapshot['forwarded_duplicate_count'])+' forwarded copies excluded.</p>'
                body+='<p><a href="/cases/'+case_id+'/attack-reviews/'+e(snapshot['review_id'])+'">Review source-linked assessment</a></p>'
                if profile['older_snapshots_omitted']: body+='<p>Older snapshots are omitted from this bounded view.</p>'
                if not content and principal.role!='viewer':
                    body+=self._form(base+'/content','View reported asset and identity keys','<p>Displays source-derived identifiers in this private workbench after checking their current evidence bytes.</p>')
                if content:
                    def links(refs):
                        return ', '.join('<a href="/cases/'+case_id+'/evidence/'+e(ref.removeprefix('evidence/'))+'">'+e(ref)+'</a>' for ref in refs)
                    body+='<h2>Reported asset keys</h2>'+table(['Identifier','Event references','Source evidence'],[(e(row['id']),e(row['event_count']),links(row['references'])) for row in profile['assets']])
                    body+='<h2>Reported identity keys</h2>'+table(['Identifier','Event references','Source evidence'],[(e(row['id']),e(row['event_count']),links(row['references'])) for row in profile['identities']])
                    body+='<h2>Reported event paths</h2>'+table(['From','To','Supplied event kinds','Source evidence'],[(e(row['source']),e(row['target']),e(', '.join(row['event_kinds'])),links(row['references'])) for row in profile['relationships']])
                    body+='<p>Source bytes and recorded custody checked on this read. Source truth and current environment coverage remain unverified.</p>'
                else: body+='<p>Source contents and current availability have not been checked by this metadata view.</p>'
            else: body+='<p id="environment-empty">No supported event snapshot has been reviewed. Environment coverage remains unknown.</p>'
            body+='<h2>Visibility gaps and unknowns</h2>'+(''.join('<p>'+('Reported missing: ' if snapshot else 'Not established: ')+e(item.title())+'</p>' for item in profile['missing_sources']) or '<p>No gaps were declared by the source. Completeness remains unverified.</p>')
            body+='<p>Profile checksum '+e(bundle['digest'])+'</p><p><a href="/cases/'+case_id+'">Back to case</a></p>'
            return '200 OK',self._page('Environment and control profile',body,principal),[]
        projection=re.fullmatch('/cases/('+ID+')/(relationships|graph)',path)
        if projection:
            if method!='GET': raise AccessDenied('workbench_route_denied')
            case_id,view=projection.groups()
            result=self.service.case_graph(self._token,case_id)
            if view=='graph':
                return '200 OK',json.dumps(result,ensure_ascii=False,allow_nan=False).encode(),[('Content-Type','application/json'),('Content-Disposition','attachment; filename="gabriel-case-graph-'+case_id+'.json"')]
            graph=result['projection']
            body='<p class="notice">Partial coverage. These are stored provenance links. Attack assessment has not been performed; links do not prove causality.</p><p><a href="/cases/'+case_id+'/graph">Download provenance graph</a></p>'
            body+='<h2>Records</h2>'+table(['Record type','Identifier','Metadata'],[(e(row['kind'].replace('_',' ')),e(row['record_id']),e(json.dumps(row['properties'],ensure_ascii=False))) for row in graph['nodes']])
            body+='<h2>Stored links</h2>'+table(['Relationship','From','To'],[(e(row['kind'].replace('_',' ')),e(row['source']),e(row['target'])) for row in graph['edges']])
            body+='<p>Projection checksum '+e(result['digest'])+'</p>'
            return '200 OK',self._page('Case provenance',body,principal),[]
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
        body='<p class="case-state">State: '+e(snapshot['case']['state'])+' · Coverage: partial · Assessment: not performed</p><p class="case-links"><a href="'+path+'/report">Download metadata report</a> · <a href="'+path+'/relationships">Explore provenance</a> · <a href="'+path+'/coordinator">Local investigation plan</a> · <a href="'+path+'/specialists">Specialist assessments</a> · <a href="'+path+'/memory">Memory review</a></p>'
        body+='<p class="case-links"><a href="'+path+'/attack-reviews">Attack pattern review</a> · <a href="'+path+'/environment">Environment and control profile</a></p>'
        workflow=self.service.case_workflow(self._token,case_id)
        current=workflow['assignment']
        body+='<h2>Assignment</h2><p id="case-assignment">'+(e(current['assigned_to'])+(' · Active member' if current.get('assignee_active') else ' · Inactive or unassigned') if current and current['assigned_to'] else 'Unassigned')+'</p>'
        writable=principal.role!='viewer' and snapshot['case']['state']=='open'
        if writable and principal.role in {'owner','admin'}:
            members=self.service.list_members(self._token)
            options='<option value="">Unassigned</option>'+''.join('<option value="'+e(row['id'])+'">'+e(row['username'])+'</option>' for row in members if row['active'] and row['role']!='viewer')
            body+=self._form(path+'/assign','Update assignment','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><label>Assign to<select name="assigned_to">'+options+'</select></label>')
        elif writable and (not current or current['assigned_to'] in {None,str(principal.user_id)}):
            body+=self._form(path+'/assign','Assign to me','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><input type="hidden" name="assigned_to" value="'+e(principal.user_id)+'">')
        body+='<h2>Investigation questions</h2><p>Answers are evidence-linked analyst comments. They do not validate source truth or enter learned memory. The metadata report covers evidence/custody; workflow comments are available here and through the workflow CLI.</p>'
        if workflow['questions_restricted']: body+='<p>Analyst comments require an analyst, admin or owner role.</p>'
        if writable:
            body+=self._form(path+'/question','Add question','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><label>Question<input name="question" maxlength="512" required></label>')
        for question in workflow['questions']:
            body+='<section><h3>'+e(question['question'])+'</h3><p>'+e(question['state'])+'</p>'
            if question['answer'] is not None:
                body+='<p>'+e(question['answer'])+'</p><p>Evidence <a href="'+path+'/evidence/'+e(question['evidence_id'])+'">'+e(question['evidence_id'])+'</a> · Source unverified</p>'
            elif writable:
                options=''.join('<option value="'+e(row['id'])+'">'+e(row['id'])+'</option>' for row in snapshot['evidence'] if row['state']=='ready' and row['storage_state']=='active')
                if options:
                    body+=self._form(path+'/answer','Record analyst answer','<input type="hidden" name="question_id" value="'+e(question['id'])+'"><label>Supporting evidence<select name="evidence_id" required>'+options+'</select></label><label>Analyst answer<input name="answer" maxlength="1024" required></label>')
            body+='</section>'
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
    dsn=read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE'])
    provider_vault=None
    if os.environ.get('GABRIEL_PROVIDER_KEYRING_FILE'):
        from gabriel.identity.vault import ProviderKeyRing,ProviderVault
        provider_vault=ProviderVault(dsn,ProviderKeyRing.from_file(os.environ['GABRIEL_PROVIDER_KEYRING_FILE']))
    app=Workbench(CaseService(dsn,store),token,config,provider_vault=provider_vault)
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
