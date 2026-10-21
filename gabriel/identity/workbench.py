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


def dollars(value):
    return str(value//1000000)+'.'+str(value%1000000).zfill(6)


def budget_amount(value):
    if not isinstance(value,str) or re.fullmatch(r'(?:0|[1-9][0-9]?)(?:\.[0-9]{1,6})?',value) is None:
        raise AccessDenied('invalid_spending_amount')
    whole,_,fraction=value.partition('.')
    return int(whole)*1000000+int(fraction.ljust(6,'0'))


def table(columns,rows):
    return '<table><thead><tr>'+''.join('<th scope="col">'+e(c)+'</th>' for c in columns)+'</tr></thead><tbody>'+''.join(
        '<tr>'+''.join('<td>'+value+'</td>' for value in row)+'</tr>' for row in rows)+'</tbody></table>'


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
        navigation=''
        if principal:
            navigation='<p id="team-scope">Organization '+e(principal.organization_id)+' · Role '+e(principal.role)+'</p><nav><a href="/cases">Cases</a><a href="/sources">Browser health</a><a href="/spending">AI spending</a>'
            if principal.role!='viewer': navigation+='<a href="/cases/new">New case</a>'
            if principal.role!='viewer': navigation+='<a href="/audit">Audit</a>'
            if principal.role in {'owner','admin'}: navigation+='<a href="/providers">Your AI keys</a>'
            navigation+=self._form('/disconnect','Disconnect workbench')+'</nav>'
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+e(title)+' · Gabriel</title><style>'+STYLE+'</style></head><body><header><a href="/cases">Gabriel — The Defender</a>'+navigation+'</header><main id="main"><h1>'+e(title)+'</h1>'+body+'</main></body></html>').encode()

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
        coordinator=re.fullmatch('/cases/('+ID+')/coordinator(?:/(new|'+ID+')(?:/(next|stop))?)?',path)
        if coordinator:
            case_id,run_id,operation=coordinator.groups()
            path='/cases/'+case_id+'/coordinator'
            case=self.service.get_case(self._token,case_id)['case']
            if run_id=='new':
                if method!='POST' or operation or set(fields)!={'csrf','request_id'}:
                    raise AccessDenied('invalid_coordinator_form')
                run=self.service.begin_coordinator(self._token,case_id,fields['request_id'])
                return '303 See Other',b'',[('Location',path+'/'+run['id'])]
            run=None
            if run_id:
                run=self.service.get_coordinator(self._token,run_id)
                if run['case_id']!=case_id: raise AccessDenied('coordinator_case_mismatch')
            if method=='POST':
                expected={'csrf','sequence'} if operation=='next' else {'csrf'}
                if not run or operation not in {'next','stop'} or set(fields)!=expected:
                    raise AccessDenied('invalid_coordinator_form')
                if operation=='next':
                    if fields['sequence'] not in {'1','2'}: raise AccessDenied('invalid_coordinator_form')
                    try:
                        self.service.advance_coordinator(self._token,run_id,expected_sequence=int(fields['sequence']))
                    except AccessDenied as error:
                        if str(error)!='coordinator_source_scope_changed': raise
                        body='<p>The evidence set changed. This plan cannot continue. Stop it and create a new plan for the current evidence.</p><p><a href="'+path+'/'+run_id+'">Review this plan</a> · <a href="'+path+'">Local plan history</a></p>'
                        return '409 Conflict',self._page('Evidence changed',body,principal),[]
                else: self.service.stop_coordinator(self._token,run_id)
                return '303 See Other',b'',[('Location',path+'/'+run_id)]
            if method!='GET' or operation: raise AccessDenied('workbench_route_denied')
            labels={'pending_local_steps':'Waiting for the next local step','local_plan_complete':'Local checks complete',
                'stopped':'Stopped','expired':'Expired','authority_lost':'Creator access changed'}
            body='<p class="notice">This plan only lists evidence records and checks telemetry coverage. It does not assess an attack or call an AI model. No external action is taken.</p>'
            if run:
                body+='<p id="coordinator-status">'+e(labels[run['status']])+'</p><p id="coordinator-progress">'+e(run['completed_steps'])+' of '+e(run['max_steps'])+' local steps complete</p><p>Created '+e(run['created_at'])+' · Expires '+e(run['expires_at'])+'</p>'
                body+='<p>Stored results are historical. Current source availability and access have not been checked by viewing this page. They are checked again when a step runs. A changed evidence set requires a new plan.</p>'
                controllable=principal.role in {'owner','admin'} or (principal.role=='analyst' and str(principal.user_id)==run['requested_by'])
                if controllable and run['status']!='stopped':
                    body+=self._form(path+'/'+run_id+'/stop','Stop this plan')
                if controllable and case['state']=='open' and run['status']=='pending_local_steps':
                    body+=self._form(path+'/'+run_id+'/next','Run next local step','<input type="hidden" name="sequence" value="'+str(run['completed_steps']+1)+'">')
                for step in run['steps']:
                    name={'evidence_inventory':'Evidence record inventory','telemetry_health':'Telemetry coverage check'}[step['operation']]
                    state='Complete' if step['completed_at'] else 'Interrupted or in progress; safe to retry' if step['claimed_at'] else 'Waiting'
                    body+='<section><h2>'+e(name)+'</h2><p>'+e(state)+'</p>'
                    if step['result'] is not None:
                        body+='<p>Completed '+e(step['completed_at'])+' · Receipt checksum '+e(step['result_digest'])+'</p>'
                        if step['operation']=='evidence_inventory':
                            body+='<p>Content integrity was not checked. Source authenticity and independent corroboration remain unverified.</p>'
                            body+=table(['Evidence record','Stored checksum'],[('<a href="/cases/'+case_id+'/evidence/'+e(item['evidence_id'])+'">'+e(item['evidence_id'])+'</a>',e(item['digest'])) for item in step['result']['sources']])
                        else:
                            body+='<p><a href="/cases/'+case_id+'/specialists/'+e(step['result']['specialist_id'])+'">Review telemetry assessment</a></p>'
                    body+='</section>'
                body+='<p>Evidence set checksum '+e(run['source_digest'])+'</p><p><a href="'+path+'">Local plan history</a></p>'
            else:
                if principal.role!='viewer' and case['state']=='open':
                    body+=self._form(path+'/new','Create local plan','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><p>Two steps maximum. Expires after fifteen minutes. Each step runs only when you request it.</p>')
                history=self.service.list_coordinator_runs(self._token,case_id)
                body+=table(['Created','Status','Progress'],[('<a href="'+path+'/'+e(row['id'])+'">'+e(row['created_at'])+'</a>',e(labels[row['status']]),e(str(row['completed_steps'])+' of '+str(row['max_steps']))) for row in history['runs']]) if history['runs'] else '<p>No local plans recorded.</p>'
                body+='<p>Showing up to 32 most recent plans.'+(' Older plans are omitted.' if history['truncated'] else '')+'</p>'
            body+='<p><a href="/cases/'+case_id+'">Back to case</a></p>'
            return '200 OK',self._page('Local investigation plan',body,principal),[]
        specialist=re.fullmatch('/cases/('+ID+')/specialists(?:/('+ID+'))?',path)
        if specialist:
            case_id,run_id=specialist.groups()
            path='/cases/'+case_id+'/specialists'
            if method=='POST':
                if run_id or set(fields)!={'csrf','request_id','role'}: raise AccessDenied('invalid_specialist_form')
                run=self.service.run_specialist(self._token,case_id,fields['request_id'],fields['role'])
                return '303 See Other',b'',[('Location',path+'/'+run['id'])]
            if method!='GET': raise AccessDenied('workbench_route_denied')
            body='<p class="notice">Telemetry coverage only. Attacker activity is not assessed. A heartbeat does not prove page visibility. Stored results are historical samples.</p>'
            if run_id:
                run=self.service.get_specialist_run(self._token,case_id,run_id)
                result=run['result']
                body+='<p id="specialist-attack-status">Attacker status: '+e(result['attack_status'])+'</p><p>Recorded '+e(run['created_at'])+' · No model was called.</p>'
                body+='<h2>Observations</h2>'+table(['Observation','Recorded reference'],[(e(row['statement']),e(', '.join(row['references']))) for row in result['observations']])
                body+='<h2>Alternative explanation</h2>'+''.join('<p>'+e(row['statement'])+'</p>' for row in result['alternatives'])
                body+='<h2>Uncertainty</h2>'+''.join('<p>'+e(item)+'</p>' for item in result['uncertainty'])
                body+='<p>Result checksum '+e(run['result_digest'])+'</p><p><a href="'+path+'">Assessment history</a></p>'
            else:
                history=self.service.list_specialist_runs(self._token,case_id)
                case=self.service.get_case(self._token,case_id)['case']
                if principal.role!='viewer' and case['state']=='open':
                    body+=self._form(path,'Check telemetry coverage','<input type="hidden" name="request_id" value="'+str(uuid4())+'"><input type="hidden" name="role" value="telemetry_health">')
                body+=table(['Recorded','Specialty'],[(f'<a href="{path}/{e(row["id"])}">{e(row["created_at"])}</a>',e(row['role'].replace('_',' '))) for row in history['runs']]) if history['runs'] else '<p>No telemetry assessments recorded.</p>'
                body+='<p>Showing up to 50 most recent assessments.'+(' Older records are omitted.' if history['truncated'] else '')+'</p>'
            return '200 OK',self._page('Telemetry assessments',body,principal),[]
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
        body='<p>State: '+e(snapshot['case']['state'])+' · Coverage: partial · Assessment: not performed</p><p><a href="'+path+'/report">Download metadata report</a> · <a href="'+path+'/relationships">Explore provenance</a> · <a href="'+path+'/coordinator">Local investigation plan</a> · <a href="'+path+'/specialists">Telemetry assessments</a> · <a href="'+path+'/memory">Memory review</a></p>'
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
