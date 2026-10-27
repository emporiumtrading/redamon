"""Actual generated-data workbench screens plus explicitly labeled design previews."""
import base64
from datetime import datetime,timedelta,timezone
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
from socketserver import ThreadingMixIn
import ssl
import subprocess
import tempfile
from threading import Thread
import time
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIServer,WSGIRequestHandler

import websocket
from tls_lab import certificates
from gabriel.identity.cases import CaseService
from gabriel.identity.checkpoints import read_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.investigation_tools import inspect
from gabriel.identity.service import migrate,provision_organization
from gabriel.identity.vault import ProviderKeyRing,ProviderVault
from gabriel.identity.workbench import Workbench,prepare_workbench


def wait(check):
    until=time.monotonic()+20
    while time.monotonic()<until:
        try:
            value=check()
            if value:return value
        except (OSError,ValueError,AssertionError):pass
        time.sleep(.05)
    raise AssertionError('gallery_readiness_timeout')


class CDP:
    def __init__(self,port):
        def address():
            conn=http.client.HTTPConnection('127.0.0.1',port,timeout=1)
            try:
                conn.request('GET','/json/version')
                return json.loads(conn.getresponse().read())['webSocketDebuggerUrl']
            finally:conn.close()
        self.ws=websocket.create_connection(wait(address),suppress_origin=True,timeout=15);self.counter=0
    def send(self,method,params=None,session=None):
        self.counter+=1;message=dict(id=self.counter,method=method,params=params or {})
        if session:message['sessionId']=session
        self.ws.send(json.dumps(message))
        while True:
            reply=json.loads(self.ws.recv())
            if reply.get('id')==self.counter:
                if reply.get('error'):raise AssertionError('gallery_cdp_error')
                return reply.get('result',{})
    def evaluate(self,session,expression):
        reply=self.send('Runtime.evaluate',dict(expression=expression,returnByValue=True,awaitPromise=True,userGesture=True),session)
        if reply.get('exceptionDetails'):raise AssertionError('gallery_dom_error')
        return reply.get('result',{}).get('value')


class Server(ThreadingMixIn,WSGIServer):daemon_threads=True
class Quiet(WSGIRequestHandler):
    def log_message(self,*args):pass


def main():
    output=Path('/output');output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='gabriel-gallery-') as private:
        root=Path(private);store=root/'evidence';store.mkdir(mode=0o700)
        tls=certificates(root);app_dsn=read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE'])
        owner_dsn=read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']);migrate(owner_dsn)
        password=secrets.token_urlsafe(32)
        org,user=provision_organization(owner_dsn,'Generated gallery organization','demo-owner',password)
        service=CaseService(app_dsn,LocalEvidenceStore(store,EvidenceKeys('gallery-evidence',{'gallery-evidence':secrets.token_bytes(32)})))
        token=service.login(org,'demo-owner',password).token
        analyst=service.create_member(token,'demo-analyst',secrets.token_urlsafe(32),'analyst')
        case=service.create_case(token,'Generated lab: suspicious sign-ins')
        case_id=str(case['id']);now=datetime.now(timezone.utc)
        logs='\n'.join(json.dumps(dict(timestamp=(now-timedelta(seconds=60-i)).isoformat(),entity='generated-identity',outcome='failure' if i<5 else 'success')) for i in range(6))
        log_source=service.acquire(token,case_id,uuid4(),logs,'Generated normalized sign-in log',approved=True)
        file_source=service.acquire(token,case_id,uuid4(),'Generated file text: powershell -EncodedCommand example-only','Generated file sample',approved=True)
        inventory=service.acquire(token,case_id,uuid4(),'Generated inventory: critical reachable exposure, mitigation not reported.','Generated exposure inventory',approved=True)
        facts=[]
        for kind,data,source in [('alert',dict(severity='critical',state='open'),log_source),('activity',dict(category='network',outcome='failure',count=5),log_source),('artifact',dict(integrity='match',custody='complete'),file_source),('exposure',dict(severity='critical',reachable='yes',mitigated='no'),inventory)]:
            facts.append(dict(id=str(uuid4()),type=kind,evidence_id=str(source['id']),evidence_digest=source['digest'],entity_id=str(uuid4()),event_time=(now-timedelta(seconds=60)).isoformat(),data=data))
        doc=dict(version='specialist-facts-v1',case_id=case_id,as_of=now.isoformat(),facts=facts)
        holder=service.acquire(token,case_id,uuid4(),json.dumps(doc),'Generated typed investigation facts',approved=True)
        report=inspect(service,token,case_id,holder['id'],'incident_scoping','inspect_logs',uuid4())
        assert report['result']['result']['artifacts'][0]['failure_burst_then_success_groups']==1
        service.assign_case(token,case_id,uuid4(),analyst)
        question=service.add_question(token,case_id,uuid4(),'What should we verify before considering containment?')
        service.answer_question(token,case_id,question,report['report_evidence_id'],'Generated logs show five failures followed by a success. Verify the source identity, duplicate records and authorized activity before deciding on containment. This is an analyst review note, not an AI verdict.')
        service.add_question(token,case_id,uuid4(),'Is the reported reachable exposure covered by an approved mitigation?')
        memory=service.propose_memory(token,case_id,log_source['id'],uuid4(),'fact','case','sign_in_review')
        configuration=root/'workbench'
        listener=make_server('127.0.0.1',0,lambda e,s:[],server_class=Server,handler_class=Quiet)
        endpoint='https://localhost:'+str(listener.server_port)
        prepare_workbench(service,token,endpoint,configuration)
        vault=ProviderVault(app_dsn,ProviderKeyRing('gallery-provider',{'gallery-provider':secrets.token_bytes(32)}))
        app=Workbench(service,token,read_document(configuration/'workbench.json',private=True),provider_vault=vault)
        def secured(environ,start_response):
            environ['wsgi.url_scheme']='https'
            return app(environ,start_response)
        listener.set_app(secured)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(tls['server.pem']),str(tls['server.key']))
        listener.socket=context.wrap_socket(listener.socket,server_side=True)
        Thread(target=listener.serve_forever,daemon=True).start()
        home=Path(os.environ['HOME']);nss=home/'.pki'/'nssdb';nss.mkdir(parents=True,mode=0o700,exist_ok=True)
        subprocess.run(['certutil','-N','-d','sql:'+str(nss),'--empty-password'],check=True,capture_output=True)
        subprocess.run(['certutil','-A','-d','sql:'+str(nss),'-n','gabriel-gallery','-t','C,,','-i',str(tls['ca.pem'])],check=True,capture_output=True)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));debug_port=probe.getsockname()[1]
        chrome=subprocess.Popen(['/usr/bin/chromium','--headless=new','--no-sandbox','--no-first-run','--disable-background-networking','--disable-sync','--disable-dev-shm-usage','--proxy-server=http://127.0.0.1:9','--user-data-dir='+str(root/'chrome'),'--remote-debugging-port='+str(debug_port),'about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cdp=None;images=[]
        try:
            cdp=CDP(debug_port)
            tab=cdp.send('Target.createTarget',{'url':endpoint+'/claim'})['targetId']
            session=cdp.send('Target.attachToTarget',{'targetId':tab,'flatten':True})['sessionId']
            cdp.send('Page.enable',session=session)
            cdp.send('Emulation.setDeviceMetricsOverride',dict(width=1440,height=1000,deviceScaleFactor=1,mobile=False),session)
            wait(lambda:cdp.evaluate(session,"Boolean(document.querySelector('input[name=ticket]'))"))
            ticket=read_document(configuration/'claim.json',private=True)['ticket']
            cdp.evaluate(session,"document.querySelector('input[name=ticket]').value="+json.dumps(ticket)+";document.querySelector('form').requestSubmit();true")
            wait(lambda:cdp.evaluate(session,"document.title==='Investigations · Gabriel'"))
            private_values=[password,token,ticket,app_dsn,owner_dsn]
            def capture(name,title,kind='actual_generated_data',selector=None,width=1440):
                cdp.send('Emulation.setDeviceMetricsOverride',dict(width=width,height=1000,deviceScaleFactor=1,mobile=False),session)
                if selector:cdp.evaluate(session,"document.querySelector("+json.dumps(selector)+").scrollIntoView({block:'center'});true")
                visible=cdp.evaluate(session,'document.body.innerText')
                assert all(secret not in visible for secret in private_values)
                assert cdp.evaluate(session,'document.documentElement.scrollWidth<=innerWidth')
                time.sleep(.15)
                raw=base64.b64decode(cdp.send('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False),session)['data'])
                (output/(name+'.png')).write_bytes(raw)
                images.append(dict(file=name+'.png',title=title,kind=kind,sha256=sha256(raw).hexdigest(),width=width,height=1000))
            def navigate(path,title):
                cdp.send('Page.navigate',{'url':endpoint+path},session)
                wait(lambda:cdp.evaluate(session,'document.title==='+json.dumps(title+' · Gabriel')))
            base='/cases/'+case_id
            navigate(base+'/agents','Specialist AI agents')
            cdp.evaluate(session,"document.querySelector('[name=role_tool]').value='incident_scoping/inspect_logs';document.querySelector('form[action$=\"/tools\"] [name=input_evidence_id]').value="+json.dumps(holder['id'])+";true")
            capture('select-investigation-tool','Choose a specialist and run an allowed local tool',selector='form[action$="/tools"]')
            navigate(base+'/evidence/'+str(report['report_evidence_id']),'Evidence and custody')
            cdp.evaluate(session,"document.querySelector('form[action$=\"/content\"]').requestSubmit();true")
            wait(lambda:cdp.evaluate(session,"Boolean(document.querySelector('#evidence-content'))"))
            capture('verified-tool-findings','Review the actual encrypted log-analysis result')
            navigate(base,'Generated lab: suspicious sign-ins')
            capture('analyst-next-actions','Assign ownership, record findings and ask the next question',selector='form[action$="/question"]')
            capture('mobile-analyst-review','Review investigation questions on mobile',selector='form[action$="/question"]',width=390)
            navigate(base+'/memory','Memory review')
            capture('review-before-learning','Review a proposed reference before reuse',selector='form[action$="/review"]')
            concept=Path('/gallery/action-preview.html')
            cdp.send('Page.navigate',{'url':concept.as_uri()},session)
            wait(lambda:cdp.evaluate(session,"document.title==='Gabriel action workflow preview'"))
            for state,title in [('preflight','Preflight before autonomous investigation'),('specialists','Supervisor assignments and analyst progress'),('response','Proposed response and analyst approval')]:
                cdp.evaluate(session,'window.showView('+json.dumps(state)+');true')
                capture('preview-'+state,title,kind='illustrative_design_not_implemented')
            manifest=dict(source_sha=os.environ['GABRIEL_GALLERY_SOURCE'],images=images,synthetic_data=True,
                model_calls=0,production_admission=False,hermes_integrated=False,hermes_requirement='required_integration_in_progress',
                environment='Isolated Chromium screenshot lab, sandbox disabled inside non-root private Docker container',
                actual_screens='Rendered current workbench against ephemeral PostgreSQL and actual local parser service',
                design_previews='Clearly labeled static workflow concepts; external-response controls are disabled')
            (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
            print('PASS: five actual generated-data UI screens and three labeled workflow previews; no credentials or model calls')
        finally:
            if cdp:cdp.ws.close()
            chrome.terminate();chrome.wait(timeout=10);listener.shutdown();listener.server_close()


if __name__=='__main__':main()
