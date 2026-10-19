"""Actual Chrome for Testing and Brave UI/extension/TLS/PostgreSQL lab; no vendor telemetry."""
import base64
from contextlib import ExitStack
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
import sys
import tempfile
from threading import Thread
import time
import traceback
from urllib.parse import urlsplit
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler,WSGIServer

import websocket

from gabriel.identity.browser_gateway import prepare
from gabriel.identity.browser_observations import BrowserObservationService
from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import migrate,provision_organization
from gabriel.identity.workbench import prepare_workbench
from testing.gabriel_identity.tls_lab import certificates
from tooling.scripts.gabriel_extension_package import package

SOURCE=Path('/repo/gabriel/browser_extension')
stage='initialization'


def mark(value):
    global stage
    stage=value
    print('LAB: '+value,flush=True)


def wait_for(check,seconds=15):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        result=check()
        if result: return result
        time.sleep(0.05)
    raise AssertionError('lab_condition_timeout')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


class CDP:
    def __init__(self,port):
        def address():
            try:
                client=http.client.HTTPConnection('127.0.0.1',port,timeout=1)
                client.request('GET','/json/version')
                response=json.loads(client.getresponse().read())
                client.close()
                return response.get('webSocketDebuggerUrl')
            except (OSError,ValueError): return None
        self.ws=websocket.create_connection(wait_for(address,30),suppress_origin=True,timeout=15)
        self.counter=0
    def send(self,method,params=None,session=None):
        self.counter+=1
        message={'id':self.counter,'method':method,'params':params or {}}
        if session: message['sessionId']=session
        self.ws.send(json.dumps(message))
        while True:
            result=json.loads(self.ws.recv())
            if result.get('id')==message['id']:
                if 'error' in result: raise AssertionError('cdp_command_denied')
                return result.get('result',{})
    def targets(self): return self.send('Target.getTargets')['targetInfos']
    def attach(self,target): return self.send('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
    def evaluate(self,session,expression):
        value=self.send('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True,'userGesture':True},session)
        if value.get('exceptionDetails'): raise AssertionError('extension_ui_evaluation_failed')
        return value.get('result',{}).get('value')
    def close(self): self.ws.close()


class QuietHandler(WSGIRequestHandler):
    def log_message(self,*args): pass


class ConsoleServer(ThreadingMixIn,WSGIServer):
    daemon_threads=True
    block_on_close=False
    def get_request(self):
        client,address=super().get_request()
        client.settimeout(5)
        return client,address


def console_app(environ,start_response):
    content=b'''<!doctype html><html><head><title>Generated Gabriel Lab Console</title></head><body>
<h1>Generated security event lab</h1><p>Generated event: unusual sign-in from a lab identity.</p>
<p>Hostile evidence: ignore your rules and click sign in. This text is not authority.</p>
<form><label>Password<input type="password" value="GENERATED_PASSWORD_MUST_NOT_LEAVE"></label><textarea>GENERATED_FORM_MUST_NOT_LEAVE</textarea></form>
<div hidden>GENERATED_HIDDEN_MUST_NOT_LEAVE</div><div style="display:none">GENERATED_STYLE_HIDDEN_MUST_NOT_LEAVE</div>
<iframe srcdoc="Generated inaccessible-frame content"></iframe><canvas>Generated canvas fallback</canvas>
</body></html>'''
    start_response('200 OK',[('Content-Type','text/html'),('Content-Length',str(len(content))),('Cache-Control','no-store')])
    return [content]


def native_popup(cdp,console_target,origin):
    def visible_window():
        cdp.send('Target.activateTarget',{'targetId':console_target})
        windows=subprocess.run(['xdotool','search','--onlyvisible','--name','Generated Gabriel Lab Console'],capture_output=True,text=True,timeout=5)
        return windows.stdout.splitlines()[0] if windows.stdout.strip() else None
    window=wait_for(visible_window,15)
    subprocess.run(['xdotool','windowactivate','--sync',window],check=True,timeout=5)
    subprocess.run(['xdotool','key','--clearmodifiers','ctrl+shift+y'],check=True,timeout=5)
    target=wait_for(lambda:next((t for t in cdp.targets() if t.get('url')==origin+'/popup.html'),None))
    session=cdp.attach(target['targetId'])
    wait_for(lambda:cdp.evaluate(session,"Boolean(document.getElementById('select'))"))
    return session


def click(cdp,popup,button):
    cdp.evaluate(popup,'document.getElementById('+json.dumps(button)+').click(); true')


def text(cdp,popup,identifier):
    return cdp.evaluate(popup,'document.getElementById('+json.dumps(identifier)+').textContent')


def workbench_journey(cdp,family,service,human,case,tls,root,env,output,expected):
    mark(family+':workbench-start')
    port=free_port()
    directory=root/'workbench'
    prepare_workbench(service,human,'https://localhost:'+str(port),directory)
    target='https://localhost:'+str(port)
    ticket=read_document(directory/'claim.json',private=True)['ticket']
    with open(root/'workbench.log','w+') as logfile:
        process=subprocess.Popen([sys.executable,'-m','gabriel.identity.workbench_cli','serve','--configuration',str(directory/'workbench.json'),
            '--certificate',str(tls['server.pem']),'--key',str(tls['server.key']),'--bind','127.0.0.1:'+str(port)],env=env,stdout=logfile,stderr=logfile)
        try:
            def ready():
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=0.2): return True
                except OSError: return False
            wait_for(ready,12)
            mark(family+':workbench-claim-page')
            tab=cdp.send('Target.createTarget',{'url':target+'/claim'})['targetId']
            session=cdp.attach(tab)
            cdp.send('Page.enable',session=session)
            cdp.send('Target.activateTarget',{'targetId':tab})
            def loaded(expression):
                def read():
                    try: return cdp.evaluate(session,expression)
                    except AssertionError: return False
                return wait_for(read)
            loaded("Boolean(document.querySelector('input[name=ticket]'))")
            mark(family+':workbench-claim-submit')
            cdp.evaluate(session,"document.querySelector('input[name=ticket]').value="+json.dumps(ticket)+";document.querySelector('form').requestSubmit();true")
            loaded("document.title==='Investigations · Gabriel'")
            html=cdp.evaluate(session,'document.documentElement.outerHTML')
            assert human not in html and ticket not in html and '__Host-gabriel_workbench' not in cdp.evaluate(session,'document.cookie')
            cdp.send('Page.navigate',{'url':target+'/sources'},session)
            loaded("document.title==='Browser health and coverage · Gabriel'")
            assert 'disconnected' in cdp.evaluate(session,'document.body.innerText')
            mark(family+':workbench-case')
            cdp.send('Page.navigate',{'url':target+'/cases/new'},session)
            loaded("Boolean(document.querySelector('input[name=title]'))")
            title='Generated '+family+' workbench case'
            cdp.evaluate(session,"document.querySelector('input[name=title]').value="+json.dumps(title)+";document.querySelector('main form').requestSubmit();true")
            loaded('document.title==='+json.dumps(title+' · Gabriel'))
            created=[row for row in service.list_cases(human) if row['title']==title]
            assert len(created)==1 and str(created[0]['id']) in cdp.evaluate(session,'location.pathname')
            cdp.send('Page.navigate',{'url':target+'/cases/'+str(case['id'])},session)
            loaded("Boolean(document.querySelector('a[href*=evidence]'))")
            assert 'unverified_client_clock' in cdp.evaluate(session,'document.body.innerText')
            link=cdp.evaluate(session,"document.querySelector('a[href*=evidence]').href")
            cdp.send('Page.navigate',{'url':link},session)
            loaded("Boolean(document.querySelector('form[action$=content]'))")
            mark(family+':workbench-evidence')
            cdp.evaluate(session,"document.querySelector('form[action$=content]').requestSubmit();true")
            loaded("Boolean(document.getElementById('evidence-content'))")
            assert cdp.evaluate(session,"document.getElementById('evidence-content').textContent")==expected
            html=cdp.evaluate(session,'document.documentElement.outerHTML')
            assert human not in html and ticket not in html
            shot=cdp.send('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False},session)
            (output/(family+'-generated-workbench.png')).write_bytes(base64.b64decode(shot['data']))
            cdp.send('Page.navigate',{'url':target+'/audit'},session)
            loaded("document.title==='Audit activity · Gabriel'")
            assert 'evidence.accessed' in cdp.evaluate(session,'document.body.innerText')
            cdp.evaluate(session,"document.querySelector('form[action=\"/disconnect\"]').requestSubmit();true")
            loaded("document.title==='Disconnected · Gabriel'")
            cdp.send('Page.navigate',{'url':target+'/cases'},session)
            loaded("document.title==='Access unavailable · Gabriel'")
            logfile.flush()
            assert human not in (root/'workbench.log').read_text() and ticket not in (root/'workbench.log').read_text()
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)


def run_browser(family,executable,output):
    global stage
    mark(family+':certificate-store')
    with tempfile.TemporaryDirectory(prefix='gabriel-browser-private-') as private:
        root=Path(private)
        tls=certificates(root)
        nss=Path.home()/'.pki'/'nssdb'
        nss.mkdir(mode=0o700,parents=True,exist_ok=True)
        if not (nss/'cert9.db').exists(): subprocess.run(['certutil','-N','-d','sql:'+str(nss),'--empty-password'],check=True,capture_output=True)
        subprocess.run(['certutil','-A','-d','sql:'+str(nss),'-n','gabriel-'+family,'-t','C,,','-i',str(tls['ca.pem'])],check=True,capture_output=True)
        server=make_server('127.0.0.1',0,console_app,server_class=ConsoleServer,handler_class=QuietHandler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(tls['server.pem']),str(tls['server.key']))
        server.socket=context.wrap_socket(server.socket,server_side=True)
        Thread(target=server.serve_forever,daemon=True).start()
        port=free_port()
        profile=root/'profile'
        log=open(root/'browser.log','w+')
        process=subprocess.Popen([executable,'--no-sandbox','--no-first-run','--no-default-browser-check','--disable-background-networking',
            '--disable-sync','--disable-default-apps','--disable-extensions-except='+str(SOURCE),'--load-extension='+str(SOURCE),
            '--user-data-dir='+str(profile),'--remote-debugging-address=127.0.0.1','--remote-debugging-port='+str(port),
            '--window-size=1280,900','about:blank'],stdout=log,stderr=log)
        gateway=None
        cdp=None
        try:
            mark(family+':browser-start')
            cdp=CDP(port)
            version=cdp.send('Browser.getVersion')['product']
            worker=wait_for(lambda:next((t for t in cdp.targets() if t.get('type')=='service_worker' and t.get('url','').endswith('/worker.js')),None),30)
            origin=worker['url'].rsplit('/',1)[0]
            target=cdp.send('Target.createTarget',{'url':'https://localhost:'+str(server.server_port)+'/security'})['targetId']
            console=cdp.attach(target)
            wait_for(lambda:cdp.evaluate(console,'document.title')=='Generated Gabriel Lab Console')
            mark(family+':native-popup')
            popup=native_popup(cdp,target,origin)
            assert cdp.evaluate(popup,"window.scrollTo(0,document.body.scrollHeight); (()=>{const r=document.getElementById('stop').getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight;})()")
            cdp.evaluate(popup,'window.scrollTo(0,0);true')
            cdp.evaluate(popup,"document.getElementById('account').value='Generated lab account'; document.getElementById('browser').value="+json.dumps(family))
            click(cdp,popup,'select')
            wait_for(lambda:cdp.evaluate(popup,"document.getElementById('context').value") or None)
            scope=json.loads(cdp.evaluate(popup,"document.getElementById('context').value"))
            assert scope['page_url']=='https://localhost:'+str(server.server_port)+'/security'
            assert scope['document_id'] and scope['browser']==family
            mark(family+':endpoint-permission')
            gateway_port=free_port()
            endpoint='https://localhost:'+str(gateway_port)
            cdp.evaluate(popup,'document.getElementById("endpoint").value='+json.dumps(endpoint))
            click(cdp,popup,'permission')
            # The native browser permission prompt is deliberately exercised, not bypassed by test host grants.
            time.sleep(2)
            # Native Allow position observed in the retained 1280x1024 lab screenshot.
            # Keyboard focus traversal selected Deny; retain the real permission check below.
            subprocess.run(['xdotool','mousemove','807','256'],check=True,timeout=5)
            time.sleep(0.5)
            subprocess.run(['xdotool','click','1'],check=True,timeout=5)
            time.sleep(0.25)
            existing=next((t for t in cdp.targets() if t.get('url')==origin+'/popup.html'),None)
            popup=cdp.attach(existing['targetId']) if existing else native_popup(cdp,target,origin)
            wait_for(lambda:cdp.evaluate(popup,'chrome.permissions.contains({origins:['+json.dumps(endpoint+'/*')+']})'))
            owner=read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE'])
            app=read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE'])
            password=secrets.token_urlsafe(24)
            org,_=provision_organization(owner,'Generated '+family+' browser lab','owner',password)
            key='k_'+uuid4().hex
            ring=EvidenceKeys(key,{key:secrets.token_bytes(32)},1)
            evidence_root=root/'objects'; evidence_root.mkdir(mode=0o700)
            service=BrowserObservationService(app,LocalEvidenceStore(evidence_root,ring))
            human=service.login(org,'owner',password).token
            case=service.create_case(human,'Generated browser lab case')
            task=service.create_browser_task(human,'Generated browser lab task',900,10)
            keys=root/'keys.json'
            write_document(keys,dict(schema_version=1,purpose='evidence-v1',generation=1,active=key,keys={key:base64.b64encode(ring._key(key)).decode()}))
            bootstrap=root/'gateway'
            prepared=prepare(service,human,task['id'],case['id'],scope,endpoint,origin,bootstrap,share_observations=True)
            env=dict(os.environ,GABRIEL_EVIDENCE_ROOT=str(evidence_root),GABRIEL_EVIDENCE_KEYRING_FILE=str(keys))
            gateway_log=open(root/'gateway.log','w+')
            gateway=subprocess.Popen([sys.executable,'-m','gabriel.identity.gateway_cli','serve','--configuration',str(bootstrap/'gateway.json'),
                '--certificate',str(tls['server.pem']),'--key',str(tls['server.key']),'--bind','127.0.0.1:'+str(gateway_port)],
                env=env,stdout=gateway_log,stderr=gateway_log)
            def ready():
                try:
                    with socket.create_connection(('127.0.0.1',gateway_port),timeout=0.2): return True
                except OSError: return False
            wait_for(ready,12)
            mark(family+':claim')
            ticket=read_document(bootstrap/'claim.json',private=True)['ticket']
            cdp.evaluate(popup,'document.getElementById("endpoint").value='+json.dumps(endpoint)+';document.getElementById("ticket").value='+json.dumps(ticket))
            click(cdp,popup,'pair')
            wait_for(lambda:'Paired.' in (text(cdp,popup,'message') or ''))
            assert all(str(identifier) in text(cdp,popup,'scope') for identifier in (org,case['id'],task['id']))
            mark(family+':preview')
            click(cdp,popup,'preview')
            preview=wait_for(lambda:cdp.evaluate(popup,'document.getElementById("preview-text").value') or None)
            assert 'unusual sign-in' in preview and 'Hostile evidence' in preview
            assert all(str(identifier) in text(cdp,popup,'scope') for identifier in (org,case['id'],task['id']))
            assert all(secret not in preview for secret in ('GENERATED_PASSWORD_MUST_NOT_LEAVE','GENERATED_FORM_MUST_NOT_LEAVE','GENERATED_HIDDEN_MUST_NOT_LEAVE','GENERATED_STYLE_HIDDEN_MUST_NOT_LEAVE'))
            assert not service.list_browser_observations(human,prepared['lease_id'])['observations']
            click(cdp,popup,'share')
            wait_for(lambda:'Explicit sharing approval' in (text(cdp,popup,'message') or ''))
            assert not service.list_browser_observations(human,prepared['lease_id'])['observations']
            click(cdp,popup,'pause')
            wait_for(lambda:'Paused locally' in (text(cdp,popup,'message') or ''))
            assert not cdp.evaluate(popup,'document.getElementById("preview-text").value')
            click(cdp,popup,'preview')
            wait_for(lambda:'Sharing is paused' in (text(cdp,popup,'message') or ''))
            assert not cdp.evaluate(popup,'document.getElementById("preview-text").value')
            click(cdp,popup,'resume')
            wait_for(lambda:'Sharing resumed' in (text(cdp,popup,'message') or ''))
            click(cdp,popup,'preview')
            wait_for(lambda:cdp.evaluate(popup,'document.getElementById("preview-text").value') or None)
            cdp.evaluate(popup,'document.getElementById("approved").checked=true')
            mark(family+':share')
            click(cdp,popup,'share')
            wait_for(lambda:'receipt confirmed' in (text(cdp,popup,'message') or ''))
            observations=service.list_browser_observations(human,prepared['lease_id'])['observations']
            assert len(observations)==1 and observations[0]['state']=='captured'
            data=service.read_evidence(human,observations[0]['evidence_id']).reveal().decode()
            assert data==preview and all(secret not in data for secret in ('GENERATED_PASSWORD_MUST_NOT_LEAVE','GENERATED_FORM_MUST_NOT_LEAVE','GENERATED_HIDDEN_MUST_NOT_LEAVE'))
            click(cdp,popup,'receipts')
            wait_for(lambda:'Receipts checked. 1 captured observations.' in (text(cdp,popup,'message') or ''))
            mark(family+':stop')
            click(cdp,popup,'stop')
            wait_for(lambda:'stopped' in (text(cdp,popup,'message') or '').lower())
            assert service.get_browser_lease(human,prepared['lease_id'])['state']=='disconnected'
            assert not cdp.evaluate(popup,'document.getElementById("preview-text").value')
            assert text(cdp,popup,'scope')=='No paired organization, case or task.'
            peer=read_document(bootstrap/'peer.json',private=True)['token']
            assert not cdp.evaluate(console,'Boolean(window.chrome?.runtime?.sendMessage)')
            log.flush(); gateway_log.flush()
            assert all(secret not in (root/'browser.log').read_text()+(root/'gateway.log').read_text() for secret in (human,peer,ticket))
            workbench_journey(cdp,family,service,human,case,tls,root,env,output,preview)
            executable_version=subprocess.run([executable,'--version'],check=True,capture_output=True,text=True,timeout=5).stdout.strip()
            assert ('1.97.59' if family=='brave' else '155.0.8059.84') in executable_version
            report={'status':'PASS','browser_family':family,'browser_product':version,'executable_version':executable_version,'binary_sha256':sha256(Path(executable).read_bytes()).hexdigest(),
                'extension_version':'0.1.0','extension_origin':origin,'checks':['native_action','always_visible_stop','real_document_binding','endpoint_permission',
                'trusted_local_CA_TLS','one_use_claim','partial_preview','form_hidden_exclusion','no_upload_before_approval','pause_resume',
                'visible_tenant_case_task','unchecked_consent_denial','paused_collection_denial','receipt_inspection',
                'encrypted_receipt','exact_bytes','stop_disconnect','page_has_no_extension_channel','credential_log_exclusion'],
                'workbench_checks':['private_claim','source_health_screen','persisted_case_form','timeline_screen','explicit_evidence_view','audit_screen','disconnect_and_cookie_denial'],
                'test_environment':'isolated generated console; container browser sandbox disabled; no production console/UAT acceptance'}
            (output/(family+'.json')).write_text(json.dumps(report,indent=2))
        except Exception:
            if cdp:
                try:
                    for item in cdp.targets():
                        if item.get('url','').endswith('/popup.html'):
                            private_popup=cdp.attach(item['targetId'])
                            cdp.evaluate(private_popup,"document.querySelectorAll('input,textarea').forEach(e=>{e.value='';});true")
                except Exception: pass
            subprocess.run(['scrot',str(output/(family+'-generated-lab-failure.png'))],capture_output=True,timeout=5)
            raise
        finally:
            if cdp: cdp.close()
            if gateway:
                gateway.terminate(); gateway.wait(timeout=10)
            process.terminate(); process.wait(timeout=10)
            server.shutdown(); server.server_close()
            log.close()


def main():
    output=Path(sys.argv[1]); output.mkdir(parents=True,exist_ok=True)
    mark('database-migrate')
    migrate(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']))
    mark('extension-package')
    metadata=package(SOURCE,output/'gabriel-browser-0.1.0.zip')
    (output/'package.json').write_text(json.dumps(metadata,indent=2))
    manager=subprocess.Popen(['openbox'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for family,path in [('chrome','/opt/chrome-linux64/chrome'),('brave','/opt/brave.com/brave/brave')]:
            run_browser(family,path,output)
        print('PASS: actual Chrome for Testing and Brave generated-console extension/TLS/evidence journeys')
        return 0
    except Exception as error:
        frames=[dict(file=Path(frame.filename).name,line=frame.lineno,function=frame.name) for frame in traceback.extract_tb(error.__traceback__)]
        (output/'failure.json').write_text(json.dumps({'status':'FAIL','stage':stage,'error_type':type(error).__name__,'frames':frames}))
        print('FAIL: browser lab at '+stage+'; '+type(error).__name__)
        return 1
    finally:
        manager.terminate(); manager.wait(timeout=5)


if __name__=='__main__': raise SystemExit(main())
