"""Operator-only generated-account console discovery; never gives Gabriel login authority."""
import http.client
import json
from pathlib import Path
import subprocess
import time

import websocket


def wait(check,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=check()
        if result: return result
        time.sleep(.1)
    raise AssertionError('console_browser_condition_timeout')


class CDP:
    def __init__(self):
        def url():
            try:
                c=http.client.HTTPConnection('127.0.0.1',19222,timeout=1);c.request('GET','/json/version')
                value=json.loads(c.getresponse().read());c.close();return value['webSocketDebuggerUrl']
            except (OSError,ValueError): return None
        self.ws=websocket.create_connection(wait(url),suppress_origin=True,timeout=20);self.serial=0;self.network={}
    def send(self,method,params=None,session=None):
        self.serial+=1;ident=self.serial
        request={'id':ident,'method':method,'params':params or {}}
        if session: request['sessionId']=session
        self.ws.send(json.dumps(request))
        while True:
            value=json.loads(self.ws.recv())
            if value.get('method')=='Network.responseReceived':
                response=value['params']['response'];key=str(response['status'])
                self.network[key]=self.network.get(key,0)+1
            if value.get('id')==ident:
                if 'error' in value: raise AssertionError('console_cdp_command_failed')
                return value.get('result',{})
    def evaluate(self,session,expression):
        value=self.send('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True},session)
        if value.get('exceptionDetails'): raise AssertionError('console_evaluation_failed')
        return value.get('result',{}).get('value')


def snapshot(cdp,session):
    return cdp.evaluate(session,"""(()=>{
const visible=e=>Boolean(e.getClientRects().length)&&getComputedStyle(e).visibility!=='hidden';
const clean=e=>e.innerText.trim().replace(/\\s+/g,' ').slice(0,160);
return {title:document.title,path:location.pathname,headings:[...document.querySelectorAll('h1,h2,h3')].filter(visible).map(clean).slice(0,30),
table_headers:[...document.querySelectorAll('th')].filter(visible).map(clean).slice(0,80),
links:[...document.querySelectorAll('a[href]')].filter(visible).map(e=>{let u=new URL(e.href);return u.origin===location.origin?{text:clean(e),path:u.pathname,fragment:u.hash.slice(0,180)}:null}).filter(Boolean).slice(0,100),
buttons:[...document.querySelectorAll('button')].filter(visible).map(e=>({text:clean(e),label:e.getAttribute('aria-label')||'',test_subject:e.getAttribute('data-test-subj')||''})).slice(0,80),
inputs:[...document.querySelectorAll('input,textarea,select')].filter(visible).map(e=>({tag:e.tagName,type:e.type,name:e.name,id:e.id})).slice(0,50)};})()""")


def main():
    creds=json.loads(Path('/run/lab/credentials.json').read_text());tool=creds['tool'];target='https://localhost:'+str(creds['port'])
    home=Path('/home/browserlab/.pki/nssdb');home.mkdir(parents=True)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(home)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['certutil','-A','-d','sql:'+str(home),'-n','generated-console-lab','-t','C,,','-i','/run/lab/server.pem'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    process=subprocess.Popen(['/usr/bin/chromium','--headless=new','--no-sandbox','--no-first-run','--disable-background-networking',
        '--disable-dev-shm-usage','--remote-debugging-port=19222','--user-data-dir=/tmp/console-profile',
        '--proxy-server=http://127.0.0.1:9','--proxy-bypass-list=localhost','about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    cdp=None;session=None;phase='browser_startup';login=None;pages=[]
    try:
        cdp=CDP();tab=cdp.send('Target.createTarget',{'url':target+('/login' if tool=='iris' else '/app/login')})['targetId']
        session=cdp.send('Target.attachToTarget',{'targetId':tab,'flatten':True})['sessionId']
        cdp.send('Network.enable',{},session)
        phase='login_form'
        wait(lambda:cdp.evaluate(session,"Boolean(document.querySelector('input[type=password]'))"),90)
        login=snapshot(cdp,session)
        expression="""(()=>{const p=document.querySelector('input[type=password]');const u=document.querySelector('input[name=username],input#username,input[type=text]');
if(!p||!u)return false;const set=(e,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,v);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
set(u,USER);set(p,PASSWORD);return true;})()""".replace('USER',json.dumps(creds['username'])).replace('PASSWORD',json.dumps(creds['password']))
        assert cdp.evaluate(session,expression)
        phase='operator_login'
        cdp.evaluate(session,"document.querySelector('button[type=submit],input[type=submit]').click();true")
        wait(lambda:cdp.evaluate(session,"!location.pathname.includes('login')&&!document.querySelector('input[type=password]')"),90)
        wait(lambda:cdp.evaluate(session,"document.readyState==='complete'"))
        phase='application_content'
        if tool=='wazuh':
            wait(lambda:cdp.evaluate(session,"(()=>{const t=document.body.innerText.toLowerCase();return ['endpoint security','threat intelligence','security operations'].some(x=>t.includes(x));})()"),180)
        else: time.sleep(3)
        pages=[snapshot(cdp,session)]
        if tool=='iris':
            cdp.send('Page.navigate',{'url':target+'/manage/cases'},session)
            wait(lambda:cdp.evaluate(session,"location.pathname==='/manage/cases'&&document.readyState==='complete'"))
            time.sleep(2);pages.append(snapshot(cdp,session))
            assert any('Case' in h or 'Name' in h for h in pages[-1]['table_headers'])
        else:
            assert any(link['text'] for link in pages[0]['links']) or any(pages[0]['headings'])
        result=dict(status='PASS',tool=tool,operator_login_only=True,gabriel_adapter_admitted=False,attack_detection_verified=False,
            browser_version=subprocess.check_output(['/usr/bin/chromium','--version']).decode().strip(),login_structure=login,pages=pages,
            http_response_status_counts=cdp.network,
            environment='generated isolated lab; headless Chromium sandbox disabled; external browser traffic blocked by dead proxy')
        encoded=json.dumps(result,sort_keys=True)
        for value in (creds['password'],):
            if value in encoded: raise AssertionError('credential_in_discovery_report')
        Path('/output/browser.json').write_text(encoded+'\n')
        print('PASS: '+tool+' operator browser login and rendered page structure; adapter and detection acceptance remain open')
    except Exception:
        diagnostic=dict(status='FAIL',tool=tool,phase=phase,operator_login_only=True,gabriel_adapter_admitted=False,
            attack_detection_verified=False,login_structure=login,pages=pages,http_response_status_counts=cdp.network if cdp else {})
        if cdp and session:
            try: diagnostic['last_structure']=snapshot(cdp,session)
            except Exception: diagnostic['last_structure_unavailable']=True
        encoded=json.dumps(diagnostic,sort_keys=True)
        if creds['password'] not in encoded: Path('/output/browser.json').write_text(encoded+'\n')
        raise AssertionError('console_browser_failed_at_'+phase) from None
    finally:
        if cdp: cdp.ws.close()
        process.terminate();process.wait(timeout=10)


if __name__=='__main__': main()
