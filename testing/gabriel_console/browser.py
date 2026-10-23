"""Operator-only generated-account console discovery; never gives Gabriel login authority."""
from hashlib import sha256
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
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
        self.ws=websocket.create_connection(wait(url),suppress_origin=True,timeout=20);self.serial=0
    def send(self,method,params=None,session=None):
        self.serial+=1;ident=self.serial
        request={'id':ident,'method':method,'params':params or {}}
        if session: request['sessionId']=session
        self.ws.send(json.dumps(request))
        while True:
            value=json.loads(self.ws.recv())
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
inputs:[...document.querySelectorAll('input,textarea,select')].filter(visible).map(e=>({tag:e.tagName,type:e.type,name:e.name,id:e.id})).slice(0,50)};})()""")


def main():
    creds=json.loads(Path('/run/lab/credentials.json').read_text());tool=creds['tool'];target='https://localhost:'+str(creds['port'])
    home=Path('/home/browserlab/.pki/nssdb');home.mkdir(parents=True)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(home)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['certutil','-A','-d','sql:'+str(home),'-n','generated-console-lab','-t','C,,','-i','/run/lab/server.pem'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    process=subprocess.Popen(['/usr/bin/chromium','--headless=new','--no-sandbox','--no-first-run','--disable-background-networking',
        '--disable-dev-shm-usage','--remote-debugging-port=19222','--user-data-dir=/tmp/console-profile',
        '--proxy-server=http://127.0.0.1:9','--proxy-bypass-list=localhost','about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    cdp=None
    try:
        cdp=CDP();tab=cdp.send('Target.createTarget',{'url':target+('/login' if tool=='iris' else '/auth/login')})['targetId']
        session=cdp.send('Target.attachToTarget',{'targetId':tab,'flatten':True})['sessionId']
        wait(lambda:cdp.evaluate(session,"Boolean(document.querySelector('input[type=password]'))"),90)
        login=snapshot(cdp,session)
        expression="""(()=>{const p=document.querySelector('input[type=password]');const u=document.querySelector('input[name=username],input#username,input[type=text]');
if(!p||!u)return false;const set=(e,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,v);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
set(u,USER);set(p,PASSWORD);return true;})()""".replace('USER',json.dumps(creds['username'])).replace('PASSWORD',json.dumps(creds['password']))
        assert cdp.evaluate(session,expression)
        cdp.evaluate(session,"document.querySelector('button[type=submit],input[type=submit]').click();true")
        wait(lambda:cdp.evaluate(session,"!location.pathname.includes('login')&&!document.querySelector('input[type=password]')"),90)
        wait(lambda:cdp.evaluate(session,"document.readyState==='complete'"))
        time.sleep(3)
        pages=[snapshot(cdp,session)]
        if tool=='iris':
            cdp.send('Page.navigate',{'url':target+'/manage/cases'},session)
            wait(lambda:cdp.evaluate(session,"location.pathname==='/manage/cases'&&document.readyState==='complete'"))
            time.sleep(2);pages.append(snapshot(cdp,session))
            assert any('Case' in h or 'Name' in h for h in pages[-1]['table_headers'])
        else:
            assert pages[0]['headings'] or pages[0]['links']
        result=dict(status='PASS',tool=tool,operator_login_only=True,gabriel_adapter_admitted=False,attack_detection_verified=False,
            browser_version=subprocess.check_output(['/usr/bin/chromium','--version']).decode().strip(),login_structure=login,pages=pages,
            environment='generated isolated lab; headless Chromium sandbox disabled; external browser traffic blocked by dead proxy')
        encoded=json.dumps(result,sort_keys=True)
        for value in (creds['password'],):
            if value in encoded: raise AssertionError('credential_in_discovery_report')
        Path('/output/browser.json').write_text(encoded+'\n')
        print('PASS: '+tool+' operator browser login and rendered page structure; adapter and detection acceptance remain open')
    finally:
        if cdp: cdp.ws.close()
        process.terminate();process.wait(timeout=10)


if __name__=='__main__': main()
