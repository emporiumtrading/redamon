"""Operator-only generated-account console discovery; never gives Gabriel login authority."""
import http.client
import json
import re
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit

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
        self.ws=websocket.create_connection(wait(url),suppress_origin=True,timeout=20);self.serial=0;self.network={};self.errors={}
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
                if response['status']>=400:
                    path=urlsplit(response['url']).path
                    route=path if re.fullmatch(r'/(?:api|internal|auth|_plugins|_opendistro)/[a-zA-Z0-9_./-]{1,120}',path) else '[other-route]'
                    route='/'.join(part if len(part)<=32 else '[id]' for part in route.split('/'))
                    error=key+' '+route;self.errors[error]=self.errors.get(error,0)+1
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
return {error_terms:['Unauthorized','Forbidden','security_exception','run_as','No API available','Error','not allowed','permissions','Wazuh API','3003','5013','account','403','401'].filter(t=>document.body.innerText.includes(t)),title:document.title,path:location.pathname,has_search:Boolean(location.search),has_fragment:Boolean(location.hash),headings:[...document.querySelectorAll('h1,h2,h3')].filter(visible).map(clean).slice(0,30),
table_headers:[...document.querySelectorAll('th,[role=columnheader]')].filter(visible).map(clean).slice(0,80),
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
    cdp=None;session=None;phase='browser_startup';login=None;pages=[];replay_check=None
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
            phase='readonly_viewer_identity'
            assert cdp.evaluate(session,"(()=>{const es=[...document.querySelectorAll('button')].filter(e=>e.getClientRects().length&&(e.getAttribute('data-test-subj')==='userMenuButton'||e.querySelector('[class*=euiAvatar]')));if(es.length!==1)return false;es[0].click();return true;})()")
            identity="[...document.querySelectorAll('span,div,p,h1,h2,h3,h4')].some(e=>!e.childElementCount&&e.getClientRects().length&&e.innerText.trim()===USER)".replace('USER',json.dumps(creds['username']))
            wait(lambda:cdp.evaluate(session,identity))
            cdp.send('Input.dispatchKeyEvent',{'type':'keyDown','key':'Escape','code':'Escape','windowsVirtualKeyCode':27},session)
            cdp.send('Input.dispatchKeyEvent',{'type':'keyUp','key':'Escape','code':'Escape','windowsVirtualKeyCode':27},session)
        else: time.sleep(3)
        pages=[snapshot(cdp,session)]
        if tool=='iris':
            assert any(link['text'].split(' ',1)[0]==creds['username'] for link in pages[0]['links'])
            cdp.send('Page.navigate',{'url':target+'/manage/cases'},session)
            wait(lambda:cdp.evaluate(session,"location.pathname==='/manage/cases'&&document.readyState==='complete'"))
            time.sleep(2);pages.append(snapshot(cdp,session))
            assert any('Case' in h or 'Name' in h for h in pages[-1]['table_headers'])
            if 'case_id' in creds:
                phase='readonly_case_page'
                cdp.send('Page.navigate',{'url':target+'/case?cid='+str(creds['case_id'])},session)
                wait(lambda:cdp.evaluate(session,"location.pathname==='/case'&&document.readyState==='complete'"))
                time.sleep(2);pages.append(snapshot(cdp,session))
                assert '#'+str(creds['case_id'])+' -' in pages[-1]['title']
        else:
            assert any(link['text'] for link in pages[0]['links']) or any(pages[0]['headings'])
            phase='threat_hunting_navigation'
            assert cdp.evaluate(session,"(()=>{const a=[...document.querySelectorAll('a[href]')].find(e=>e.getClientRects().length&&new URL(e.href).pathname==='/app/threat-hunting'&&e.innerText.trim()==='Threat Hunting');if(!a)return false;a.click();return true;})()")
            wait(lambda:cdp.evaluate(session,"location.pathname==='/app/threat-hunting'&&document.readyState==='complete'"),90)
            time.sleep(5);pages.append(snapshot(cdp,session))
            phase='threat_hunting_events'
            wait(lambda:cdp.evaluate(session,"[...document.querySelectorAll('button,a,[role=tab]')].some(e=>e.getClientRects().length&&e.innerText.trim()==='Events')"),90)
            assert cdp.evaluate(session,"(()=>{const e=[...document.querySelectorAll('button,a,[role=tab]')].find(e=>e.getClientRects().length&&e.innerText.trim()==='Events');if(!e)return false;e.click();return true;})()")
            wait(lambda:cdp.evaluate(session,"[...document.querySelectorAll('th,[role=columnheader]')].some(e=>e.getClientRects().length&&e.innerText.trim())"),90)
            pages.append(snapshot(cdp,session))
            phase='replay_event_query'
            replay=json.loads(Path('/run/lab/replay.json').read_text());marker=replay['marker']
            assert replay['live_attack'] is False and re.fullmatch(r'gabriel-lab-[a-f0-9]{12}',marker)
            expected=sorted({event['rule_id'] for event in replay['observed_alerts']})
            assert expected
            def search(query):
                expression="""(()=>{const es=[...document.querySelectorAll('textarea')].filter(e=>e.getClientRects().length);if(es.length!==1)return false;
const e=es[0];Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(e,QUERY);
e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()""".replace('QUERY',json.dumps(query))
                assert cdp.evaluate(session,expression)
                wait(lambda:cdp.evaluate(session,"Boolean(document.querySelector('button[data-test-subj=querySubmitButton]:not([disabled])'))"))
                cdp.evaluate(session,"document.querySelector('button[data-test-subj=querySubmitButton]').click();true")
            phase='replay_empty_control'
            search('full_log: "'+marker+'-absent"')
            wait(lambda:cdp.evaluate(session,"(()=>{const e=document.querySelector('[data-test-subj=discoverNoResults]');return Boolean(e&&e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden');})()"),90)
            replay_check=dict(marker=marker,empty_control_verified=True,marker_filtered_rows_rendered=False,
                native_event_identity_verified=False,live_attack=False)
            phase='replay_marker_results'
            search('full_log: "'+marker+'"')
            def matching():
                return cdp.evaluate(session,"(()=>{const ids=new Set(EXPECTED);return [...new Set([...document.querySelectorAll('a[href]')].filter(e=>e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden').slice(0,100).filter(e=>{const id=e.innerText.trim(),u=new URL(e.href);return ids.has(id)&&u.origin===location.origin&&u.pathname==='/app/rules'&&u.hash==='#/manager/?tab=rules&redirectRule='+id;}).map(e=>e.innerText.trim()))];})()".replace('EXPECTED',json.dumps(expected)))
            found=wait(matching,120)
            replay_check=dict(marker=marker,empty_control_verified=True,matching_rule_ids=found,
                marker_filtered_rows_rendered=True,native_event_identity_verified=False,live_attack=False)
            pages.append(snapshot(cdp,session))
            phase='native_document_details'
            details=[];seen=set()
            for page_number in range(4):
                count=cdp.evaluate(session,"[...document.querySelectorAll('button[aria-label=\"Inspect document details\"]')].filter(e=>e.getClientRects().length).length")
                assert 1<=count<=100
                for index in range(count):
                    expression="(()=>{const es=[...document.querySelectorAll('button[aria-label=\"Inspect document details\"]')].filter(e=>e.getClientRects().length);if(!es[INDEX])return false;es[INDEX].click();return true;})()".replace('INDEX',str(index))
                    assert cdp.evaluate(session,expression)
                    wait(lambda:cdp.evaluate(session,"[...document.querySelectorAll('[role=tab],button')].some(e=>e.getClientRects().length&&e.innerText.trim()==='JSON')"))
                    cdp.evaluate(session,"[...document.querySelectorAll('[role=tab],button')].find(e=>e.getClientRects().length&&e.innerText.trim()==='JSON').click();true")
                    raw=wait(lambda:cdp.evaluate(session,"(()=>{const e=document.querySelector('[aria-label=\"Document details\"]');return e&&e.getClientRects().length?e.innerText:null;})()"))
                    source=json.loads(raw)['_source']
                    assert marker in source['full_log'] and re.fullmatch(r'[0-9]+\.[0-9]+',source['id'])
                    assert source['rule']['id'] in {'5710','5712'} and source['id'] not in seen
                    seen.add(source['id'])
                    details.append(dict(event_id=source['id'],event_time=source['timestamp'],
                        rule_id=source['rule']['id'],agent_id=source['agent']['id'],agent_name=source['agent']['name'],
                        full_log=source['full_log'][:512],location=source['location'],
                        data={k:source.get('data',{}).get(k) for k in ('srcip','srcport','dstuser')}))
                    cdp.send('Input.dispatchKeyEvent',{'type':'keyDown','key':'Escape','code':'Escape','windowsVirtualKeyCode':27},session)
                    cdp.send('Input.dispatchKeyEvent',{'type':'keyUp','key':'Escape','code':'Escape','windowsVirtualKeyCode':27},session)
                    wait(lambda:cdp.evaluate(session,"!document.querySelector('[aria-label=\"Document details\"]')"))
                if len(details)==replay['emitted_records']: break
                assert len(details)<replay['emitted_records']
                before=cdp.evaluate(session,"document.querySelector('table,[role=grid]').innerText")
                assert cdp.evaluate(session,"(()=>{const b=[...document.querySelectorAll('button')].find(e=>e.getClientRects().length&&e.getAttribute('aria-label')==='Next page'&&!e.disabled);if(!b)return false;b.click();return true;})()")
                wait(lambda:cdp.evaluate(session,"document.querySelector('table,[role=grid]').innerText")!=before)
            assert len(details)==12
            replay_check['native_details']=details
            replay_check['native_id_visible']=True
            replay_check['observed_event_count']=len(details)
        result=dict(status='PASS',tool=tool,operator_login_only=True,generated_viewer_used=True,viewer_username=creds['username'],gabriel_adapter_admitted=False,attack_detection_verified=False,
            browser_version=subprocess.check_output(['/usr/bin/chromium','--version']).decode().strip(),login_structure=login,pages=pages,
            http_response_status_counts=cdp.network,
            http_error_routes=cdp.errors,
            replay_event_query=replay_check,
            environment='generated isolated lab; headless Chromium sandbox disabled; external browser traffic blocked by dead proxy')
        encoded=json.dumps(result,sort_keys=True)
        for value in (creds['password'],):
            if value in encoded: raise AssertionError('credential_in_discovery_report')
        Path('/output/browser.json').write_text(encoded+'\n')
        print('PASS: '+tool+' operator browser login and rendered page structure; adapter and detection acceptance remain open')
    except Exception:
        diagnostic=dict(status='FAIL',tool=tool,phase=phase,operator_login_only=True,gabriel_adapter_admitted=False,
            attack_detection_verified=False,login_structure=login,pages=pages,http_response_status_counts=cdp.network if cdp else {},
            http_error_routes=cdp.errors if cdp else {},replay_event_query=replay_check)
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
