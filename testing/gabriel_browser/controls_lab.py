"""Real packaged-extension actions against a generated read-only dashboard."""
from html import escape
import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import parse_qs
from uuid import uuid4

from gabriel.identity.browser_gateway import prepare
from gabriel.identity.browser_navigation import BrowserNavigationService
from gabriel.identity.browser_controls import VERSION
from gabriel.identity.checkpoints import read_document


def page(path,query):
    if not path.startswith('/controls/'):return None
    value=parse_qs(query).get('q',[''])[0]
    landmark='Search results for '+value if path=='/controls/results' else 'Generated dashboard'
    return ('''<!doctype html><html><head><title>Generated Controls Dashboard</title></head><body>
<p>Generated lab account</p><h1 id="landmark">'''+escape(landmark)+'''</h1>
<button id="sections" type="button" aria-haspopup="menu" aria-controls="menu" aria-expanded="false"
 onclick="window.actions++;this.setAttribute('aria-expanded','true');document.getElementById('menu').hidden=false">Open sections</button>
<nav id="menu" hidden><a id="traffic" href="/controls/second">Traffic section</a></nav>
<label for="severity">Severity</label><select id="severity" onchange="window.actions++;document.getElementById('filter-result').textContent=this.value==='high'?'High severity results':'All severity results'">
<option value="all">All</option><option value="high">High</option></select><p id="filter-result">All severity results</p>
<form id="search" aria-label="Search events" method="get" action="/controls/results" onsubmit="window.submitHandlerCalled++;return false">
<label for="q">Search query</label><input id="q" name="q" type="search" value="'''+escape(value,quote=True)+'''"
 onchange="window.actions++;document.getElementById('edit-result').textContent='Search ready'">
<button type="submit">Search events</button></form><p id="edit-result">Search not entered</p>
<button id="next" type="button" onclick="window.actions++;document.getElementById('page-result').textContent='Page 2'">Next page</button><p id="page-result">Page 1</p>
<label for="password">Password</label><input id="password" type="password" value="GENERATED_CREDENTIAL_EXCLUDED">
<textarea id="unlabelled">GENERATED_CONFIDENTIAL_NOTES_EXCLUDED</textarea>
<label>Notes<textarea id="wrapped">GENERATED_PRIVATE_NOTE_4961</textarea></label>
<button id="delete" type="button" onclick="window.unsafeActions++">Delete incident</button>
<script>window.actions=0;window.unsafeActions=0;window.submitHandlerCalled=0;</script></body></html>''').encode()


def policy(origin):
    first=origin+'/controls/start';second=origin+'/controls/second';result=origin+'/controls/results?q=generated'
    def step(kind,tag,identifier,name,source,destination,expected_id,expected,**extra):
        return dict(kind=kind,target=dict(tag=tag,id=identifier,name=name),source_url=source,destination_url=destination,
            expect=dict(id=expected_id,text=expected),**extra)
    return dict(version=VERSION,request_id=str(uuid4()),read_only_role_confirmed=True,query_keys=['q'],steps=[
        step('menu','button','sections','Open sections',first,first,'menu','Traffic section'),
        step('paginate','a','traffic','Traffic section',first,second,'landmark','Generated dashboard'),
        step('filter','select','severity','Severity',second,second,'filter-result','High severity results',value='high'),
        step('fill','input','q','Search query',second,second,'edit-result','Search ready',value='generated'),
        step('paginate','button','next','Next page',second,second,'page-result','Page 2'),
        step('submit','form','search','Search events',second,result,'landmark','Search results for generated',fields={'q':'generated'})])


def journey(cdp,family,service,human,tls,root,env,console_target,console,origin,extension_origin,port):
    from testing.gabriel_browser.lab import click,text,wait_for,native_popup,mark
    service=BrowserNavigationService(service._dsn,service.store)
    checks=[]
    unassigned=cdp.send('Target.createTarget',{'url':origin+'/controls/unassigned'})['targetId']
    other=cdp.attach(unassigned)
    wait_for(lambda:cdp.evaluate(other,'document.readyState')=='complete')
    for scenario in ('success','approval','ambiguous','password','post','hidden_field','postcondition','covered_postcondition','stale_postcondition','stop_race'):
        mark(family+':controls-'+scenario)
        cdp.send('Page.navigate',{'url':origin+'/controls/start'},console)
        wait_for(lambda:cdp.evaluate(console,'document.title')=='Generated Controls Dashboard' and cdp.evaluate(console,'document.readyState')=='complete')
        popup=native_popup(cdp,console_target,extension_origin)
        cdp.evaluate(popup,'document.getElementById("account").value="Generated lab account";document.getElementById("browser").value='+json.dumps(family))
        click(cdp,popup,'select')
        scope=json.loads(wait_for(lambda:cdp.evaluate(popup,'document.getElementById("context").value') or None))
        click(cdp,popup,'controls-inventory')
        wait_for(lambda:'coverage' in (text(cdp,popup,'controls-details') or ''))
        inventory=json.loads(text(cdp,popup,'controls-details'))
        assert all(row['id'] not in {'password','delete','unlabelled'} for row in inventory['controls'])
        assert 'GENERATED_CREDENTIAL_EXCLUDED' not in json.dumps(inventory)
        assert 'GENERATED_CONFIDENTIAL_NOTES_EXCLUDED' not in json.dumps(inventory)
        assert 'GENERATED_PRIVATE_NOTE_4961' not in json.dumps(inventory)
        assert next(row for row in inventory['controls'] if row['id']=='wrapped')['name']=='Notes'
        reviewed=policy(origin)
        if scenario in {'password','post','hidden_field'}:
            reviewed['steps']=[reviewed['steps'][3 if scenario=='password' else 5]]
            reviewed['steps'][0]['source_url']=origin+'/controls/start'
            if scenario=='password':
                reviewed['steps'][0]['destination_url']=origin+'/controls/start'
                cdp.evaluate(console,'document.getElementById("q").type="password";true')
            else:
                cdp.evaluate(console,'document.getElementById("q").value="generated";true')
                if scenario=='post':cdp.evaluate(console,'document.getElementById("search").method="post";true')
                else:cdp.evaluate(console,'document.getElementById("search").insertAdjacentHTML("beforeend","<input type=hidden name=csrf value=GENERATED_HIDDEN_TOKEN>");true')
        if scenario=='postcondition':
            reviewed['steps']=[reviewed['steps'][0]]
            reviewed['steps'][0]['expect']['text']='This result never appears'
        if scenario=='stale_postcondition':
            reviewed['steps']=[reviewed['steps'][4]]
            reviewed['steps'][0]['source_url']=reviewed['steps'][0]['destination_url']=origin+'/controls/start'
            cdp.evaluate(console,'''document.getElementById('page-result').textContent='Page 2';
                document.getElementById('next').onclick=()=>{window.actions++;
                    setTimeout(()=>document.getElementById('page-result').textContent='Loading',1000)};true''')
        if scenario=='covered_postcondition':
            reviewed['steps']=[reviewed['steps'][0]]
            cdp.evaluate(console,'''document.getElementById('sections').addEventListener('click',()=>{
                const box=document.getElementById('menu').getBoundingClientRect();
                const overlay=document.createElement('div');overlay.textContent='Loading';
                Object.assign(overlay.style,{position:'fixed',zIndex:'9999',background:'white',
                    left:box.left+'px',top:box.top+'px',width:box.width+'px',height:box.height+'px'});
                document.body.append(overlay);
            });true''')
        if scenario=='ambiguous':
            cdp.evaluate(console,'document.getElementById("sections").after(document.getElementById("sections").cloneNode(true));true')
        case=service.create_case(human,'Generated controls '+scenario,purpose='performance_test')
        task=service.create_browser_task(human,'Reviewed controls '+scenario,300,20)
        directory=root/('controls-'+scenario)
        enrolled=prepare(service,human,task['id'],case['id'],scope,'https://localhost:'+str(port),extension_origin,directory,
            share_observations=True,control_plan=reviewed)
        with open(root/('controls-'+scenario+'.log'),'w+') as logfile:
            process=subprocess.Popen([sys.executable,'-m','testing.gabriel_browser.controls_gateway' if scenario=='stop_race' else 'gabriel.identity.gateway_cli',
                'serve','--configuration',str(directory/'gateway.json'),'--certificate',str(tls['server.pem']),
                '--key',str(tls['server.key']),'--bind','127.0.0.1:'+str(port)],env=env,stdout=logfile,stderr=logfile)
            try:
                def ready():
                    if process.poll() is not None:raise AssertionError('controls_gateway_exited')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2):return True
                    except OSError:return False
                wait_for(ready)
                ticket=read_document(directory/'claim.json',private=True)['ticket']
                peer=read_document(directory/'peer.json',private=True)['token']
                cdp.evaluate(popup,'document.getElementById("endpoint").value='+json.dumps('https://localhost:'+str(port))+';document.getElementById("ticket").value='+json.dumps(ticket))
                click(cdp,popup,'pair')
                wait_for(lambda:service.get_browser_lease(human,enrolled['lease_id'])['state']=='active')
                click(cdp,popup,'controls-plan')
                wait_for(lambda:'Review every control' in (text(cdp,popup,'message') or ''))
                if scenario=='approval':
                    click(cdp,popup,'controls-run')
                    wait_for(lambda:'explicitly approve controls' in (text(cdp,popup,'message') or ''))
                    assert cdp.evaluate(console,'window.actions')==0
                    assert not service.list_browser_observations(human,enrolled['lease_id'])['observations']
                    click(cdp,popup,'stop')
                else:
                    cdp.evaluate(popup,'document.getElementById("controls-approved").checked=true')
                    click(cdp,popup,'controls-run')
                    if scenario=='stop_race':
                        wait_for(lambda:'CONTROL_PREPARED_DELAY' in (root/('controls-'+scenario+'.log')).read_text())
                        click(cdp,popup,'stop')
                        wait_for(lambda:service.get_browser_lease(human,enrolled['lease_id'])['state']=='disconnected')
                        assert cdp.evaluate(console,'window.actions')==0
                    elif scenario=='success':
                        wait_for(lambda:'Completed 6 reviewed control steps' in (text(cdp,popup,'message') or ''),45)
                        assert cdp.evaluate(console,'location.href')==origin+'/controls/results?q=generated'
                        observations=service.list_browser_observations(human,enrolled['lease_id'])['observations']
                        assert len(observations)==6
                        for row in observations:
                            value=service.read_evidence(human,row['evidence_id']).reveal().decode()
                            assert 'GENERATED_CREDENTIAL_EXCLUDED' not in value
                        assert cdp.evaluate(console,'window.submitHandlerCalled')==0
                        click(cdp,popup,'stop')
                    else:
                        wait_for(lambda:service.get_browser_lease(human,enrolled['lease_id'])['state']=='disconnected',20)
                        assert not service.list_browser_observations(human,enrolled['lease_id'])['observations']
                        assert cdp.evaluate(console,'window.actions')==(1 if scenario in {'postcondition','covered_postcondition'} else 0)
                assert cdp.evaluate(console,'window.submitHandlerCalled')==0
                assert cdp.evaluate(console,'window.unsafeActions')==0
                assert cdp.evaluate(other,'window.actions')==0 and cdp.evaluate(other,'location.href')==origin+'/controls/unassigned'
                logfile.flush();assert all(secret not in (root/('controls-'+scenario+'.log')).read_text() for secret in (human,peer,ticket))
                checks.append(scenario)
            finally:
                process.terminate();process.wait(timeout=10)
    cdp.send('Target.closeTarget',{'targetId':unassigned})
    return ['menu_disclosure','menu_link_subpage','native_filter','text_search_field','button_pagination','reviewed_get_form',
        'exact_postconditions','encrypted_six_step_observations','credential_exclusion','unassigned_tab_isolation',
        'no_submit_event_handler','explicit_approval','ambiguous_target_denied','password_drift_denied','post_form_denied','hidden_form_fields_denied',
        'postcondition_failure_stops','covered_postcondition_stops','stale_postcondition_denied','stop_after_prepare_no_dispatch','no_automatic_replay','private_token_exclusion']
