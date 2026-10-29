"""Ordinary generated dashboards exercised through the installed extension and HTTPS."""
import base64
from hashlib import sha256
from html import escape
import json
import re
from pathlib import Path
import socket
import subprocess
import sys
from uuid import uuid4

from gabriel.identity.browser_gateway import prepare
from gabriel.identity.browser_navigation import BrowserNavigationService
from gabriel.identity.checkpoints import read_document
from gabriel.identity.service import connection
from gabriel.identity.workbench import prepare_workbench


VARIANTS={
    '/structure-alpha':('Northstar generated console',('Time','Severity','State')),
    '/structure-beta':('Harbor generated workspace',('State','Time','Severity')),
    '/structure-gamma':('Summit generated dashboard',('Severity','State','Time')),
}
FORBIDDEN=('GENERATED_STRUCTURE_HIDDEN','GENERATED_STRUCTURE_FORM','GENERATED_STRUCTURE_OFFSCREEN',
    'GENERATED_STRUCTURE_COVERED','GENERATED_STRUCTURE_FRAME')


def page(path):
    if path not in VARIANTS:return None
    title,headers=VARIANTS[path]
    values={'Time':'2026-01-02T03:04:05Z','Severity':'High','State':'Open'}
    table='<table id="untrusted-selector-do-not-export"><thead><tr>'+''.join('<th>'+h+'</th>' for h in headers)+\
        '</tr></thead><tbody><tr>'+''.join('<td>'+values[h]+'</td>' for h in headers)+'</tr></tbody></table>'
    return ('<!doctype html><html><head><title>'+escape(title)+'</title><style>'
        'body{font:14px/1.3 sans-serif;margin:16px}table{border-collapse:collapse}th,td{padding:8px;border:1px solid #444}'
        'dl{margin:12px 0}dt,dd{display:inline-block;margin:0 12px 0 0}'
        '</style></head><body><p>Generated lab account</p><h1>'+escape(title)+'</h1>'+table+
        '<h2>Documentation examples and aggregate counts require review</h2>'
        '<dl><dt>Reported source</dt><dd>Generated sensor - unverified</dd></dl>'
        '<dl><dt>Aggregate total</dt><dd>7</dd></dl>'
        '<h2 hidden>GENERATED_STRUCTURE_HIDDEN</h2>'
        '<dl hidden><dt>GENERATED_STRUCTURE_HIDDEN</dt><dd>excluded</dd></dl>'
        '<form><dl><dt>GENERATED_STRUCTURE_FORM</dt><dd>excluded</dd></dl><input value="GENERATED_STRUCTURE_FORM"></form>'
        '<dl style="position:absolute;top:4000px"><dt>GENERATED_STRUCTURE_OFFSCREEN</dt><dd>excluded</dd></dl>'
        '<div style="position:relative;width:600px;height:35px"><dl style="position:absolute;inset:0;margin:0">'
        '<dt>GENERATED_STRUCTURE_COVERED</dt><dd>excluded</dd></dl>'
        '<div style="position:absolute;inset:0;background:white;z-index:2">Generated visible cover</div></div>'
        '<iframe srcdoc="<h1>GENERATED_STRUCTURE_FRAME</h1>"></iframe></body></html>').encode()


def _wire(cdp,popup,value):
    return cdp.evaluate(popup,'chrome.runtime.sendMessage('+json.dumps(value)+')')


def _relation(structure):
    assert len(structure['tables'])==1
    table=structure['tables'][0]
    assert table['id']=='t1'
    assert len(table['rows'])==1
    headers={h['id']:h['text'] for h in table['headers']}
    row=table['rows'][0]
    assert row['id']=='t1/r2'
    relation={}
    for cell in row['cells']:
        column=cell['id'].rsplit('/c',1)[1]
        relation[headers['t1/h'+column]]=cell['text']
    return relation


def _workbench(cdp,family,service,human,case_id,draft_id,tls,root,env,h):
    port=h['free_port']();target='https://localhost:'+str(port)
    directory=root/'structure-workbench'
    prepare_workbench(service,human,target,directory)
    ticket=read_document(directory/'claim.json',private=True)['ticket']
    logfile=root/'structure-workbench.log'
    with logfile.open('w+') as log:
        process=subprocess.Popen([sys.executable,'-m','gabriel.identity.workbench_cli','serve','--configuration',str(directory/'workbench.json'),
            '--certificate',str(tls['server.pem']),'--key',str(tls['server.key']),'--bind','127.0.0.1:'+str(port)],env=env,stdout=log,stderr=log)
        tab=None
        try:
            def ready():
                if process.poll() is not None:raise AssertionError('structure_workbench_exited')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):return True
                except OSError:return False
            h['wait_for'](ready,12)
            tab=cdp.send('Target.createTarget',{'url':target+'/claim'})['targetId']
            session=cdp.attach(tab)
            h['wait_for'](lambda:cdp.evaluate(session,"Boolean(document.querySelector('input[name=ticket]'))"))
            cdp.evaluate(session,"document.querySelector('input[name=ticket]').value="+json.dumps(ticket)+";document.querySelector('form').requestSubmit();true")
            h['wait_for'](lambda:cdp.evaluate(session,"document.title==='Investigations · Gabriel'"))
            cdp.send('Page.navigate',{'url':target+'/cases/'+case_id+'/evidence/'+draft_id},session)
            h['wait_for'](lambda:cdp.evaluate(session,"Boolean(document.querySelector('form[action$=content]'))"))
            assert not cdp.evaluate(session,"Boolean(document.getElementById('evidence-content'))")
            cdp.evaluate(session,"document.querySelector('form[action$=content]').requestSubmit();true")
            h['wait_for'](lambda:cdp.evaluate(session,"Boolean(document.getElementById('evidence-content'))"))
            rendered=json.loads(cdp.evaluate(session,"document.getElementById('evidence-content').textContent"))
            assert rendered['version']=='browser-structure-draft-v1'
            assert rendered['status']=='unreviewed_historical_structure'
            assert rendered['field_meanings']=='unknown' and rendered['counts']['event_count']=='unknown'
            assert rendered['source_verified'] is False and rendered['incident_facts_admitted'] is False
            assert rendered['model_calls']==0
            html=cdp.evaluate(session,'document.documentElement.outerHTML')
            assert human not in html and ticket not in html
            assert all(secret not in html for secret in FORBIDDEN)
            output=h['output']
            source_sha=(output/'source-sha.txt').read_text().strip()
            assert len(source_sha)==40 and all(c in '0123456789abcdef' for c in source_sha)
            screenshots={}
            for width in (1280,390):
                cdp.send('Emulation.setDeviceMetricsOverride',dict(width=width,height=900,deviceScaleFactor=1,mobile=False),session)
                assert cdp.evaluate(session,'document.documentElement.scrollWidth<=innerWidth'), (width,'structure page overflow')
                shot=base64.b64decode(cdp.send('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False),session)['data'])
                screenshot=family+'-generated-structure-draft'+('' if width==1280 else '-390')+'.png'
                (output/screenshot).write_bytes(shot)
                screenshots[str(width)]=dict(screenshot=screenshot,screenshot_sha256=sha256(shot).hexdigest())
            cdp.send('Emulation.clearDeviceMetricsOverride',session=session)
            evidence=dict(kind='actual_generated_data_authenticated_content_view',source_sha=source_sha,
                screenshots=screenshots,draft_evidence_id=draft_id,
                draft_sha256=sha256(service.read_evidence(human,draft_id).reveal()).hexdigest(),
                source=rendered['source'],model_calls=0,production_admission=False,native_device_acceptance=False)
            (output/(family+'-generated-structure-draft.json')).write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')
        finally:
            if tab and any(t['targetId']==tab for t in cdp.targets()):cdp.send('Target.closeTarget',{'targetId':tab})
            process.terminate();process.wait(timeout=5)
            log.flush()
            assert human not in logfile.read_text() and ticket not in logfile.read_text()


def journey(cdp,family,service,human,tls,root,env,console_origin,extension_origin,port,h):
    navigation=BrowserNavigationService(service._dsn,service.store)
    endpoint='https://localhost:'+str(port)
    relations=[];checks=[];last=None
    with connection(service._dsn) as conn:
        before_calls=conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_dispatch_claims').fetchone()['n']
    for index,path in enumerate(VARIANTS):
        h['mark'](family+':visible-structure-'+str(index+1))
        for old in cdp.targets():
            if old.get('url')==extension_origin+'/popup.html':cdp.send('Target.closeTarget',{'targetId':old['targetId']})
        tab=cdp.send('Target.createTarget',{'url':console_origin+path})['targetId']
        session=cdp.attach(tab)
        h['wait_for'](lambda:cdp.evaluate(session,'document.readyState')=='complete' and cdp.evaluate(session,'location.pathname')==path)
        cdp.send('Target.activateTarget',{'targetId':tab})
        popup=h['native_popup'](cdp,tab,extension_origin)
        cdp.evaluate(popup,'document.getElementById("account").value="Generated lab account";document.getElementById("browser").value='+json.dumps(family))
        h['click'](cdp,popup,'select')
        scope=json.loads(h['wait_for'](lambda:cdp.evaluate(popup,'document.getElementById("context").value') or None))
        case=navigation.create_case(human,'Generated ordinary structure '+str(index))
        task=navigation.create_browser_task(human,'Generated structure task '+str(index),900,20)
        directory=root/('structure-'+str(index))
        enrolled=prepare(navigation,human,task['id'],case['id'],scope,endpoint,extension_origin,directory,share_observations=True)
        logfile=root/('structure-'+str(index)+'.log')
        with logfile.open('w+') as log:
            process=subprocess.Popen([sys.executable,'-m','gabriel.identity.gateway_cli','serve','--configuration',str(directory/'gateway.json'),
                '--certificate',str(tls['server.pem']),'--key',str(tls['server.key']),'--bind','127.0.0.1:'+str(port)],env=env,stdout=log,stderr=log)
            try:
                def ready():
                    if process.poll() is not None:raise AssertionError('structure_gateway_exited')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2):return True
                    except OSError:return False
                h['wait_for'](ready,12)
                ticket=read_document(directory/'claim.json',private=True)['ticket']
                cdp.evaluate(popup,'document.getElementById("endpoint").value='+json.dumps(endpoint)+';document.getElementById("ticket").value='+json.dumps(ticket))
                h['click'](cdp,popup,'pair')
                h['wait_for'](lambda:navigation.get_browser_lease(human,enrolled['lease_id'])['state']=='active' and str(case['id']) in (h['text'](cdp,popup,'scope') or ''))
                preview=_wire(cdp,popup,dict(operation='preview-structure'))
                assert preview['ok'],preview
                content=preview['result']['content'];structure=json.loads(content)
                assert structure['version']=='browser-visible-structure-v1'
                assert structure['account']==dict(id='a1',text='Generated lab account')
                assert all(secret not in content for secret in FORBIDDEN)
                assert 'untrusted-selector-do-not-export' not in content
                assert not cdp.evaluate(session,"Boolean(document.querySelector('meta[name=\"gabriel-generated-console\"]'))")
                relations.append(_relation(structure))
                assert not navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                denied=_wire(cdp,popup,dict(operation='share-structure',content=content,observed_at=preview['result']['observed_at'],approved=False))
                assert not denied['ok']
                assert not navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                if index==0:
                    h['click'](cdp,popup,'preview-structure')
                    h['wait_for'](lambda:cdp.evaluate(popup,'document.getElementById("structure-text").value') or None)
                    assert json.loads(cdp.evaluate(popup,'document.getElementById("structure-text").value'))==structure
                    h['click'](cdp,popup,'share-structure')
                    h['wait_for'](lambda:'Explicit sharing approval' in (h['text'](cdp,popup,'message') or ''))
                    assert not navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                    original=cdp.evaluate(session,'document.querySelector("table").outerHTML')
                    for field in ('th','td'):
                        cdp.evaluate(session,'document.querySelectorAll('+json.dumps(field)+')[1].style.visibility="hidden";true')
                        limited=_wire(cdp,popup,dict(operation='preview-structure'))
                        assert limited['ok'],limited
                        limited_table=json.loads(limited['result']['content'])['tables'][0]
                        assert limited_table['rows'][0]['id']=='t1/r2'
                        cells={c['id']:c['text'] for c in limited_table['rows'][0]['cells']}
                        assert cells['t1/r2/c1']=='2026-01-02T03:04:05Z' and cells['t1/r2/c3']=='Open'
                        if field=='th':
                            assert [head['id'] for head in limited_table['headers']]==['t1/h1','t1/h3']
                            assert 'Severity' not in limited['result']['content']
                        else:
                            assert 't1/r2/c2' not in cells and 'High' not in limited['result']['content']
                        cdp.evaluate(session,'document.querySelector("table").outerHTML='+json.dumps(original)+';true')
                    for mutation in ('document.querySelector("td").setAttribute("colspan","2")',
                            'document.querySelector("td").innerHTML="<table><tr><td>Nested generated cell</td></tr></table>"',
                            'document.querySelector("thead").remove();document.querySelector("table").insertAdjacentHTML("beforeend","<tfoot><tr><th>Generated summary</th><th>Generated total</th><th>Generated footer</th></tr></tfoot>")'):
                        cdp.evaluate(session,mutation+';true')
                        unsupported=_wire(cdp,popup,dict(operation='preview-structure'))
                        assert not unsupported['ok']
                        cdp.evaluate(session,'document.querySelector("table").outerHTML='+json.dumps(original)+';true')
                    cdp.evaluate(session,'document.querySelector("p").textContent="Different generated account";true')
                    assert not _wire(cdp,popup,dict(operation='preview-structure'))['ok']
                    cdp.evaluate(session,'document.querySelector("p").textContent="Generated lab account";true')
                    oversized='Generated '+('x'*1025)
                    cdp.evaluate(session,'document.querySelector("h1").style.cssText="font-size:10px;width:800px;overflow-wrap:anywhere";document.querySelector("h1").textContent='+json.dumps(oversized)+';true')
                    assert not _wire(cdp,popup,dict(operation='preview-structure'))['ok']
                    cdp.evaluate(session,'document.querySelector("h1").style.cssText="";document.querySelector("h1").textContent='+json.dumps(VARIANTS[path][0])+';true')
                    fresh=_wire(cdp,popup,dict(operation='preview-structure'))
                    cdp.evaluate(session,'document.querySelector("td").textContent="Generated source changed after preview";true')
                    stale=_wire(cdp,popup,dict(operation='share-structure',content=fresh['result']['content'],observed_at=fresh['result']['observed_at'],approved=True))
                    assert not stale['ok']
                    assert not navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                    cdp.evaluate(session,'document.querySelector("table").outerHTML='+json.dumps(original)+';true')
                    checks+=['ordinary_table_privacy_exclusions','hidden_header_and_missing_cell_never_shift_columns',
                        'merged_nested_and_footer_header_table_rejected','account_mismatch_denied','oversized_structure_denied','source_change_after_preview_denied']
                if index==0:
                    h['click'](cdp,popup,'preview-structure')
                    preview_content=h['wait_for'](lambda:cdp.evaluate(popup,'document.getElementById("structure-text").value') or None)
                    cdp.evaluate(popup,'document.getElementById("structure-approved").checked=true;true')
                    h['click'](cdp,popup,'share-structure')
                    def recorded():
                        text=h['text'](cdp,popup,'result') or ''
                        found=re.search(r'structural draft ([a-f0-9-]{36})',text)
                        return found.group(1) if found else None
                    draft_id=h['wait_for'](recorded)
                    observations=navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                    assert len(observations)==1
                    receipt=dict(observation_id=str(observations[0]['id']),evidence_id=str(observations[0]['evidence_id']))
                    checks.append('actual_popup_structure_preview_consent_and_share_controls')
                else:
                    preview=_wire(cdp,popup,dict(operation='preview-structure'))
                    assert preview['ok']
                    preview_content=preview['result']['content']
                    if index==1:
                        edited=json.loads(preview_content)
                        edited['tables'][0]['rows'][0]['cells'][0]['text']='Invented replacement'
                        denied=_wire(cdp,popup,dict(operation='share-structure',content=json.dumps(edited),observed_at=preview['result']['observed_at'],approved=True))
                        assert not denied['ok']
                        assert not navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                        redacted=json.loads(preview_content)
                        removed=redacted['pairs'].pop(0)
                        assert removed['value']['text']=='Generated sensor - unverified'
                        preview_content=json.dumps(redacted)
                        checks+=['retained_structural_field_edit_denied','whole_block_redaction_before_sharing']
                    if index==2:
                        assert _wire(cdp,popup,dict(operation='preview'))['ok']
                        denied=_wire(cdp,popup,dict(operation='share-structure',content=preview_content,observed_at=preview['result']['observed_at'],approved=True))
                        assert not denied['ok']
                        preview=_wire(cdp,popup,dict(operation='preview-structure'))
                        assert preview['ok']
                        assert _wire(cdp,popup,dict(operation='pause'))['ok']
                        assert _wire(cdp,popup,dict(operation='resume'))['ok']
                        denied=_wire(cdp,popup,dict(operation='share-structure',content=preview['result']['content'],observed_at=preview['result']['observed_at'],approved=True))
                        assert not denied['ok']
                        assert not navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                        preview=_wire(cdp,popup,dict(operation='preview-structure'))
                        assert preview['ok']
                        preview_content=preview['result']['content']
                        checks+=['capture_mode_change_invalidates_structural_preview','pause_resume_requires_new_structural_preview']
                    result=_wire(cdp,popup,dict(operation='share-structure',content=preview_content,observed_at=preview['result']['observed_at'],approved=True))
                    assert result['ok'],result
                    receipt=result['result']['receipt'];review=result['result']['review']
                    assert review['model_calls']==0 and review['counts']['event_count']=='unknown'
                    draft_id=review['draft_evidence_id']
                    observations=navigation.list_browser_observations(human,enrolled['lease_id'])['observations']
                assert len(observations)==1 and observations[0]['state']=='captured'
                raw=navigation.read_evidence(human,receipt['evidence_id']).reveal()
                assert json.loads(raw)==json.loads(preview_content)
                if index==1:assert b'Generated sensor - unverified' not in raw
                draft_raw=navigation.read_evidence(human,draft_id).reveal()
                draft=json.loads(draft_raw)
                assert draft['structure']==json.loads(raw)
                assert draft['source']['evidence_digest']==sha256(raw).hexdigest()
                assert draft['source']['evidence_id']==str(receipt['evidence_id'])
                assert draft['source']['observation_id']==str(receipt['observation_id'])
                assert draft['console_identity']=='unverified' and draft['field_meanings']=='unknown'
                assert draft['counts']['visible_table_rows']==1 and draft['counts']['event_count']=='unknown'
                assert draft['coverage']=='partial' and draft['source_verified'] is False and draft['incident_facts_admitted'] is False
                assert all(secret not in draft_raw.decode() for secret in FORBIDDEN)
                assert all(b'Generated sensor - unverified' not in file.read_bytes() for file in service.store.root.glob('*.gbe'))
                stopped=_wire(cdp,popup,dict(operation='stop-tab'))
                assert stopped['ok'] and navigation.get_browser_lease(human,enrolled['lease_id'])['state']=='disconnected'
                assert json.loads(navigation.read_evidence(human,draft_id).reveal())==draft
                if last is None:last=(str(case['id']),draft_id)
            finally:
                process.terminate();process.wait(timeout=5)
                log.flush()
                assert human not in logfile.read_text() and ticket not in logfile.read_text()
                if any(t['targetId']==tab for t in cdp.targets()):cdp.send('Target.closeTarget',{'targetId':tab})
    assert relations==[dict(Time='2026-01-02T03:04:05Z',Severity='High',State='Open')]*3
    _workbench(cdp,family,navigation,human,*last,tls,root,env,h)
    with connection(service._dsn) as conn:
        after_calls=conn.execute('SELECT count(*) AS n FROM gabriel_identity.model_dispatch_claims').fetchone()['n']
    assert after_calls==before_calls
    return checks+['three_unmarked_rebranded_reordered_tables','exact_source_cells_and_capture_digest',
        'visible_row_count_is_not_event_count','separate_structured_capture_consent','encrypted_local_structural_draft',
        'historical_draft_after_stop','authenticated_explicit_workbench_content','structure_content_responsive_390_and_1280','zero_new_model_dispatches']
