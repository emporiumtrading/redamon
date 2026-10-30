"""Generated HTTPS enrollment and lifecycle checks through the actual Docker controller."""
from datetime import datetime,timezone
import http.client
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import time
from unittest.mock import patch
from uuid import uuid4

from installation_journey import connect,request

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo/'tooling/scripts'))
from gabriel_install import Installation,prepare
from gabriel_acceptance import collect

ORIGIN='chrome-extension://'+'a'*32


def gateway(root,port,operation,body,*,token=None,origin=ORIGIN):
    client=http.client.HTTPSConnection('localhost',port,context=ssl.create_default_context(cafile=str(root/'tls/ca.pem')),timeout=10)
    headers={'Origin':origin,'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    try:
        client.request('POST','/v1/browser/'+operation,json.dumps(body),headers)
        response=client.getresponse()
        return response.status,json.loads(response.read())
    finally:client.close()


def closed(port):
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=2):pass
    except OSError:return True
    return False


def assert_closed(port):
    for _ in range(20):
        if closed(port):return
        time.sleep(0.25)
    raise AssertionError('gateway listener remained open')


def main():
    directory=Path(sys.argv[1]);directory.mkdir(mode=0o700)
    root=directory/'installation'
    password=secrets.token_urlsafe(32)
    image=sys.argv[2]
    app=None
    checks=[]
    try:
        prepare(root,18544,image);app=Installation(root)
        app.start_db();app.check_network()
        app.operator('initialize',dict(organization='Generated browser installation',username='owner',password=password))
        cookie,csrf=connect(root,app,password)
        code,html,_=request(root,18544,'/cases/new',cookie=cookie);assert code==200
        nonce=re.search(r'name="nonce" value="([A-Za-z0-9_-]+)"',html)[1]
        code,_,headers=request(root,18544,'/cases',dict(csrf=csrf,nonce=nonce,title='Generated browser gateway case'),cookie)
        assert code==303
        case_id=headers['Location'].split('/')[-1]
        analyst_password=secrets.token_urlsafe(24)
        assert request(root,18544,'/members/create',dict(csrf=csrf,username='generated-browser-analyst',password=analyst_password,role='analyst'),cookie)[0]==303
        context=dict(browser='chrome',extension_version='0.4.0',installation_id=str(uuid4()),tab_id=7,
            document_id=str(uuid4()),page_url='https://generated-console.invalid/dashboard',account_label='Generated read-only lab')
        def opened(duration=120):
            return app.browser_open(case_id,context,ORIGIN,port=18543,duration=duration,max_steps=3,share_observations=True)
        result=opened()
        assert set(result)-{'previous_browser_stop'}=={'lease_id','task_id','case_id','endpoint','expires_at','ticket','listener_loopback_only','sharing_approved'}
        assert gateway(root,18543,'claim',dict(ticket=result['ticket'],context=context),origin='chrome-extension://'+'b'*32)[0]==403
        assert gateway(root,18543,'claim',dict(ticket=result['ticket'],context=dict(context,tab_id=8)))[0]==403
        code,value=gateway(root,18543,'claim',dict(ticket=result['ticket'],context=context));assert code==200
        assert set(value)=={'status','result'} and set(value['result'])=={'lease_id','paired','expires_at','scheduled_review_enabled',
            'discovery_enabled','capabilities','page_content_received','sharing_approved','token','context','organization_id','case_id','task_id','ai_review_enabled'}
        export_check="""import json,sys
from gabriel.identity.installation import active
from gabriel.identity.checkpoints import read_document
candidate=json.load(sys.stdin)
human=read_document(active()/'human.json',private=True)['token']
assert human not in json.dumps(candidate)
print(json.dumps({'human_token_absent_from_exports':True}))
"""
        confinement=json.loads(app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',export_check,
            payload=json.dumps({'opened':result,'claim':value}).encode()))
        assert confinement=={'human_token_absent_from_exports':True}
        peer=value['result']['token'];assert peer.startswith('gbp1_')
        assert value['result']['case_id']==case_id and value['result']['task_id']==result['task_id']
        assert gateway(root,18543,'claim',dict(ticket=result['ticket'],context=context))[0]==403
        assert gateway(root,18543,'heartbeat',dict(context=context),token=peer)[0]==200
        content='Generated installation browser evidence; untrusted page text, no incident conclusion.'
        observation=dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=1,
            context=context,observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',client_minimized=True,content=content)
        code,value=gateway(root,18543,'observe',observation,token=peer);assert code==200
        receipt=value['result'];assert not receipt['source_verified']
        assert gateway(root,18543,'observe',observation,token=peer)[1]['result']['evidence_id']==receipt['evidence_id']
        code,value=gateway(root,18543,'receipts',dict(context=context),token=peer)
        assert code==200 and value['result']['observations'][0]['state']=='captured'
        evidence_check="""from gabriel.identity.installation import active,browser_service
from gabriel.identity.checkpoints import read_document
app=browser_service();token=read_document(active()/'human.json',private=True)['token']
assert app.read_evidence(token,EVIDENCE).reveal()==CONTENT.encode()
assert all(CONTENT.encode() not in path.read_bytes() for path in app.store.root.glob('*.gbe'))
assert app.custody(token,EVIDENCE)
print('verified encrypted browser evidence and custody')
""".replace('EVIDENCE',repr(receipt['evidence_id'])).replace('CONTENT',repr(content))
        assert app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',evidence_check).decode().startswith('verified encrypted')
        active=collect(root)
        assert len(active['services'])==7 and active['browser_gateway_source_binding']==active['runtime_source_binding']
        assert not active['production_admitted'] and not active['provider_egress_explicit']
        (directory/'browser-runtime-acceptance.json').write_text(json.dumps(active,indent=2))
        stopped=app.browser_stop();assert stopped['listener_stopped'] and stopped['revocation_confirmed']
        assert_closed(18543)
        assert len(collect(root)['services'])==5
        verify="""import json
from gabriel.identity.installation import active,browser_service
from gabriel.identity.checkpoints import read_document
from gabriel.identity.tasks import TaskService
app=browser_service();token=read_document(active()/'human.json',private=True)['token']
lease=app.get_browser_lease(token,LEASE)
task=TaskService(app._dsn).get_task(token,TASK)
assert lease['state']=='disconnected' and task['state']=='cancelled'
print(json.dumps({'lease_revoked':True,'task_cancelled':True}))
""".replace('LEASE',repr(result['lease_id'])).replace('TASK',repr(result['task_id']))
        verified=json.loads(app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',verify))
        assert verified=={'lease_revoked':True,'task_cancelled':True}
        checks.append('exact native-shaped scope, one-use TLS claim, peer heartbeat, strict seven-service/source attestation, explicit revoke and task cancellation')

        old_peer=peer
        opened()
        assert gateway(root,18543,'heartbeat',dict(context=context),token=old_peer)[0]==403
        app.open(analyst_password,username='generated-browser-analyst')
        assert_closed(18543)
        checks.append('named account switch quiesces and revokes gateway before replacing original authority')
        app.operator('revoke')
        try:opened()
        except ValueError:pass
        else:raise AssertionError('revoked human session enrolled browser')
        assert_closed(18543)
        checks.append('saved but revoked human session cannot enroll or start listener')
        connect(root,app,password)

        uncertain=opened()
        app.compose('stop','identity-db')
        # Keep the real database offline during this single Stop attempt instead of restarting it.
        with patch.object(app,'start_db',return_value=None):stopped=app.browser_stop()
        assert stopped['listener_stopped'] and not stopped['revocation_confirmed']
        assert_closed(18543)
        checks.append('actual database outage closes listener and reports unconfirmed revocation')
        app.start_db()
        stopped=app.browser_stop();assert stopped['revocation_confirmed'] and stopped['listener_stopped']
        retry_verify=verify.replace(repr(result['lease_id']),repr(uncertain['lease_id'])).replace(repr(result['task_id']),repr(uncertain['task_id']))
        assert json.loads(app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',retry_verify))=={'lease_revoked':True,'task_cancelled':True}
        assert_closed(18543)
        checks.append('restored database allows explicit Stop retry to confirm original lease and task cleanup')

        result=opened(60)
        code,value=gateway(root,18543,'claim',dict(ticket=result['ticket'],context=context));assert code==200
        deadline=datetime.fromisoformat(result['expires_at']).timestamp()+3
        while True:
            remaining=deadline-time.time()
            if remaining<=0:break
            time.sleep(min(1,remaining))
        assert_closed(18543)
        ids=app.compose('ps','--all','--quiet','browser-gateway','browser-entry').decode().split()
        from gabriel_install import run
        containers=json.loads(run(['docker','inspect',*ids]))
        assert len(containers)==2 and all(not row['State']['Running'] for row in containers)
        assert all(row['HostConfig']['RestartPolicy']['Name']=='no' for row in containers)
        app.browser_stop()
        checks.append('real original lease deadline terminates both gateway process and published relay without renewal')

        opened()
        backup=app.backup(directory/'backup')
        assert backup['browser_stop']['listener_stopped'] and backup['browser_stop']['revocation_confirmed']
        assert_closed(18543)
        checks.append('quiesced backup stops and revokes browser gateway before snapshot')
        result=dict(version='gabriel-install-browser-journey-v1',checks=checks,production_admitted=False,
            native_browser_acceptance='pending',provider_dispatch_not_enabled=True,human_token_absent_from_exports=confinement['human_token_absent_from_exports'])
        (directory/'browser-installation-result.json').write_text(json.dumps(result,indent=2))
        print('PASS: generated Docker browser enrollment, trusted TLS claim, revocation, database-outage shutdown and real finite expiry; native user acceptance pending')
    finally:
        if app:app.compose('--profile','browser','--profile','operator','down','--volumes','--remove-orphans')


if __name__=='__main__':main()
