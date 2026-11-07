"""Exercise the actual host controller, fresh Docker services and HTTPS UI privately."""
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
from threading import Thread
from urllib.parse import urlencode

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo/'tooling/scripts'))
from gabriel_install import DockerOperationError,Installation,prepare
from gabriel_setup import SetupServer
from gabriel_acceptance import collect as collect_runtime_acceptance


def request(root,port,path,fields=None,cookie=None,*,host='localhost',timeout=10,extra_headers=None):
    client=http.client.HTTPSConnection(host,port,context=ssl.create_default_context(cafile=str(root/'tls/ca.pem')),timeout=timeout)
    headers={'Origin':f'https://{host}:{port}', **(extra_headers or {})}
    if fields is not None: headers['Content-Type']='application/x-www-form-urlencoded'
    if cookie: headers['Cookie']=cookie
    try:
        client.request('POST' if fields is not None else 'GET',path,body=urlencode(fields) if fields is not None else None,headers=headers)
        response=client.getresponse()
        return response.status,response.read().decode(),dict(response.getheaders())
    finally: client.close()


@contextmanager
def running_setup(app):
    with SetupServer(app) as wizard:
        server = Thread(target=wizard.run, daemon=True)
        server.start()
        try:
            yield wizard
        finally:
            wizard.finished = True
            server.join(timeout=10)
            assert not server.is_alive()


def setup_ticket(app, password, action):
    with running_setup(app) as wizard:
        def submit(fields, headers=None):
            return request(app.root, wizard.server_port, '/start', fields,
                           host='127.0.0.1', timeout=420, extra_headers=headers)

        fields = dict(setup_key=wizard.key, action=action, organization='Generated installation lab',
                      username='owner', password=password)
        status, html, headers = request(app.root, wizard.server_port, '/', host='127.0.0.1')
        assert status == 200 and wizard.key not in html
        assert headers['Cache-Control'] == 'no-store'
        assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
        assert submit(fields, {'Host': 'localhost'})[0] == 403
        assert submit(fields, {'Origin': 'null'})[0] == 403
        assert submit(dict(fields, setup_key='invalid'))[0] == 403
        if action == 'create':
            status, html, _ = submit(dict(fields, password='weak'))
            assert status == 400 and 'at least 16 characters' in html
            assert not wizard.owner_created
        status, html, _ = submit(fields)
        assert status == 200, 'setup did not open the workbench'
        assert 'Gabriel is ready' in html and f'https://localhost:{app.config["port"]}/claim' in html
        assert password not in html and 'Connect Chrome or Brave' in html
        return re.search(r'id="ticket" value="([A-Za-z0-9_-]+)"', html)[1]


def connect(root,app,password,*,ticket=None):
    if ticket is None:
        ticket=app.open(password)['ticket']
    port=app.config['port']
    navigation = {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate',
                  'Sec-Fetch-Dest': 'document', 'Sec-Fetch-User': '?1'}
    assert request(root,port,'/claim',extra_headers={'Sec-Fetch-Site': 'cross-site'})[0]==403
    code,html,_=request(root,port,'/claim',extra_headers=navigation);assert code==200
    csrf=re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"',html)[1]
    assert request(root,port,'/claim',dict(csrf='wrong',ticket=ticket))[0]==403
    assert request(root,port,'/claim',dict(csrf=csrf,ticket=ticket),extra_headers=navigation)[0]==403
    code,_,headers=request(root,port,'/claim',dict(csrf=csrf,ticket=ticket));assert code==303
    cookie=headers['Set-Cookie'].split(';',1)[0]
    assert all(part in headers['Set-Cookie'] for part in ('Secure','HttpOnly','SameSite=Strict'))
    assert request(root,port,'/cases')[0]==403
    return cookie,csrf


def main():
    directory=Path(sys.argv[1]);directory.mkdir(mode=0o700)
    image=sys.argv[2]
    secret=secrets.token_urlsafe(32)
    apps=[]
    try:
        root=directory/'original'
        prepare(root,18444,image)
        app=Installation(root);apps.append(app)
        readiness=json.loads(app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator',
            '-m','gabriel.identity.gateway_cli','ai-readiness','--ai-model','openai/gpt-oss-120b'))
        assert readiness['projection_version']=='browser-candidate-ai-v1'
        assert not readiness['production_admitted'] and not readiness['raw_page_text_export']
        assert not readiness['reviewed_memory_export'] and not readiness['external_actions_enabled']
        assert re.fullmatch('[a-f0-9]{64}',readiness['configuration_digest'])
        (directory/'browser-ai-readiness.json').write_text(json.dumps(readiness,indent=2))
        config=json.loads(app.compose('--profile','operator','config','--format','json'))
        assert config['networks']['private']['internal']
        assert set(config['services']['workbench']['networks'])=={'private','toolbus'}
        toolbox=config['services']['investigation-tools']
        assert config['networks']['toolbus']['internal'] and set(toolbox['networks'])=={'toolbus'}
        assert not toolbox.get('secrets') and not toolbox.get('volumes') and not toolbox.get('ports') and not toolbox.get('environment')
        assert toolbox['read_only'] and toolbox['cap_drop']==['ALL'] and toolbox['user']=='10001:10001'
        hermes=config['services']['hermes']
        assert set(hermes['networks'])=={'toolbus'} and not hermes.get('secrets') and not hermes.get('volumes') and not hermes.get('ports')
        assert hermes['read_only'] and hermes['cap_drop']==['ALL'] and hermes['user']=='10001:10001'
        assert 'hermes' in config['services']['workbench']['depends_on']
        assert not config['services']['identity-db'].get('ports')
        assert not config['services']['workbench'].get('ports')
        assert config['services']['local-entry']['ports'][0]['host_ip']=='127.0.0.1'
        assert not config['services']['local-entry'].get('secrets') and not config['services']['local-entry'].get('volumes')
        assert config['services']['workbench']['read_only'] and config['services']['workbench']['user']=='10001:10001'
        assert config['services']['workbench']['tmpfs']==['/tmp:rw,noexec,nosuid,nodev,size=64m']
        assert 'owner_dsn' not in {s['source'] for s in config['services']['workbench']['secrets']}
        app.start_db()
        (directory/'installation-network.json').write_text(json.dumps(app.check_network(),indent=2))
        ticket=setup_ticket(app,secret,'create')
        identity=app.operator('receipt')
        assert set(identity)=={'organization_id','user_id','username'}
        try: app.operator('initialize',dict(organization='Duplicate fixture',username='owner',password=secret))
        except ValueError: pass
        else: raise AssertionError('duplicate initialization admitted')
        cookie,csrf=connect(root,app,secret,ticket=ticket)
        assert request(root,18444,'/providers',cookie=cookie)[0]==200
        assert request(root,18444,'/getting-started')[0]==403
        status, html, _ = request(root,18444,'/cases',cookie=cookie)
        assert status == 200 and '3 steps to get started' in html and '/getting-started' in html
        status, html, _ = request(root,18444,'/getting-started',cookie=cookie)
        assert status == 200 and all(label in html for label in ('Create an investigation', 'Connect Chrome or Brave', 'Investigate.'))
        tooling=json.loads(app.compose('exec','-T','workbench','python','-c',"import json; from gabriel.identity.investigation_tools import remote; print(json.dumps(remote('inspect_toolkit')))"))
        assert tooling['status']=='ready' and tooling['packaged_tools_ready']
        supervisor=json.loads(app.compose('exec','-T','workbench','python','-c',"import json; from gabriel.identity.hermes_bridge import health; print(json.dumps(health()))"))
        assert supervisor['status']=='ready' and supervisor['upstream']=='bf0203a794a07aac3ff764972ab9087baa4e4f4e'
        (directory/'hermes-runtime-readiness.json').write_text(json.dumps(supervisor,indent=2))
        runtime=collect_runtime_acceptance(root)
        assert runtime['runtime_checks_passed'] and runtime['production_admitted'] is False
        (directory/'runtime-acceptance.json').write_text(json.dumps(runtime,indent=2))
        analyst_password=secrets.token_urlsafe(24)
        assert request(root,18444,'/members/create',dict(csrf=csrf,username='generated-install-analyst',password=analyst_password,role='analyst'),cookie)[0]==303
        opened=app.open(analyst_password,username='generated-install-analyst')
        code,html,_=request(root,18444,'/claim');assert code==200
        form_csrf=re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"',html)[1]
        code,_,headers=request(root,18444,'/claim',dict(csrf=form_csrf,ticket=opened['ticket']));assert code==303
        analyst_cookie=headers['Set-Cookie'].split(';',1)[0]
        assert request(root,18444,'/personal-providers',cookie=analyst_cookie)[0]==200
        assert request(root,18444,'/providers',cookie=analyst_cookie)[0]==403
        cookie,csrf=connect(root,app,secret,ticket=setup_ticket(app,secret,'open'))
        optional=Installation(root)
        optional.command.extend(['--file',str(repo/'compose.gabriel-specialist-ai.yml')])
        ai_config=json.loads(optional.compose('--profile','operator','config','--format','json'))
        assert set(ai_config['services']['workbench']['networks'])=={'private','toolbus','ai_egress'}
        assert set(ai_config['services']['investigation-tools']['networks'])=={'toolbus'}
        assert set(ai_config['services']['identity-db']['networks'])=={'private'}

        code,html,_=request(root,18444,'/cases/new',cookie=cookie);assert code==200
        nonce=re.search(r'name="nonce" value="([A-Za-z0-9_-]+)"',html)[1]
        code,_,headers=request(root,18444,'/cases',dict(csrf=csrf,nonce=nonce,title='Generated persistent installation case'),cookie)
        assert code==303
        location=headers['Location']
        assert request(root,18444,location,cookie=cookie)[0]==200
        # The live application writes encrypted evidence before backup, then verifies it after restore.
        evidence_script="""import json,os
from uuid import uuid4
from gabriel.identity.installation import active,service
from gabriel.identity.checkpoints import read_document
app=service();token=read_document(active()/'human.json',private=True)['token']
case=app.list_cases(token)[0]['id']
row=app.acquire(token,case,uuid4(),'Generated installation recovery evidence.','generated installation fixture',approved=True)
print(json.dumps({'case':str(case),'evidence':str(row['id'])}))
"""
        raw=app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',evidence_script)
        evidence=json.loads(raw)
        app.compose('restart','identity-db');app.start_db()
        assert request(root,18444,location,cookie=cookie)[0]==200
        old_cookie=cookie
        cookie,csrf=connect(root,app,secret)
        assert request(root,18444,'/cases',cookie=old_cookie)[0]==403
        assert 'Generated persistent installation case' in request(root,18444,'/cases',cookie=cookie)[1]
        original_trust=ssl.create_default_context(cafile=str(root/'tls/ca.pem'))
        key_identity={name:(root/name/'keyring.json').read_bytes() for name in ('provider','evidence')}
        old_cookie=cookie
        renewal=app.renew_tls()
        assert renewal['tls_renewed'] and renewal['workbench_stopped'] and renewal['requires_fresh_login']
        assert renewal['certificate_trust_requires_review'] and not renewal['production_admitted']
        assert renewal['previous_ca_file_sha256']!=renewal['ca_file_sha256']
        assert app.operator('receipt')==identity
        assert all((root/name/'keyring.json').read_bytes()==value for name,value in key_identity.items())
        cookie,csrf=connect(root,app,secret)
        assert request(root,18444,'/cases',cookie=old_cookie)[0]==403
        old_client=http.client.HTTPSConnection('localhost',18444,context=original_trust,timeout=5)
        try:
            try:old_client.request('GET','/claim')
            except ssl.SSLCertVerificationError:pass
            else:raise AssertionError('retired CA still trusted replacement server')
        finally:old_client.close()
        (directory/'tls-renewal.json').write_text(json.dumps(dict(renewal,
            original_identity_and_keys_retained=True,old_cookie_denied=True,
            retired_ca_denied=True,fresh_trusted_https_login=True),indent=2))
        backup=directory/'backup';app.backup(backup)
        assert set(p.name for p in backup.iterdir())=={'database.dump','evidence.tar.gz','backup.json'}
        target=directory/'restored';prepare(target,18445,image)
        restored=Installation(target);apps.append(restored)
        restored.restore(backup,root)
        cookie,csrf=connect(target,restored,secret)
        assert 'Generated persistent installation case' in request(target,18445,'/cases',cookie=cookie)[1]
        verify="""import json
from gabriel.identity.installation import active,service
from gabriel.identity.checkpoints import read_document
app=service();token=read_document(active()/'human.json',private=True)['token']
case=app.list_cases(token)[0]['id'];snapshot=app.get_case(token,case)
row=snapshot['evidence'][0];assert app.read_evidence(token,row['id']).reveal()==b'Generated installation recovery evidence.'
print('PASS: restored encrypted evidence decrypted using the original evidence key')
"""
        output=restored.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',verify).decode()
        assert output.startswith('PASS: restored encrypted evidence')
        assert restored.operator('receipt')==identity
        restored.stop();restored.start_db()
        cookie,_=connect(target,restored,secret)
        assert request(target,18445,'/cases',cookie=cookie)[0]==200
        print('PASS: browser AI module/readiness in rebuilt image; guided setup and reopen; least-privilege loopback HTTPS; hashed owner identity; case and encrypted evidence persistence; old-cookie denial; quiesced backup; fresh-project restore with original keys; fresh login after Stop')
    except DockerOperationError as exc:
        diagnostic=((exc.stdout or b'')+b'\n'+(exc.stderr or b'')).decode(errors='replace')
        replacements=[secret]
        for app in apps:
            for folder in ('database','provider','evidence'):
                for file in (app.root/folder).iterdir():
                    text=file.read_text().strip();replacements.append(text)
                    try:
                        value=json.loads(text)
                        replacements.extend(value.get('keys',{}).values())
                    except ValueError: pass
        for value in sorted(replacements,key=len,reverse=True):
            if value: diagnostic=diagnostic.replace(value,'[GENERATED SECRET REMOVED]')
        diagnostic=re.sub(r'(?:gwt1_|gb1_|gwu1_)[A-Za-z0-9_-]+','[GENERATED TOKEN REMOVED]',diagnostic)
        print('GENERATED-LAB DIAGNOSTIC ONLY: '+diagnostic[-6000:],flush=True)
        raise
    finally:
        for app in apps:
            app.compose('--profile','operator','down','--volumes','--remove-orphans')


if __name__=='__main__': main()
