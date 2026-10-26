"""Exercise the actual host controller, fresh Docker services and HTTPS UI privately."""
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
from urllib.parse import urlencode

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo/'tooling/scripts'))
from gabriel_install import DockerOperationError,Installation,prepare


def request(root,port,path,fields=None,cookie=None):
    client=http.client.HTTPSConnection('localhost',port,context=ssl.create_default_context(cafile=str(root/'tls/ca.pem')),timeout=10)
    headers={'Origin':'https://localhost:'+str(port)}
    if fields is not None: headers['Content-Type']='application/x-www-form-urlencoded'
    if cookie: headers['Cookie']=cookie
    try:
        client.request('POST' if fields is not None else 'GET',path,body=urlencode(fields) if fields is not None else None,headers=headers)
        response=client.getresponse()
        return response.status,response.read().decode(),dict(response.getheaders())
    finally: client.close()


def connect(root,app,password):
    result=app.open(password)
    port=app.config['port']
    code,html,_=request(root,port,'/claim');assert code==200
    csrf=re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"',html)[1]
    assert request(root,port,'/claim',dict(csrf='wrong',ticket=result['ticket']))[0]==403
    code,_,headers=request(root,port,'/claim',dict(csrf=csrf,ticket=result['ticket']));assert code==303
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
        assert set(config['services']['workbench']['networks'])=={'private'}
        assert not config['services']['identity-db'].get('ports')
        assert not config['services']['workbench'].get('ports')
        assert config['services']['local-entry']['ports'][0]['host_ip']=='127.0.0.1'
        assert not config['services']['local-entry'].get('secrets') and not config['services']['local-entry'].get('volumes')
        assert config['services']['workbench']['read_only'] and config['services']['workbench']['user']=='10001:10001'
        assert config['services']['workbench']['tmpfs']==['/tmp:rw,noexec,nosuid,nodev,size=64m']
        assert 'owner_dsn' not in {s['source'] for s in config['services']['workbench']['secrets']}
        app.start_db()
        identity=app.operator('initialize',dict(organization='Generated installation lab',username='owner',password=secret))
        assert set(identity)=={'organization_id','user_id','username'}
        try: app.operator('initialize',dict(organization='Duplicate fixture',username='owner',password=secret))
        except ValueError: pass
        else: raise AssertionError('duplicate initialization admitted')
        cookie,csrf=connect(root,app,secret)
        assert request(root,18444,'/providers',cookie=cookie)[0]==200
        analyst_password=secrets.token_urlsafe(24)
        assert request(root,18444,'/members/create',dict(csrf=csrf,username='generated-install-analyst',password=analyst_password,role='analyst'),cookie)[0]==303
        opened=app.open(analyst_password,username='generated-install-analyst')
        code,html,_=request(root,18444,'/claim');assert code==200
        form_csrf=re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"',html)[1]
        code,_,headers=request(root,18444,'/claim',dict(csrf=form_csrf,ticket=opened['ticket']));assert code==303
        analyst_cookie=headers['Set-Cookie'].split(';',1)[0]
        assert request(root,18444,'/personal-providers',cookie=analyst_cookie)[0]==200
        assert request(root,18444,'/providers',cookie=analyst_cookie)[0]==403
        cookie,csrf=connect(root,app,secret)
        optional=Installation(root)
        optional.command.extend(['--file',str(repo/'compose.gabriel-specialist-ai.yml')])
        ai_config=json.loads(optional.compose('--profile','operator','config','--format','json'))
        assert set(ai_config['services']['workbench']['networks'])=={'private','ai_egress'}
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
        print('PASS: browser AI module/readiness in rebuilt image; fresh installation; least-privilege loopback HTTPS; hashed owner identity; case and encrypted evidence persistence; old-cookie denial; quiesced backup; fresh-project restore with original keys; fresh login after Stop')
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
