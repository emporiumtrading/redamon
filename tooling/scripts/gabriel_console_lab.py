#!/usr/bin/env python3
"""Prepare and check dedicated generated-data console labs; never a Gabriel adapter."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import time
from uuid import uuid4

REPO=Path(__file__).resolve().parents[2]
PINS={
    'iris':('https://github.com/dfir-iris/iris-web.git','v2.4.24','3e1e42d6088d950cf5c51ed8ad708adfb900beae'),
    'wazuh':('https://github.com/wazuh/wazuh-docker.git','v4.14.9','56ece955b1107b7b62823afae5b7057e1dab9d98'),
}
PHASE='preflight'
PRIVATE=[]
RESOLVED={}


def run(command,*,cwd=None,env=None,data=None,timeout=900,accepted=(0,)):
    result=subprocess.run(command,cwd=cwd,env=env,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if result.returncode not in accepted:
        message=result.stderr.decode(errors='replace')[-3000:]
        for value in sorted(PRIVATE,key=len,reverse=True): message=message.replace(value,'[REMOVED]')
        raise RuntimeError('command_failed: '+message)
    return result.stdout


def write(path,value):
    with path.open('x') as stream: json.dump(value,stream,sort_keys=True);stream.write('\n')


def secret():
    value='Aa1!'+secrets.token_urlsafe(32)
    PRIVATE.append(value)
    return value


def image(tag):
    run(['docker','pull','--quiet',tag])
    metadata=json.loads(run(['docker','image','inspect',tag]))[0]
    digests=metadata.get('RepoDigests',[])
    if not digests or '@sha256:' not in digests[0]: raise ValueError('image_digest_missing')
    RESOLVED[tag]={'digest':digests[0],'image_id':metadata['Id'],'os':metadata['Os'],'architecture':metadata['Architecture']}
    return digests[0],metadata['Id']


def compose(root,*args,data=None,accepted=(0,)):
    info=json.loads((root/'lab.json').read_text())
    if re.fullmatch(r'gabriel-console-[a-f0-9]{16}',info['project']) is None: raise ValueError('invalid_project')
    if sha256((root/'compose.json').read_bytes()).hexdigest()!=info['compose_sha256']: raise ValueError('configuration_changed')
    return run(['docker','compose','--project-name',info['project'],'--file',str(root/'compose.json'),*args],cwd=root,data=data,accepted=accepted)


def certificates(root):
    directory=root/'tls';directory.mkdir(mode=0o700)
    run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-days','1','-nodes',
        '-keyout',str(directory/'server.key'),'-out',str(directory/'server.pem'),'-subj','/CN=localhost',
        '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'])
    for path in directory.iterdir(): path.chmod(0o444)


def prepare(tool,root):
    global PHASE
    if root.exists() or not root.is_absolute() or root!=root.resolve() or REPO in root.parents: raise ValueError('new_external_directory_required')
    run(['docker','info']);run(['docker','compose','version'])
    if tool=='wazuh' and int(Path('/proc/sys/vm/max_map_count').read_text())<262144: raise ValueError('configure_lab_vm_max_map_count_first')
    root.mkdir(mode=0o700)
    project='gabriel-console-'+uuid4().hex[:16]
    source=root/'source';url,tag,commit=PINS[tool]
    PHASE='pinned_source'
    run(['git','clone','--depth','1','--branch',tag,url,str(source)])
    if run(['git','rev-parse','HEAD'],cwd=source).decode().strip()!=commit: raise ValueError('upstream_source_changed')
    certificates(root)
    port=18446 if tool=='iris' else 18447
    owner_password=secret()
    credentials={'tool':tool,'username':'gabriel-lab-owner' if tool=='iris' else 'admin','password':owner_password,'port':port}
    write(root/'credentials.json',credentials)
    if tool=='iris':
        base=source
        broker_password=secret()
        values=dict(POSTGRES_USER='postgres',POSTGRES_PASSWORD=secret(),POSTGRES_ADMIN_USER='raptor',POSTGRES_ADMIN_PASSWORD=secret(),
            POSTGRES_DB='iris_db',POSTGRES_SERVER='db',POSTGRES_PORT='5432',IRIS_SECRET_KEY=secret(),IRIS_SECURITY_PASSWORD_SALT=secret(),
            IRIS_ADM_USERNAME=credentials['username'],IRIS_ADM_PASSWORD=owner_password,IRIS_ADM_API_KEY=secret(),IRIS_ADM_EMAIL='generated-owner@example.invalid',
            IRIS_UPSTREAM_SERVER='app',IRIS_UPSTREAM_PORT='8000',IRIS_AUTHENTICATION_TYPE='local',DOCKERIZED='1',
            INTERFACE_HTTPS_PORT=str(port),SERVER_NAME='localhost',CERT_FILENAME='server.pem',KEY_FILENAME='server.key',CELERY_BROKER='amqp://gabriel-lab-broker:'+broker_password+'@rabbitmq',
            APP_IMAGE_NAME='ghcr.io/dfir-iris/iriswebapp_app',APP_IMAGE_TAG='v2.4.24',DB_IMAGE_NAME='ghcr.io/dfir-iris/iriswebapp_db',DB_IMAGE_TAG='v2.4.24',
            NGINX_IMAGE_NAME='ghcr.io/dfir-iris/iriswebapp_nginx',NGINX_IMAGE_TAG='v2.4.24')
        with (source/'.env').open('x') as stream: stream.write(''.join(k+'='+v+'\n' for k,v in values.items()))
        environment=dict(os.environ,**values)
        for directory in ('certificates/rootCA','certificates/web_certificates','certificates/ldap'): (source/directory).mkdir(parents=True,exist_ok=True)
        shutil.copyfile(root/'tls/server.pem',source/'certificates/rootCA/irisRootCACert.pem')
        for name in ('server.pem','server.key'): shutil.copyfile(root/'tls'/name,source/'certificates/web_certificates'/name);(source/'certificates/web_certificates'/name).chmod(0o444)
        config=json.loads(run(['docker','compose','--file','docker-compose.yml','config','--format','json'],cwd=base,env=environment))
        config['services']['rabbitmq']['environment']={'RABBITMQ_DEFAULT_USER':'gabriel-lab-broker','RABBITMQ_DEFAULT_PASS':broker_password}
        for service in config['services'].values(): service.pop('env_file',None)
        config['networks']={'iris_backend':{'internal':True},'iris_frontend':{'internal':True},'entry':{}}
        config['services']['nginx']['networks']={'iris_frontend':{},'entry':{}}
        entry='nginx'
    else:
        base=source/'single-node'
        PHASE='wazuh_certificates'
        generator,_=image('wazuh/wazuh-certs-generator:0.0.4')
        generation=json.loads(run(['docker','compose','-f','generate-indexer-certs.yml','config','--format','json'],cwd=base))
        generation['services']['generator']['image']=generator
        generation.pop('name',None)
        for network in generation.get('networks',{}).values(): network.pop('name',None)
        write(root/'generate.json',generation)
        run(['docker','compose','--project-name',project+'-certs','--file',str(root/'generate.json'),'run','--rm','generator'],cwd=base)
        run(['docker','compose','--project-name',project+'-certs','--file',str(root/'generate.json'),'down','--remove-orphans'],cwd=base)
        hasher,_=image('httpd:2.4-alpine')
        run(['docker','run','--rm','--network','none','--mount','type=bind,src='+str(base/'config/wazuh_indexer_ssl_certs')+',dst=/certs',
            '--entrypoint','sh',hasher,'-c','find /certs -type d -exec chmod 755 {} +; find /certs -type f -exec chmod 444 {} +'])
        config=json.loads(run(['docker','compose','--file','docker-compose.yml','config','--format','json'],cwd=base))
        inputs=root/'generated-input';inputs.mkdir(mode=0o755)
        (inputs/'auth.log').touch(mode=0o444)
        settings=base/'config/wazuh_cluster/wazuh_manager.conf'
        text=settings.read_text()
        before,closing=text.rsplit('</ossec_config>',1)
        settings.write_text(before+'<localfile><log_format>syslog</log_format><location>/var/log/gabriel-lab/auth.log</location></localfile>\n</ossec_config>'+closing)
        config['services']['wazuh.manager']['volumes'].append({'type':'bind','source':str(inputs),'target':'/var/log/gabriel-lab','read_only':True})
        dashboard_password=secret();api_password=secret()
        PHASE='wazuh_private_accounts'
        def bcrypt(value):
            raw=run(['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--entrypoint','htpasswd',hasher,'-niBC','12','generated'],data=(value+'\n').encode()).decode().strip()
            result=raw.split(':',1)[1]
            if re.fullmatch(r'\$2[aby]\$12\$[./A-Za-z0-9]{53}',result) is None: raise ValueError('invalid_password_hash')
            return result
        users={'_meta':{'type':'internalusers','config_version':2},
            'admin':{'hash':bcrypt(owner_password),'reserved':True,'backend_roles':['admin']},
            'kibanaserver':{'hash':bcrypt(dashboard_password),'reserved':True}}
        (base/'config/wazuh_indexer/internal_users.yml').write_text(json.dumps(users))
        (base/'config/wazuh_indexer/internal_users.yml').chmod(0o444)
        settings=base/'config/wazuh_dashboard/wazuh.yml'
        text=settings.read_text();text,n=re.subn(r'(?m)^(\s+password:) .+$',lambda m:m[1]+' '+json.dumps(api_password),text)
        if n!=1: raise ValueError('unexpected_api_configuration')
        settings.write_text(text);settings.chmod(0o444)
        for service in config['services'].values():
            env=service.get('environment',{})
            for key in ('INDEXER_PASSWORD','API_PASSWORD','DASHBOARD_PASSWORD'):
                if key in env: env[key]={'INDEXER_PASSWORD':owner_password,'API_PASSWORD':api_password,'DASHBOARD_PASSWORD':dashboard_password}[key]
        for mount in config['services']['wazuh.dashboard']['volumes']:
            if mount['target']=='/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem': mount['source']=str(root/'tls/server.pem')
            if mount['target']=='/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem': mount['source']=str(root/'tls/server.key')
        config['networks']={'private':{'internal':True},'entry':{}}
        for service in config['services'].values(): service['networks']={'private':{}}
        config['services']['wazuh.dashboard']['networks']={'private':{},'entry':{}}
        entry='wazuh.dashboard'
    PHASE='image_resolution'
    images={}
    for name,service in config['services'].items():
        original=service['image']
        if original not in images:
            digest,identity=image(original);images[original]={'digest':digest,'image_id':identity}
        service['image']=images[original]['digest'];service['pull_policy']='never'
        service.pop('container_name',None);service.pop('ports',None);service.pop('restart',None);service.pop('links',None)
        service['restart']='no'
        service['mem_limit']={'wazuh.indexer':'3g','wazuh.manager':'2g','wazuh.dashboard':'2g','app':'2g','worker':'1g','db':'1g','rabbitmq':'512m','nginx':'256m'}[name]
        service['pids_limit']=1024
        service['cpus']=2
        for mount in service.get('volumes',[]):
            if mount['type']!='bind': continue
            path=Path(mount['source'])
            if root not in path.resolve().parents: raise ValueError('mount_outside_generated_lab')
            paths=[path,*path.rglob('*')] if path.is_dir() else [path]
            for item in paths:
                if item.is_symlink(): raise ValueError('unexpected_mount_symlink')
                if item.stat().st_uid==os.getuid(): item.chmod(0o755 if item.is_dir() else 0o444)
    config['services'][entry]['ports']=[{'host_ip':'127.0.0.1','published':str(port),'target':port if tool=='iris' else 5601,'protocol':'tcp'}]
    config.pop('name',None)
    for network in config['networks'].values(): network.pop('name',None)
    for volume in config.get('volumes',{}).values(): volume.pop('name',None)
    write(root/'compose.json',config)
    manifest=dict(schema_version=1,tool=tool,project=project,upstream_commit=commit,upstream_tag=tag,port=port,images=images,
        resolved_images=RESOLVED,
        compose_sha256=sha256((root/'compose.json').read_bytes()).hexdigest(),production_admitted=False,gabriel_adapter_admitted=False)
    write(root/'lab.json',manifest)
    return manifest


def ready(root):
    info=json.loads((root/'lab.json').read_text())
    context=ssl.create_default_context(cafile=str(root/'tls/server.pem'))
    limit=time.monotonic()+480
    while time.monotonic()<limit:
        connection=http.client.HTTPSConnection('localhost',info['port'],context=context,timeout=5)
        try:
            connection.request('GET','/login' if info['tool']=='iris' else '/app/login')
            response=connection.getresponse();body=response.read(262144).decode(errors='replace')
            if response.status==200 and ('password' in body.lower() or info['tool']=='wazuh' and any(x in body.lower() for x in ('opensearch','wazuh'))): return {'trusted_https':True}
        except (OSError,ssl.SSLError,http.client.HTTPException): pass
        finally: connection.close()
        time.sleep(2)
    raise ValueError('console_https_readiness_timeout')


def replay(root):
    """A generated log replay checks collection; it does not execute an attack."""
    info=json.loads((root/'lab.json').read_text())
    if info['tool']!='wazuh': raise ValueError('wazuh_replay_only')
    if (root/'replay.json').exists(): raise ValueError('replay_already_recorded')
    limit=time.monotonic()+120
    while time.monotonic()<limit:
        # Upstream status exits 1 when an optional daemon (e.g. clustering) is stopped.
        status=json.loads(compose(root,'exec','-T','wazuh.manager','/var/ossec/bin/wazuh-control','-j','status',accepted=(0,1)))
        if status.get('error')!=0 or type(status.get('data')) is not list: raise ValueError('invalid_daemon_status')
        states={item['daemon']:item['status'] for item in status['data']}
        if all(states.get(name)=='running' for name in ('wazuh-logcollector','wazuh-analysisd')): break
        time.sleep(2)
    else: raise ValueError('wazuh_collection_not_ready')
    marker='gabriel-lab-'+uuid4().hex[:12]
    started=datetime.now(timezone.utc).isoformat()
    # The collector opens this fresh lab's file at startup; wait for its first scan.
    time.sleep(5)
    path=root/'generated-input/auth.log'
    path.chmod(0o600)
    try:
        with path.open('a') as stream:
            for number in range(12):
                stamp=datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')
                stream.write(f'{stamp} generated-lab sshd[{20000+number}]: Failed password for invalid user {marker} from 192.0.2.10 port {40000+number} ssh2\n')
                stream.flush();os.fsync(stream.fileno())
                time.sleep(.2)
    finally: path.chmod(0o444)
    limit=time.monotonic()+180
    alerts={}
    while time.monotonic()<limit:
        raw=compose(root,'exec','-T','wazuh.manager','sh','-c','if test -f /var/ossec/logs/alerts/alerts.json; then tail -c 4194304 /var/ossec/logs/alerts/alerts.json; fi')
        for line in raw.splitlines():
            try: event=json.loads(line)
            except ValueError: continue
            if marker not in event.get('full_log','') or event.get('location')!='/var/log/gabriel-lab/auth.log': continue
            if not event.get('id') or not event.get('rule',{}).get('id'): continue
            alerts[event['id']]={'id':event['id'],'timestamp':event['timestamp'],'rule_id':event['rule']['id'],
                'rule_level':event['rule'].get('level'),'decoder':event.get('decoder',{}).get('name')}
        if alerts: break
        time.sleep(2)
    if not alerts: raise ValueError('generated_replay_not_collected')
    report=dict(schema_version=1,kind='synthetic_syslog_replay',live_attack=False,endpoint_sensor_verified=False,
        browser_capture_verified=False,indexer_forwarding_verified=False,tool='wazuh',marker=marker,emitted_records=12,
        observed_alerts=list(alerts.values()),started_at=started,first_observed_at=datetime.now(timezone.utc).isoformat(),
        required_daemons={name:states[name] for name in ('wazuh-logcollector','wazuh-analysisd')},
        inactive_optional_daemons=sorted(name for name,state in states.items() if state!='running'),
        source_sha256=sha256(path.read_bytes()).hexdigest())
    write(root/'replay.json',report)
    return {'synthetic_replay_collected':True,'observed_alert_count':len(alerts)}


def analyst(root):
    """Provision a case-scoped viewer only in the generated IRIS lab."""
    info=json.loads((root/'lab.json').read_text())
    if info['tool']!='iris': raise ValueError('iris_analyst_only')
    if (root/'analyst-credentials.json').exists(): raise ValueError('analyst_already_prepared')
    if sha256((root/'compose.json').read_bytes()).hexdigest()!=info['compose_sha256']: raise ValueError('configuration_changed')
    config=json.loads((root/'compose.json').read_text())
    owner_key=config['services']['app']['environment']['IRIS_ADM_API_KEY']
    context=ssl.create_default_context(cafile=str(root/'tls/server.pem'))
    def request(method,path,key,payload=None,expected=200):
        connection=http.client.HTTPSConnection('localhost',info['port'],context=context,timeout=30)
        try:
            connection.request(method,path,body=json.dumps(payload) if payload is not None else None,
                headers={'X-IRIS-AUTH':key,'Content-Type':'application/json'})
            response=connection.getresponse();value=json.loads(response.read(1048576))
            if response.status!=expected or value.get('status')!=('success' if expected==200 else 'error'):
                raise ValueError('iris_analyst_permission_check_failed')
            return value.get('data')
        finally: connection.close()
    username='gabriel-viewer-'+uuid4().hex[:10];password=secret()
    user=request('POST','/manage/users/add',owner_key,dict(user_name=username,user_login=username,
        user_email=username+'@example.invalid',user_password=password,user_isadmin=False,user_is_service_account=False,active=True))
    user_id=user['id'];viewer_key=user['user_api_key'];PRIVATE.append(viewer_key)
    if type(user_id) is not int: raise ValueError('invalid_generated_user_id')
    group=request('POST','/manage/groups/add',owner_key,dict(group_name=username,group_description='Generated case-scoped lab viewer',
        group_permissions=[1],group_auto_follow=False,group_auto_follow_access_level=1))
    if group['group_permissions']!=1 or type(group['group_id']) is not int: raise ValueError('unexpected_viewer_permissions')
    request('POST',f'/manage/users/{user_id}/groups/update',owner_key,{'groups_membership':[group['group_id']]})
    request('POST',f'/manage/users/{user_id}/cases-access/update',owner_key,{'cases_list':[1],'access_level':2})
    summary=request('GET','/case/summary/fetch?cid=1',viewer_key)
    request('POST','/case/summary/update?cid=1',viewer_key,{'case_description':summary['case_description']},expected=403)
    request('GET','/manage/users/list',viewer_key,expected=403)
    if request('GET','/case/summary/fetch?cid=1',owner_key)!=summary: raise ValueError('readonly_case_changed')
    write(root/'analyst-credentials.json',dict(tool='iris',username=username,password=password,port=info['port'],case_id=1))
    write(root/'analyst-access.json',dict(schema_version=1,tool='iris',username=username,user_id=user_id,case_id=1,
        group_permissions=1,case_access_level=2,case_read_http=200,case_write_http=403,admin_read_http=403,
        case_summary_unchanged=True,browser_session_verified=False,gabriel_adapter_admitted=False))
    return {'generated_case_viewer_prepared':True,'case_write_denied':True,'admin_read_denied':True}


def main():
    global PHASE
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','up','check','replay','analyst','down'))
    parser.add_argument('tool',choices=tuple(PINS))
    parser.add_argument('directory',type=Path)
    args=parser.parse_args();os.umask(0o077)
    try:
        root=args.directory.absolute()
        if args.command=='prepare': prepare(args.tool,root);result={'prepared':True}
        else:
            if json.loads((root/'lab.json').read_text())['tool']!=args.tool: raise ValueError('lab_mismatch')
            PRIVATE.append(json.loads((root/'credentials.json').read_text())['password'])
            for service in json.loads((root/'compose.json').read_text())['services'].values():
                for key,value in service.get('environment',{}).items():
                    if any(word in key for word in ('PASSWORD','SECRET','SALT','API_KEY','BROKER')) and isinstance(value,str): PRIVATE.append(value)
            if args.command=='up': PHASE='startup';compose(root,'up','-d');result=ready(root)
            elif args.command=='check': result=ready(root)
            elif args.command=='replay': PHASE='generated_replay';result=replay(root)
            elif args.command=='analyst': PHASE='generated_analyst';result=analyst(root)
            else: compose(root,'down','--volumes','--remove-orphans');result={'generated_lab_removed':True}
        print(json.dumps({'status':'ok','result':result,'production_admitted':False}))
        return 0
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.SubprocessError) as exc:
        print('FAIL: console lab '+PHASE+' ('+type(exc).__name__+')',flush=True)
        if isinstance(exc,RuntimeError): print(str(exc),flush=True)
        return 1


if __name__=='__main__': raise SystemExit(main())
