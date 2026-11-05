#!/usr/bin/env python3
"""Local Docker test installation controller. Requires Python 3 and Docker Compose v2."""
import argparse
import fcntl
import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from uuid import UUID,uuid4

from gabriel_identity_prepare import prepare as database_secrets
from gabriel_provider_keys import prepare as keyring

REPO=Path(__file__).resolve().parents[2]
COMPOSE=REPO/'compose.gabriel-installation.yml'
NETWORK_CHECK="""import json,socket
result={'version':'gabriel-install-network-v1','dns_resolves':False,'tcp_reachable':False}
try:
    addresses=socket.getaddrinfo('identity-db',5432,socket.AF_INET,socket.SOCK_STREAM)
    result['dns_resolves']=bool(addresses)
    if addresses:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(addresses[0][4])
        result['tcp_reachable']=True
except OSError:
    pass
print(json.dumps(result))
"""


class InstallationNetworkError(ValueError):
    def __init__(self,phase):
        self.phase=phase
        super().__init__('installation_network_check_failed: '+phase)


class DockerOperationError(ValueError):
    def __init__(self,completed):
        super().__init__('docker_operation_failed; inspect the local Docker service and installation state')
        self.stdout=completed.stdout
        self.stderr=completed.stderr


def run(command,*,env=None,payload=None,output=None,timeout=None):
    completed=subprocess.run(command,cwd=REPO,env=env,input=payload,stdout=output if output is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,check=False,timeout=timeout)
    if completed.returncode:
        try:
            diagnostic=json.loads(completed.stdout or b'{}')
            if diagnostic.get('code')=='installation_operation_denied':
                phase=diagnostic.get('phase','unknown');kind=diagnostic.get('kind','unknown')
                if re.fullmatch(r'[a-z_]{1,64}',phase) and re.fullmatch(r'[A-Za-z]{1,64}',kind):
                    raise ValueError('installation denied at '+phase+' ('+kind+'); no secret values logged')
        except (json.JSONDecodeError,UnicodeError): pass
        raise DockerOperationError(completed)
    return completed.stdout


def write(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())


def private(path):
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid!=os.getuid():
        raise ValueError('operator_owned_private_directory_required')


def read(path,*,private_file=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & (0o077 if private_file else 0o022)
                or private_file and info.st_uid!=os.getuid()): raise ValueError('unsafe_configuration_file')
        data=stream.read(65537)
    if len(data)>65536: raise ValueError('configuration_limit')
    from gabriel_provider_keys import unique
    return json.loads(data,object_pairs_hook=unique)


def external(path):
    path=Path(path).absolute()
    if path!=path.resolve() or path==REPO or REPO in path.parents or '\n' in str(path) or '$' in str(path):
        raise ValueError('absolute_external_directory_without_links_required')
    return path


def read_controls(path):
    path=external(path)
    private(path.parent)
    return read(path,private_file=True)


def prepare_tls(directory,image):
    directory.mkdir(mode=0o700)
    run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--user',str(os.getuid())+':'+str(os.getgid()),'--mount','type=bind,src='+str(directory)+',dst=/tls',
        '--entrypoint','python',image,'-m','gabriel.identity.installation','tls','--directory','/tls'])


def prepare(root,port,image):
    if root.exists() or type(port) is not int or not 1024<=port<=65535: raise ValueError('new_directory_and_local_port_required')
    run(['docker','info'])
    run(['docker','compose','version'])
    image=build_image(image)
    root.mkdir(mode=0o700)
    database_secrets(root/'database')
    keyring(root/'provider')
    keyring(root/'evidence',purpose='evidence-v1')
    prepare_tls(root/'tls',image)
    manifest=dict(schema_version=1,purpose='gabriel-local-test-installation-v1',project='gabriel-install-'+uuid4().hex[:16],
        port=port,image=image,source=run(['git','rev-parse','HEAD']).decode().strip(),production_admitted=False)
    write(root/'installation.json',manifest)
    return manifest


class Installation:
    def __init__(self,root):
        private(root)
        self.root=root
        self.config=read(root/'installation.json')
        c=self.config
        if (set(c)!={'schema_version','purpose','project','port','image','source','production_admitted'} or c['schema_version']!=1
                or c['purpose']!='gabriel-local-test-installation-v1' or c['production_admitted'] is not False
                or re.fullmatch(r'gabriel-install-[a-f0-9]{16}',c['project']) is None
                or re.fullmatch(r'sha256:[a-f0-9]{64}',c['image']) is None
                or re.fullmatch(r'[a-f0-9]{40}',c['source']) is None or type(c['port']) is not int or not 1024<=c['port']<=65535):
            raise ValueError('invalid_installation')
        self.env=dict(os.environ,GABRIEL_INSTALL_ROOT=str(root),GABRIEL_INSTALL_PORT=str(c['port']),GABRIEL_INSTALL_IMAGE=c['image'],GABRIEL_HERMES_IMAGE=c['project']+'-hermes:local')
        self.command=['docker','compose','--project-name',c['project'],'--file',str(COMPOSE)]

    def compose(self,*args,payload=None,output=None,timeout=None):
        return run(self.command+list(args),env=self.env,payload=payload,output=output,timeout=timeout)

    def check_network(self):
        name=self.config['project']+'-network-check'
        try:
            raw=self.compose('run','--rm','--no-deps','-T','--name',name,
                'network-check','-c',NETWORK_CHECK,timeout=30)
        except subprocess.TimeoutExpired:
            try: run(['docker','rm','--force',name],timeout=10)
            except (OSError,ValueError,subprocess.SubprocessError): pass
            raise InstallationNetworkError('probe_timeout') from None
        except DockerOperationError:
            raise InstallationNetworkError('probe_execution') from None
        try: report=json.loads(raw)
        except (ValueError,UnicodeError): raise InstallationNetworkError('invalid_probe_result') from None
        if (type(report) is not dict or set(report)!={'version','dns_resolves','tcp_reachable'}
                or report['version']!='gabriel-install-network-v1'
                or type(report['dns_resolves']) is not bool or type(report['tcp_reachable']) is not bool
                or (report['tcp_reachable'] and not report['dns_resolves'])):
            raise InstallationNetworkError('invalid_probe_result')
        if not report['dns_resolves']: raise InstallationNetworkError('database_dns')
        if not report['tcp_reachable']: raise InstallationNetworkError('database_tcp')
        return report

    def operator(self,command,payload=None):
        service='browser-operator' if command in {'browser-open','browser-stop'} else 'operator'
        raw=self.compose('run','--rm','--no-deps','-T',service,command,
            payload=json.dumps(payload).encode() if payload is not None else None)
        value=json.loads(raw)
        if value.get('status')!='ok': raise ValueError('operator_operation_denied')
        return value['result']

    def start_db(self): self.compose('up','-d','--wait','identity-db')

    def browser_image_supported(self):
        image=json.loads(run(['docker','image','inspect',self.config['image']]))[0]
        return (image.get('Config',{}).get('Labels') or {}).get('org.gabriel.browser-installation')=='v1'

    def browser_state(self):
        from datetime import datetime
        value=read(self.root/'browser.json')
        if (set(value)!={'port','lease_id','task_id','case_id','endpoint','expires_at'}
                or type(value['port']) is not int or not 1024<=value['port']<=65535
                or value['port']==self.config['port'] or value['endpoint']!='https://localhost:'+str(value['port'])
                or any(str(UUID(value[n]))!=value[n] for n in ('lease_id','task_id','case_id'))
                or datetime.fromisoformat(value['expires_at']).tzinfo is None):
            raise ValueError('invalid_browser_installation_state')
        return value

    def browser_stop(self):
        # Close the published listener first, even when PostgreSQL or human authority is gone.
        self.compose('rm','-sf','browser-entry','browser-gateway')
        if (self.root/'browser.json').exists():(self.root/'browser.json').unlink()
        if not self.browser_image_supported():
            return {'listener_stopped':True,'revocation_confirmed':False,'browser_image_supported':False}
        try:
            self.start_db()
            result=self.operator('browser-stop')
        except (DockerOperationError,ValueError):result={'revocation_confirmed':False}
        return dict(listener_stopped=True,**result)

    def browser_open(self,case_id,context,origin,*,port=8443,duration=300,max_steps=20,share_observations=False,control_plan=None,approve_controls=False):
        if type(port) is not int or not 1024<=port<=65535 or port==self.config['port']:
            raise ValueError('distinct_loopback_browser_port_required')
        if control_plan is not None:
            if not approve_controls or not share_observations:raise ValueError('explicit_controls_and_sharing_approval_required')
            labels=json.loads(run(['docker','image','inspect',self.config['image'],'--format','{{json .Config.Labels}}']))
            if not isinstance(labels,dict) or labels.get('org.gabriel.browser-controls')!='v1':raise ValueError('controls_image_rebuild_required')
        elif approve_controls:raise ValueError('control_plan_required')
        previous=self.browser_stop()
        if not self.browser_image_supported():raise ValueError('rebuild_required_for_browser_installation')
        if not previous['revocation_confirmed']:raise ValueError('browser_revocation_unconfirmed; retry browser-stop before enrollment')
        self.start_db()
        self.check_network()
        payload=dict(case_id=case_id,context=context,extension_origin=origin,
            port=port,duration=duration,max_steps=max_steps,share_observations=share_observations)
        if control_plan is not None:payload['control_plan']=control_plan
        result=self.operator('browser-open',payload)
        state={k:v for k,v in result.items() if k!='ticket'}
        try:
            write(self.root/'browser.json',dict(state,port=port))
            self.env.update(GABRIEL_BROWSER_PORT=str(port),GABRIEL_BROWSER_EXPIRES_AT=result['expires_at'])
            self.compose('up','-d','--wait','--force-recreate','browser-gateway','browser-entry')
        except Exception:
            try:self.browser_stop()
            except Exception:pass
            raise
        return dict(result,listener_loopback_only=True,sharing_approved=share_observations,previous_browser_stop=previous)

    def stop(self):
        self.compose('stop','local-entry','workbench')
        browser=self.browser_stop()
        try:
            self.start_db()
            self.operator('revoke')
        finally:self.compose('stop','hermes','investigation-tools','identity-db')
        return browser

    def open(self,password,*,ai_egress=False,username=None):
        if type(ai_egress) is not bool:raise ValueError('invalid_ai_egress_option')
        self.compose('stop','local-entry','workbench')
        browser=self.browser_stop()
        self.command=['docker','compose','--project-name',self.config['project'],'--file',str(COMPOSE)]
        if ai_egress:self.command.extend(['--file',str(REPO/'compose.gabriel-specialist-ai.yml')])
        self.start_db()
        self.check_network()
        payload=dict(password=password,port=self.config['port'])
        if username is not None:payload['username']=username
        ticket=self.operator('open',payload)
        self.compose('build','hermes')
        self.compose('up','-d','--wait','--force-recreate','workbench','local-entry')
        return dict(endpoint='https://localhost:'+str(self.config['port'])+'/claim',ai_egress=ai_egress,browser_stop=browser,**ticket)

    def backup(self,destination):
        if destination.exists(): raise ValueError('new_backup_directory_required')
        destination.mkdir(mode=0o700)
        self.compose('stop','local-entry','workbench')
        browser=self.browser_stop()
        self.start_db()
        self.operator('revoke')
        receipt=self.operator('receipt')
        with (destination/'database.dump').open('xb') as stream:
            self.compose('exec','-T','identity-db','pg_dump','-U','postgres','-d','gabriel','--format=custom',output=stream)
        with (destination/'evidence.tar.gz').open('xb') as stream:
            self.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',
                "import sys,tarfile\nwith tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as archive: archive.add('/var/lib/gabriel-evidence',arcname='.')\n",output=stream)
        manifest=dict(schema_version=1,purpose='gabriel-quiesced-test-backup-v1',image=self.config['image'],source=self.config['source'],
            identity=receipt,files={name:digest(destination/name) for name in ('database.dump','evidence.tar.gz')},
            key_fingerprints={name:digest(self.root/name/'keyring.json') for name in ('provider','evidence')})
        write(destination/'backup.json',manifest)
        return {'backup_complete':True,'workbench_stopped':True,'keys_included':False,'browser_stop':browser}


    def renew_tls(self):
        labels=json.loads(run(['docker','image','inspect',self.config['image'],'--format','{{json .Config.Labels}}']))
        if not isinstance(labels,dict) or labels.get('org.gabriel.tls-profile')!='rfc5280-strict-v1':
            raise ValueError('strict_tls_image_rebuild_required')
        if len(list(self.root.glob('tls-retired-*')))+len(list(self.root.glob('tls-pending-*')))>=16:
            raise ValueError('tls_history_limit_requires_operator_review')
        self.compose('stop','local-entry','workbench')
        browser=self.browser_stop()
        if not browser.get('revocation_confirmed'):
            raise ValueError('browser_revocation_unconfirmed')
        self.start_db()
        self.check_network()
        self.operator('revoke')
        directory=self.root/('tls-pending-'+uuid4().hex)
        prepare_tls(directory,self.config['image'])
        previous=digest(self.root/'tls/ca.pem')
        current=digest(directory/'ca.pem')
        retired=self.root/('tls-retired-'+uuid4().hex)
        os.rename(self.root/'tls',retired)
        try: os.rename(directory,self.root/'tls')
        except OSError:
            os.rename(retired,self.root/'tls')
            raise
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        return dict(tls_renewed=True,previous_ca_file_sha256=previous,ca_file_sha256=current,
            certificate_trust_requires_review=True,requires_fresh_login=True,
            workbench_stopped=True,browser_stop=browser,production_admitted=False)

    def rebuild(self,backup,image=None):
        self.compose('stop','local-entry','workbench')
        self.browser_stop()
        if len(list(self.root.glob('rebuild-*.json')))>=32:
            raise ValueError('rebuild_history_limit_requires_operator_review')
        candidate=build_image(image)
        readiness=json.loads(run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--entrypoint','python',candidate,
            '-m','gabriel.identity.gateway_cli','ai-readiness','--ai-model','openai/gpt-oss-120b']))
        if readiness.get('projection_version')!='browser-candidate-ai-v1':
            raise ValueError('browser_ai_installation_image_required')
        new=dict(self.config,image=candidate,source=run(['git','rev-parse','HEAD']).decode().strip())
        self.backup(backup)
        previous=read(backup/'backup.json')
        record=self.root/('rebuild-'+uuid4().hex+'.json')
        write(record,dict(previous=self.config,candidate=new,backup=str(backup),automatic_rollback=False))
        temporary=self.root/('pending-'+uuid4().hex+'.json')
        write(temporary,new)
        os.replace(temporary,self.root/'installation.json')
        parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
        rebuilt=Installation(self.root)
        rebuilt.check_network()
        program="""import os,json
from gabriel.identity.cli import read_secret
from gabriel.identity.service import migrate
migrate(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']))
print(json.dumps({'migrated':True}))
"""
        migrated=json.loads(rebuilt.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',program))
        if migrated!={'migrated':True} or rebuilt.operator('receipt')!=previous['identity']:
            raise ValueError('rebuild_identity_verification_failed')
        if any(digest(self.root/name/'keyring.json')!=value for name,value in previous['key_fingerprints'].items()):
            raise ValueError('rebuild_key_identity_changed')
        return dict(rebuilt=True,image=candidate,source=new['source'],backup=str(backup),
            original_identity_retained=True,original_keys_retained=True,requires_fresh_login=True,
            production_admitted=False,browser_ai=readiness)

    def restore(self,backup,keys):
        private(backup);private(keys)
        manifest=read(backup/'backup.json')
        if (set(manifest)!={'schema_version','purpose','image','source','identity','files','key_fingerprints'}
                or manifest['schema_version']!=1 or manifest['purpose']!='gabriel-quiesced-test-backup-v1'
                or manifest['image']!=self.config['image'] or manifest['source']!=self.config['source']
                or set(manifest['files'])!={'database.dump','evidence.tar.gz'} or set(manifest['key_fingerprints'])!={'provider','evidence'}):
            raise ValueError('matching_source_backup_required')
        for name,value in manifest['files'].items():
            if (backup/name).stat().st_size>128*1024*1024: raise ValueError('test_backup_restore_limit')
            if digest(backup/name)!=value: raise ValueError('backup_digest_mismatch')
        for name,value in manifest['key_fingerprints'].items():
            if digest(keys/name/'keyring.json')!=value: raise ValueError('original_keys_required')
        # No service or volume may already exist in a fresh restore target.
        if self.compose('ps','--all','--quiet').strip() or run(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+self.config['project']]).strip():
            raise ValueError('fresh_restore_target_required')
        for name in ('provider','evidence'):
            target=self.root/name/'keyring.json'
            target.chmod(0o600)
            with target.open('wb') as stream: stream.write((keys/name/'keyring.json').read_bytes())
            target.chmod(0o444)
        self.start_db()
        self.check_network()
        self.compose('exec','-T','identity-db','pg_restore','-U','postgres','--dbname=gabriel','--exit-on-error','--single-transaction',payload=(backup/'database.dump').read_bytes())
        raw=self.compose('run','--rm','--no-deps','-T','operator','restore-objects',payload=(backup/'evidence.tar.gz').read_bytes())
        if json.loads(raw).get('status')!='ok': raise ValueError('object_restore_denied')
        self.operator('restore-receipt',manifest['identity'])
        return {'restored':True,'requires_fresh_login':True,'production_admitted':False}


def build_image(image):
    if image is None:
        image=run(['docker','build','--quiet','-f','gabriel/identity/Dockerfile','--target','production','.']).decode().strip().splitlines()[-1]
    if re.fullmatch(r'sha256:[a-f0-9]{64}',image) is None: raise ValueError('exact_local_image_id_required')
    inspected=json.loads(run(['docker','image','inspect',image]))[0]
    if inspected['Config']['User']!='10001:10001': raise ValueError('non_root_image_required')
    return image


def digest(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode): raise ValueError('regular_file_required')
    value=sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): value.update(block)
    return value.hexdigest()


def password(args):
    if args.password_file:
        path=Path(args.password_file)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077: raise ValueError('private_password_file_required')
            raw=stream.read(1025)
        if len(raw)>1024: raise ValueError('password_limit')
        return raw.decode().removesuffix('\n')
    return getpass.getpass('Your Gabriel owner password: ')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','initialize','open','status','stop','backup','restore','rebuild','diagnose','browser-open','browser-stop','renew-tls'))
    parser.add_argument('directory')
    parser.add_argument('--port',type=int,default=8444)
    parser.add_argument('--image')
    parser.add_argument('--organization',default='Gabriel private lab')
    parser.add_argument('--username')
    parser.add_argument('--password-file')
    parser.add_argument('--backup')
    parser.add_argument('--keys-from')
    parser.add_argument('--ai-egress',action='store_true',help='Allow the opened workbench to reach its fixed AI provider; requires qualified configuration and own key')
    parser.add_argument('--case-id')
    parser.add_argument('--context-file')
    parser.add_argument('--extension-origin')
    parser.add_argument('--gateway-port',type=int,default=8443)
    parser.add_argument('--duration',type=int,default=300)
    parser.add_argument('--max-steps',type=int,default=20)
    parser.add_argument('--approve-observation-sharing',action='store_true')
    parser.add_argument('--controls-file')
    parser.add_argument('--approve-browser-controls',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    try:
        if bool(args.controls_file)!=args.approve_browser_controls or args.controls_file and args.command!='browser-open':raise ValueError('explicit_browser_controls_approval_required')
        if args.ai_egress and args.command!='open':raise ValueError('ai_egress_only_for_open')
        root=external(args.directory)
        if args.command=='prepare': result=prepare(root,args.port,args.image)
        else:
            installation=Installation(root)
            fd=os.open(root/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                if args.command=='initialize':
                    installation.start_db()
                    installation.check_network()
                    secret=password(args)
                    result=installation.operator('initialize',dict(organization=args.organization,username=args.username or 'owner',password=secret))
                elif args.command=='diagnose':
                    installation.start_db()
                    result=dict(network=installation.check_network(),production_admitted=False)
                elif args.command=='open':
                    installation.compose('stop','local-entry','workbench')
                    installation.browser_stop()
                    result=installation.open(password(args),ai_egress=args.ai_egress,username=args.username)
                elif args.command=='browser-open':
                    context_path=external(args.context_file)
                    private(context_path.parent)
                    result=installation.browser_open(args.case_id,read(context_path),args.extension_origin,
                        port=args.gateway_port,duration=args.duration,max_steps=args.max_steps,
                        share_observations=args.approve_observation_sharing,
                        control_plan=read_controls(args.controls_file) if args.controls_file else None,approve_controls=args.approve_browser_controls)
                elif args.command=='browser-stop':result=installation.browser_stop()
                elif args.command=='renew-tls':result=installation.renew_tls()
                elif args.command=='status':
                    raw=installation.compose('ps','--all','--format','json').decode().strip()
                    rows=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines()]
                    result=dict(services=rows,production_admitted=False)
                elif args.command=='stop': result=dict(stopped=True,volumes_retained=True,browser_stop=installation.stop())
                elif args.command=='backup': result=installation.backup(external(args.backup))
                elif args.command=='rebuild': result=installation.rebuild(external(args.backup),args.image)
                else: result=installation.restore(external(args.backup),external(args.keys_from))
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except InstallationNetworkError as exc:
        print(json.dumps({'status':'denied','code':'installation_network_check_failed','phase':exc.phase,
            'probe_uses_credentials':False,'guidance':'Inspect Docker DNS, bridge connectivity and firewall backend consistency; preserve internal networks and loopback listeners.'}))
        return 1
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError):
        print(json.dumps({'status':'denied','code':'installation_command_failed; existing state retained for inspection'}))
        return 1


if __name__=='__main__': raise SystemExit(main())



