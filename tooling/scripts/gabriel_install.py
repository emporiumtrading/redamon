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
from uuid import uuid4

from gabriel_identity_prepare import prepare as database_secrets
from gabriel_provider_keys import prepare as keyring

REPO=Path(__file__).resolve().parents[2]
COMPOSE=REPO/'compose.gabriel-installation.yml'


class DockerOperationError(ValueError):
    def __init__(self,completed):
        super().__init__('docker_operation_failed; inspect the local Docker service and installation state')
        self.stdout=completed.stdout
        self.stderr=completed.stderr


def run(command,*,env=None,payload=None,output=None):
    completed=subprocess.run(command,cwd=REPO,env=env,input=payload,stdout=output if output is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,check=False)
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


def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022: raise ValueError('unsafe_configuration_file')
        data=stream.read(65537)
    if len(data)>65536: raise ValueError('configuration_limit')
    from gabriel_provider_keys import unique
    return json.loads(data,object_pairs_hook=unique)


def external(path):
    path=Path(path).absolute()
    if path!=path.resolve() or path==REPO or REPO in path.parents or '\n' in str(path) or '$' in str(path):
        raise ValueError('absolute_external_directory_without_links_required')
    return path


def prepare(root,port,image):
    if root.exists() or type(port) is not int or not 1024<=port<=65535: raise ValueError('new_directory_and_local_port_required')
    run(['docker','info'])
    run(['docker','compose','version'])
    if image is None:
        image=run(['docker','build','--quiet','-f','gabriel/identity/Dockerfile','--target','production','.']).decode().strip().splitlines()[-1]
    if re.fullmatch(r'sha256:[a-f0-9]{64}',image) is None: raise ValueError('exact_local_image_id_required')
    inspected=json.loads(run(['docker','image','inspect',image]))[0]
    if inspected['Config']['User']!='10001:10001': raise ValueError('non_root_image_required')
    root.mkdir(mode=0o700)
    database_secrets(root/'database')
    keyring(root/'provider')
    keyring(root/'evidence',purpose='evidence-v1')
    (root/'tls').mkdir(mode=0o700)
    run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--user',str(os.getuid())+':'+str(os.getgid()),'--mount','type=bind,src='+str(root/'tls')+',dst=/tls',
        '--entrypoint','python',image,'-m','gabriel.identity.installation','tls','--directory','/tls'])
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
        self.env=dict(os.environ,GABRIEL_INSTALL_ROOT=str(root),GABRIEL_INSTALL_PORT=str(c['port']),GABRIEL_INSTALL_IMAGE=c['image'])
        self.command=['docker','compose','--project-name',c['project'],'--file',str(COMPOSE)]

    def compose(self,*args,payload=None,output=None):
        return run(self.command+list(args),env=self.env,payload=payload,output=output)

    def operator(self,command,payload=None):
        raw=self.compose('run','--rm','--no-deps','-T','operator',command,
            payload=json.dumps(payload).encode() if payload is not None else None)
        value=json.loads(raw)
        if value.get('status')!='ok': raise ValueError('operator_operation_denied')
        return value['result']

    def start_db(self): self.compose('up','-d','--wait','identity-db')

    def stop(self):
        self.start_db()
        self.compose('stop','workbench')
        self.operator('revoke')
        self.compose('stop','identity-db')

    def open(self,password):
        self.start_db()
        self.compose('stop','workbench')
        ticket=self.operator('open',dict(password=password,port=self.config['port']))
        self.compose('up','-d','--wait','--force-recreate','workbench')
        return dict(endpoint='https://localhost:'+str(self.config['port'])+'/claim',**ticket)

    def backup(self,destination):
        if destination.exists(): raise ValueError('new_backup_directory_required')
        destination.mkdir(mode=0o700)
        self.start_db()
        self.compose('stop','workbench')
        self.operator('revoke')
        receipt=self.operator('receipt')
        with (destination/'database.dump').open('xb') as stream:
            self.compose('exec','-T','identity-db','pg_dump','-U','postgres','-d','gabriel','--format=custom',output=stream)
        with (destination/'evidence.tar.gz').open('xb') as stream:
            self.compose('run','--rm','--no-deps','-T','--entrypoint','tar','operator','-czf','-','-C','/var/lib/gabriel-evidence','.',output=stream)
        manifest=dict(schema_version=1,purpose='gabriel-quiesced-test-backup-v1',image=self.config['image'],source=self.config['source'],
            identity=receipt,files={name:digest(destination/name) for name in ('database.dump','evidence.tar.gz')},
            key_fingerprints={name:digest(self.root/name/'keyring.json') for name in ('provider','evidence')})
        write(destination/'backup.json',manifest)
        return {'backup_complete':True,'workbench_stopped':True,'keys_included':False}

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
        self.compose('exec','-T','identity-db','pg_restore','-U','postgres','--dbname=gabriel','--exit-on-error','--single-transaction',payload=(backup/'database.dump').read_bytes())
        raw=self.compose('run','--rm','--no-deps','-T','operator','restore-objects',payload=(backup/'evidence.tar.gz').read_bytes())
        if json.loads(raw).get('status')!='ok': raise ValueError('object_restore_denied')
        self.operator('restore-receipt',manifest['identity'])
        return {'restored':True,'requires_fresh_login':True,'production_admitted':False}


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
    parser.add_argument('command',choices=('prepare','initialize','open','status','stop','backup','restore'))
    parser.add_argument('directory')
    parser.add_argument('--port',type=int,default=8444)
    parser.add_argument('--image')
    parser.add_argument('--organization',default='Gabriel private lab')
    parser.add_argument('--username',default='owner')
    parser.add_argument('--password-file')
    parser.add_argument('--backup')
    parser.add_argument('--keys-from')
    args=parser.parse_args()
    os.umask(0o077)
    try:
        root=external(args.directory)
        if args.command=='prepare': result=prepare(root,args.port,args.image)
        else:
            installation=Installation(root)
            fd=os.open(root/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                if args.command=='initialize':
                    secret=password(args)
                    installation.start_db()
                    result=installation.operator('initialize',dict(organization=args.organization,username=args.username,password=secret))
                elif args.command=='open': result=installation.open(password(args))
                elif args.command=='status':
                    raw=installation.compose('ps','--all','--format','json').decode().strip()
                    rows=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines()]
                    result=dict(services=rows,production_admitted=False)
                elif args.command=='stop': installation.stop();result={'stopped':True,'volumes_retained':True}
                elif args.command=='backup': result=installation.backup(external(args.backup))
                else: result=installation.restore(external(args.backup),external(args.keys_from))
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError):
        print(json.dumps({'status':'denied','code':'installation_command_failed; existing state retained for inspection'}))
        return 1


if __name__=='__main__': raise SystemExit(main())
