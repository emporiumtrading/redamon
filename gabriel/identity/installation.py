"""Finite operator installation commands; never refreshes authority automatically."""
import argparse
from datetime import datetime,timedelta,timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import ssl
import sys
import re
import tarfile
import select
import socket
import socketserver
import signal
import subprocess
from threading import BoundedSemaphore
import time
from uuid import UUID,uuid4

from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.cli import read_secret
from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import AuthenticationDenied,IdentityError,connection,migrate,provision_organization,username
from gabriel.identity.workbench import prepare_workbench,serve_workbench

ROOT=Path('/var/lib/gabriel-workbench')
BROWSER_ROOT=Path('/var/lib/gabriel-browser')
PHASE='command'


def service():
    return CaseService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),
        LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE'])))


def publish(path,value):
    temporary=path.parent/('pending-'+uuid4().hex+'.json')
    write_document(temporary,value)
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def active():
    receipt=read_document(ROOT/'active.json',private=True)
    if set(receipt)!={'session'} or str(UUID(receipt['session']))!=receipt['session']: raise ValueError('invalid_session')
    return ROOT/receipt['session']


def tls(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
    directory=Path(directory)
    if not directory.is_dir() or any(directory.iterdir()): raise ValueError('new_tls_directory_required')
    now=datetime.now(timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Gabriel private test installation CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=31))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True).sign(ca_key,hashes.SHA256()))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]))
        .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),critical=True)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256()))
    values={'ca.pem':ca.public_bytes(serialization.Encoding.PEM),'server.pem':cert.public_bytes(serialization.Encoding.PEM),
        'server.key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())}
    for name,value in values.items():
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        with os.fdopen(fd,'wb') as stream: stream.write(value)
    # The signing key is intentionally not retained: this CA can only attest this installation.
    return {'certificate_days':30}


def initialize(payload):
    global PHASE
    if set(payload)!={'organization','username','password'}: raise ValueError('invalid_enrollment')
    owner=read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE'])
    PHASE='migration'
    migrate(owner)
    PHASE='empty_organization_check'
    with connection(owner,runtime=False) as conn:
        if conn.execute('SELECT count(*) AS n FROM gabriel_identity.organizations').fetchone()['n']:
            raise ValueError('already_initialized')
    PHASE='owner_creation'
    org,user=provision_organization(owner,payload['organization'],payload['username'],payload['password'])
    receipt={'organization_id':str(org),'user_id':str(user),'username':username(payload['username'])}
    PHASE='receipt_publication'
    write_document(ROOT/'installation.json',receipt)
    return receipt


def open_workbench(payload):
    if set(payload) not in ({'password','port'},{'password','port','username'}) or type(payload['port']) is not int or not 1024<=payload['port']<=65535:
        raise ValueError('invalid_open_request')
    receipt=read_document(ROOT/'installation.json',private=True)
    if sum(1 for p in ROOT.iterdir() if p.is_dir())>=128: raise ValueError('session_directory_limit')
    app=service()
    grant=app.login(receipt['organization_id'],payload.get('username',receipt['username']),payload['password'])
    directory=ROOT/str(uuid4())
    try:
        if (ROOT/'active.json').exists():
            previous=active()
            try: app.logout(read_document(previous/'human.json',private=True)['token'])
            except AuthenticationDenied: pass
        prepare_workbench(app,grant.token,'https://localhost:'+str(payload['port']),directory)
        publish(ROOT/'active.json',{'session':directory.name})
    except Exception:
        app.logout(grant.token)
        raise
    return {'ticket':read_document(directory/'claim.json',private=True)['ticket'],'session_seconds':600}


def browser_active():
    receipt=read_document(BROWSER_ROOT/'active.json',private=True)
    if set(receipt)!={'session'} or str(UUID(receipt['session']))!=receipt['session']:
        raise ValueError('invalid_browser_session')
    return BROWSER_ROOT/receipt['session']


def browser_service():
    from gabriel.identity.browser_navigation import BrowserNavigationService
    return BrowserNavigationService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']),
        LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE'])))


def open_browser(payload):
    from gabriel.identity.browser_gateway import prepare,extension_origin
    from gabriel.identity.browser_sessions import approved_context
    required={'case_id','context','extension_origin','port','duration','max_steps','share_observations'}
    if (set(payload) not in (required,required|{'control_plan'}) or type(payload['port']) is not int or not 1024<=payload['port']<=65535
            or type(payload['duration']) is not int or not 60<=payload['duration']<=300
            or type(payload['max_steps']) is not int or not 1<=payload['max_steps']<=1000
            or type(payload['share_observations']) is not bool):
        raise ValueError('invalid_browser_open_request')
    context=approved_context(payload['context'])
    control_plan=payload.get('control_plan')
    if control_plan is not None:
        from gabriel.identity.browser_controls import validate
        validate(control_plan,context)
        if not payload['share_observations'] or payload['max_steps']<len(control_plan['steps']):raise ValueError('controls_require_sharing_and_step_budget')
    origin=extension_origin(payload['extension_origin'])
    case_id=str(UUID(payload['case_id']))
    app=browser_service()
    if (BROWSER_ROOT/'active.json').exists():raise ValueError('browser_stop_required')
    token=read_document(active()/'human.json',private=True)['token']
    # The local operator command is explicit authorization; a saved token alone grants nothing.
    app.get_case(token,case_id)
    if sum(1 for p in BROWSER_ROOT.iterdir() if p.is_dir())>=128:raise ValueError('browser_directory_limit')
    task=app.create_browser_task(token,'Approved installation browser tab',payload['duration'],payload['max_steps'])
    directory=BROWSER_ROOT/str(uuid4())
    result=None
    try:
        result=prepare(app,token,str(task['id']),case_id,context,'https://localhost:'+str(payload['port']),origin,directory,
            share_observations=payload['share_observations'],control_plan=control_plan)
        write_document(directory/'task.json',{'task_id':str(task['id'])})
        publish(BROWSER_ROOT/'active.json',{'session':directory.name})
    except Exception:
        if result is not None:
            try:app.revoke_browser_lease(token,result['lease_id'])
            except IdentityError:pass
        from gabriel.identity.tasks import TaskService
        try:TaskService(app._dsn).end_task(token,task['id'],'cancelled')
        except IdentityError:pass
        raise
    return dict(lease_id=result['lease_id'],task_id=str(task['id']),case_id=case_id,endpoint=result['endpoint'],
        expires_at=result['expires_at'],ticket=read_document(directory/'claim.json',private=True)['ticket'])


def stop_browser():
    if not (BROWSER_ROOT/'active.json').exists():return {'revocation_confirmed':True,'lease_present':False}
    directory=browser_active()
    config=read_document(directory/'gateway.json',private=True)
    tokens=[read_document(directory/'human.json',private=True)['token']]
    try:
        current=read_document(active()/'human.json',private=True)['token']
        if current not in tokens:tokens.append(current)
    except (OSError,ValueError):pass
    from gabriel.identity.tasks import TaskService
    task=read_document(directory/'task.json',private=True)['task_id']
    app=browser_service()
    tasks=TaskService(app._dsn)
    confirmed=True
    for operation in (lambda token:app.revoke_browser_lease(token,config['lease_id']),
            lambda token:tasks.end_task(token,task,'cancelled')):
        complete=False
        for token in tokens:
            try:operation(token);complete=True;break
            except IdentityError:pass
        confirmed=confirmed and complete
    # Retain uncertain cleanup so a later explicit Stop can retry both operations honestly.
    if confirmed:(BROWSER_ROOT/'active.json').unlink()
    return {'revocation_confirmed':confirmed,'lease_present':True}


def remaining_browser_seconds(value):
    expiry=datetime.fromisoformat(value)
    if expiry.tzinfo is None:raise ValueError('browser_expiry_timezone_required')
    remaining=(expiry-datetime.now(timezone.utc)).total_seconds()
    if not 0<remaining<=300:raise ValueError('browser_lifetime_unavailable')
    return remaining


def serve_browser():
    config=browser_active()/'gateway.json'
    remaining=remaining_browser_seconds(read_document(config,private=True)['expires_at'])
    child=subprocess.Popen([sys.executable,'-m','gabriel.identity.gateway_cli','serve','--configuration',str(config),
        '--certificate','/run/secrets/tls_certificate','--key','/run/secrets/tls_key','--bind','0.0.0.0:8443'],start_new_session=True)
    def terminate(signum,frame):raise SystemExit(0)
    previous=signal.signal(signal.SIGTERM,terminate)
    try:
        try:
            if child.wait(timeout=remaining)!=0:raise ValueError('browser_gateway_failed')
        except subprocess.TimeoutExpired:pass
    finally:
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
        signal.signal(signal.SIGTERM,previous)


def browser_health():
    from urllib.parse import urlsplit
    config=read_document(browser_active()/'gateway.json',private=True)
    client=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl.create_default_context(cafile='/run/secrets/tls_ca'),timeout=3)
    try:
        client.request('GET','/v1/browser/status',headers={'Host':urlsplit(config['endpoint']).netloc})
        response=client.getresponse()
        if response.status!=403:raise ValueError('unauthenticated_browser_access_not_denied')
        response.read()
    finally:client.close()
    return {'https':True,'browser_authority_acceptance':False}


def health():
    directory=active()
    config=read_document(directory/'workbench.json',private=True)
    from urllib.parse import urlsplit
    client=http.client.HTTPSConnection('127.0.0.1',8444,context=ssl.create_default_context(cafile='/run/secrets/tls_ca'),timeout=3)
    try:
        client.request('GET','/cases',headers={'Host':urlsplit(config['endpoint']).netloc})
        response=client.getresponse()
        if response.status!=403: raise ValueError('unauthenticated_access_not_denied')
        response.read()
    finally: client.close()
    service().whoami(read_document(directory/'human.json',private=True)['token'])
    return {'https':True,'database_identity':True,'application_acceptance':False}


def restore_objects(stream):
    root=Path(os.environ['GABRIEL_EVIDENCE_ROOT'])
    if any(root.iterdir()): raise ValueError('empty_evidence_target_required')
    objects={}
    total=0
    with tarfile.open(fileobj=stream,mode='r|gz') as archive:
        for member in archive:
            if member.name=='.' and member.isdir(): continue
            if (not member.isfile() or re.fullmatch(r'\./[0-9a-f]{32}\.gbe',member.name) is None
                    or member.name in objects or not 29<=member.size<=128*1024+28 or len(objects)>=4096):
                raise ValueError('invalid_evidence_archive')
            total+=member.size
            if total>128*1024*1024: raise ValueError('restore_limit')
            body=archive.extractfile(member).read(member.size+1)
            if len(body)!=member.size: raise ValueError('truncated_object')
            objects[member.name]=body
    for name,body in objects.items():
        fd=os.open(root/Path(name).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output: output.write(body);output.flush();os.fsync(output.fileno())
    return {'restored_objects':len(objects)}


def relay(*,browser=False):
    """Opaque bounded TLS forwarding to one fixed service; no credentials or target selection."""
    slots=BoundedSemaphore(4)
    deadline=time.monotonic()+remaining_browser_seconds(os.environ['GABRIEL_BROWSER_EXPIRES_AT']) if browser else None
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(('browser-gateway',8443) if browser else ('workbench',8444),timeout=3) as upstream:
                    self.request.settimeout(3)
                    pair={self.request:upstream,upstream:self.request}
                    remaining=4*1024*1024
                    end=time.monotonic()+240
                    while remaining>0 and time.monotonic()<end:
                        ready,_,_=select.select(list(pair),[],[],max(0,end-time.monotonic()))
                        if not ready: return
                        for source in ready:
                            body=source.recv(min(65536,remaining))
                            if not body: return
                            remaining-=len(body)
                            pair[source].sendall(body)
            except OSError: return
    class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
        allow_reuse_address=True
        daemon_threads=True
        request_queue_size=4
        def process_request(self,request,address):
            if not slots.acquire(blocking=False): self.close_request(request);return
            try: super().process_request(request,address)
            except Exception: slots.release();raise
        def process_request_thread(self,request,address):
            try: super().process_request_thread(request,address)
            finally: slots.release()
    with Server(('0.0.0.0',8443 if browser else 8444),Handler) as server:
        if deadline is None:server.serve_forever()
        else:
            server.timeout=0.5
            while time.monotonic()<deadline:server.handle_request()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('tls','initialize','open','serve','health','receipt','restore-receipt','revoke','restore-objects','relay',
        'browser-open','browser-stop','browser-serve','browser-relay','browser-health'))
    parser.add_argument('--directory')
    args=parser.parse_args()
    try:
        if args.command=='tls': result=tls(args.directory)
        elif args.command=='relay': relay();return 0
        elif args.command=='browser-relay':relay(browser=True);return 0
        elif args.command=='browser-stop':result=stop_browser()
        elif args.command=='browser-health':result=browser_health()
        elif args.command=='browser-serve':
            serve_browser()
            return 0
        elif args.command=='serve':
            serve_workbench(str(active()/'workbench.json'),'/run/secrets/tls_certificate','/run/secrets/tls_key','0.0.0.0:8444')
            return 0
        elif args.command=='health': result=health()
        elif args.command=='restore-objects': result=restore_objects(sys.stdin.buffer)
        elif args.command=='receipt': result=read_document(ROOT/'installation.json',private=True)
        elif args.command=='revoke':
            if (ROOT/'active.json').exists():
                try: service().logout(read_document(active()/'human.json',private=True)['token'])
                except AuthenticationDenied: pass
            result={'revoked':True}
        else:
            raw=sys.stdin.buffer.read(8193)
            if len(raw)>8192: raise ValueError('input_limit')
            from gabriel.identity.cli import _unique
            payload=json.loads(raw,object_pairs_hook=_unique)
            if args.command=='initialize': result=initialize(payload)
            elif args.command=='open': result=open_workbench(payload)
            elif args.command=='browser-open':result=open_browser(payload)
            else:
                if set(payload)!={'organization_id','user_id','username'}: raise ValueError('invalid_receipt')
                migrate(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']))
                with connection(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),runtime=False) as conn:
                    row=conn.execute('SELECT username FROM gabriel_identity.users WHERE organization_id=%s AND id=%s',
                        (str(UUID(payload['organization_id'])),str(UUID(payload['user_id'])))).fetchone()
                    if not row or row['username']!=payload['username']: raise ValueError('restore_identity_mismatch')
                write_document(ROOT/'installation.json',payload)
                result={'restored_identity':True}
        print(json.dumps({'status':'ok','result':result}))
        return 0
    except (IdentityError,OSError,ValueError,TypeError,KeyError,tarfile.TarError) as exc:
        print(json.dumps({'status':'denied','code':'installation_operation_denied','phase':PHASE,'kind':type(exc).__name__}))
        return 1


if __name__=='__main__': raise SystemExit(main())


