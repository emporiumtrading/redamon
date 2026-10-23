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
from uuid import UUID,uuid4

from gabriel.identity.checkpoints import read_document,write_document
from gabriel.identity.cli import read_secret
from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore
from gabriel.identity.service import AuthenticationDenied,IdentityError,connection,migrate,provision_organization,username
from gabriel.identity.workbench import prepare_workbench,serve_workbench

ROOT=Path('/var/lib/gabriel-workbench')


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
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True).sign(ca_key,hashes.SHA256()))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]))
        .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
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
    if set(payload)!={'organization','username','password'}: raise ValueError('invalid_enrollment')
    owner=read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE'])
    migrate(owner)
    with connection(owner,runtime=False) as conn:
        if conn.execute('SELECT count(*) AS n FROM gabriel_identity.organizations').fetchone()['n']:
            raise ValueError('already_initialized')
    org,user=provision_organization(owner,payload['organization'],payload['username'],payload['password'])
    receipt={'organization_id':str(org),'user_id':str(user),'username':username(payload['username'])}
    write_document(ROOT/'installation.json',receipt)
    return receipt


def open_workbench(payload):
    if set(payload)!={'password','port'} or type(payload['port']) is not int or not 1024<=payload['port']<=65535:
        raise ValueError('invalid_open_request')
    receipt=read_document(ROOT/'installation.json',private=True)
    if sum(1 for p in ROOT.iterdir() if p.is_dir())>=128: raise ValueError('session_directory_limit')
    app=service()
    grant=app.login(receipt['organization_id'],receipt['username'],payload['password'])
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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('tls','initialize','open','serve','health','receipt','restore-receipt','revoke','restore-objects'))
    parser.add_argument('--directory')
    args=parser.parse_args()
    try:
        if args.command=='tls': result=tls(args.directory)
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
    except (IdentityError,OSError,ValueError,TypeError,KeyError,tarfile.TarError):
        print(json.dumps({'status':'denied','code':'installation_operation_denied'}))
        return 1


if __name__=='__main__': raise SystemExit(main())
