"""Private installation certificates and fail-closed encrypted-object restoration."""
from concurrent.futures import ThreadPoolExecutor
import io
import socket
from pathlib import Path
import ssl
import tarfile

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from gabriel.identity.installation import restore_objects,tls


def archive(entries):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz') as output:
        for name,body,kind in entries:
            member=tarfile.TarInfo(name)
            member.type=kind
            member.size=len(body) if kind==tarfile.REGTYPE else 0
            if kind==tarfile.SYMTYPE: member.linkname='../outside'
            output.addfile(member,io.BytesIO(body) if member.isfile() else None)
    stream.seek(0)
    return stream


def test_installation_tls_names_usage_and_no_signing_key_retained(tmp_path):
    assert tls(tmp_path)=={'certificate_days':30}
    assert set(p.name for p in tmp_path.iterdir())=={'ca.pem','server.pem','server.key'}
    ca=x509.load_pem_x509_certificate((tmp_path/'ca.pem').read_bytes())
    leaf=x509.load_pem_x509_certificate((tmp_path/'server.pem').read_bytes())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert ExtendedKeyUsageOID.SERVER_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)==['localhost']
    assert str(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)[0])=='127.0.0.1'
    ssl.create_default_context(cafile=str(tmp_path/'ca.pem'))
    with pytest.raises(ValueError): tls(tmp_path)


def test_encrypted_objects_restore_exactly_and_refuse_nonempty_target(tmp_path,monkeypatch):
    monkeypatch.setenv('GABRIEL_EVIDENCE_ROOT',str(tmp_path))
    name='./'+'a'*32+'.gbe';body=b'generated-encrypted-object-fixture'*2
    assert restore_objects(archive([(name,body,tarfile.REGTYPE)]))=={'restored_objects':1}
    assert (tmp_path/Path(name).name).read_bytes()==body
    with pytest.raises(ValueError): restore_objects(archive([]))


@pytest.mark.parametrize('name,body,kind',[
    ('../outside',b'x'*32,tarfile.REGTYPE),
    ('./'+'a'*32+'.gbe',b'',tarfile.SYMTYPE),
    ('./unknown',b'x'*32,tarfile.REGTYPE),
    ('./'+'b'*32+'.gbe',b'x'*28,tarfile.REGTYPE),
    ('./'+'c'*32+'.gbe',b'x'*(128*1024+29),tarfile.REGTYPE),
])
def test_invalid_archive_denied_before_any_objects_published(tmp_path,monkeypatch,name,body,kind):
    monkeypatch.setenv('GABRIEL_EVIDENCE_ROOT',str(tmp_path))
    entries=[('./'+'f'*32+'.gbe',b'x'*32,tarfile.REGTYPE),(name,body,kind)]
    with pytest.raises(ValueError): restore_objects(archive(entries))
    assert list(tmp_path.iterdir())==[]


def test_duplicate_archive_objects_rejected_before_publication(tmp_path,monkeypatch):
    monkeypatch.setenv('GABRIEL_EVIDENCE_ROOT',str(tmp_path))
    entry=('./'+'a'*32+'.gbe',b'x'*32,tarfile.REGTYPE)
    with pytest.raises(ValueError): restore_objects(archive([entry,entry]))
    assert not list(tmp_path.iterdir())



def test_installation_certificate_accepts_strict_native_tls(tmp_path):
    tls(tmp_path)
    context=ssl.create_default_context(cafile=str(tmp_path/'ca.pem'))
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(tmp_path/'server.pem'),str(tmp_path/'server.key'))
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as pool:
        listener.settimeout(5)
        listener.bind(('127.0.0.1',0))
        listener.listen(1)
        def respond():
            raw,_=listener.accept()
            with raw, server_context.wrap_socket(raw,server_side=True) as secure:
                secure.sendall(b'generated-strict-tls')
        result=pool.submit(respond)
        with socket.create_connection(listener.getsockname(),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname='localhost') as secure:
                assert secure.recv(64)==b'generated-strict-tls'
        result.result(timeout=5)
