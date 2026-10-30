"""Ephemeral private CA and localhost certificate for isolated TLS contracts."""
from datetime import datetime,timedelta,timezone
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID


def certificates(directory):
    now=datetime.now(timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Generated Gabriel isolated lab CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256()))
    server=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]))
        .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(ca_key,hashes.SHA256()))
    paths={name:directory/name for name in ('ca.pem','server.pem','server.key')}
    paths['ca.pem'].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths['server.pem'].write_bytes(server.public_bytes(serialization.Encoding.PEM))
    paths['server.key'].write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    paths['server.key'].chmod(0o600)
    return paths

