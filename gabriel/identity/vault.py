"""Encrypted model credentials. No external login, network client or plaintext CLI."""
import base64
import binascii
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gabriel.identity.service import (AccessDenied, IdentityConfigurationError, IdentityError,
    IdentityService, InvalidIdentityInput, _audit, connection)

PURPOSE = 'model-provider-v1'
KEY_ID = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}')


class SecretUnavailable(IdentityError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class ProviderKeyRing:
    def __init__(self, active, keys, generation=1):
        if (type(generation) is not int or not 1 <= generation <= 1000000
                or not isinstance(active, str) or not isinstance(keys, dict) or not 1 <= len(keys) <= 16
                or active not in keys
                or any(not isinstance(k, str) or not KEY_ID.fullmatch(k)
                       or type(v) is not bytes or len(v) != 32 for k, v in keys.items())
                or len(set(keys.values())) != len(keys)):
            raise IdentityConfigurationError('invalid_provider_key_configuration')
        self.active = active
        self.generation = generation
        self._keys = MappingProxyType(dict(keys))

    def __repr__(self):
        return '<ProviderKeyRing [REDACTED]>'

    @classmethod
    def from_file(cls, path):
        try:
            if not path:
                raise ValueError
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                mode = os.fstat(stream.fileno())
                if not stat.S_ISREG(mode.st_mode) or mode.st_mode & 0o022:
                    raise ValueError
                raw = stream.read(8193)
            if len(raw) > 8192:
                raise ValueError
            data = json.loads(raw, object_pairs_hook=_unique)
            if not isinstance(data, dict) or set(data) != {'schema_version','generation','active','keys'} or type(data['schema_version']) is not int or data['schema_version'] != 1:
                raise ValueError
            if not isinstance(data['keys'], dict) or any(not isinstance(v, str) for v in data['keys'].values()):
                raise ValueError
            keys = {k:base64.b64decode(v, validate=True) for k,v in data['keys'].items()}
            return cls(data['active'], keys, data['generation'])
        except (OSError, ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
            raise IdentityConfigurationError('invalid_provider_key_configuration') from None

    def _key(self, key_id):
        try:
            return self._keys[key_id]
        except KeyError:
            raise SecretUnavailable('provider_key_unavailable') from None


class ProviderCredential:
    """Only trusted backend consumers call reveal; never serialize this object."""
    __slots__ = ('__value',)

    def __init__(self, value):
        self.__value = value

    def __repr__(self):
        return '<ProviderCredential [REDACTED]>'

    __str__ = __repr__

    def reveal(self):
        return self.__value


def _provider(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', value):
        raise InvalidIdentityInput('invalid_model_provider')
    return value


def _secret(value):
    try:
        valid = isinstance(value, str) and 1 <= len(value.encode('utf-8')) <= 8192 and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    except UnicodeError:
        valid = False
    if not valid:
        raise InvalidIdentityInput('invalid_provider_secret')
    return value


def _aad(row, key_id):
    return json.dumps([PURPOSE,str(row['organization_id']),str(row['id']),row['provider'],
                       row['revision'],key_id], separators=(',',':')).encode('utf-8')


class ProviderVault(IdentityService):
    def __init__(self, dsn, keyring):
        super().__init__(dsn)
        if not isinstance(keyring, ProviderKeyRing):
            raise IdentityConfigurationError('provider_key_configuration_required')
        self._ring = keyring

    def _register_key(self, conn, key_id):
        fingerprint = sha256(self._ring._key(key_id)).hexdigest()
        conn.execute('''INSERT INTO gabriel_identity.provider_key_registry VALUES (%s,%s)
            ON CONFLICT (key_id) DO NOTHING''', (key_id,fingerprint))
        actual = conn.execute('SELECT fingerprint FROM gabriel_identity.provider_key_registry WHERE key_id=%s', (key_id,)).fetchone()
        if not actual or actual['fingerprint'] != fingerprint:
            raise IdentityConfigurationError('provider_key_identity_mismatch')

    def _active(self, conn, principal):
        self._register_key(conn,self._ring.active)
        conn.execute('''INSERT INTO gabriel_identity.provider_key_state VALUES (%s,%s,%s)
            ON CONFLICT (organization_id) DO NOTHING''', (principal.organization_id,self._ring.active,self._ring.generation))
        row = conn.execute('SELECT active_key_id,generation FROM gabriel_identity.provider_key_state WHERE organization_id=%s', (principal.organization_id,)).fetchone()
        if row['active_key_id'] != self._ring.active or row['generation'] != self._ring.generation:
            raise IdentityConfigurationError('provider_key_rotation_required')

    def _encrypt(self, conn, row, value):
        key_id, nonce = self._ring.active, os.urandom(12)
        self._register_key(conn,key_id)
        ciphertext = AESGCM(self._ring._key(key_id)).encrypt(nonce,value.encode('utf-8'),_aad(row,key_id))
        return key_id,nonce,ciphertext

    def _decrypt(self, conn, row):
        self._register_key(conn,row['key_id'])
        try:
            return AESGCM(self._ring._key(row['key_id'])).decrypt(
                bytes(row['nonce']),bytes(row['ciphertext']),_aad(row,row['key_id'])).decode('utf-8')
        except (InvalidTag, UnicodeError, ValueError, TypeError):
            raise SecretUnavailable('provider_secret_integrity_failed') from None

    def put(self, token, provider, value):
        provider, value = _provider(provider), _secret(value)
        with connection(self._dsn) as conn:
            principal = self._admin(conn,token)
            self._active(conn,principal)
            row = conn.execute('SELECT * FROM gabriel_identity.provider_secrets WHERE organization_id=%s AND provider=%s FOR UPDATE', (principal.organization_id,provider)).fetchone()
            if row:
                row['revision'] += 1
            else:
                count = conn.execute('SELECT count(*) AS n FROM gabriel_identity.provider_secrets WHERE organization_id=%s', (principal.organization_id,)).fetchone()['n']
                if count >= 64:
                    raise AccessDenied('provider_secret_limit')
                row = {'organization_id':principal.organization_id,'id':uuid4(),'provider':provider,'revision':1}
            key_id,nonce,ciphertext = self._encrypt(conn,row,value)
            conn.execute('''INSERT INTO gabriel_identity.provider_secrets
                (organization_id,id,provider,purpose,revision,updated_by,key_id,nonce,ciphertext)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (organization_id,provider) DO UPDATE SET
                  revision=EXCLUDED.revision,updated_by=EXCLUDED.updated_by,key_id=EXCLUDED.key_id,
                  nonce=EXCLUDED.nonce,ciphertext=EXCLUDED.ciphertext,revoked_at=NULL,updated_at=clock_timestamp()''',
                (principal.organization_id,row['id'],provider,PURPOSE,row['revision'],principal.user_id,key_id,nonce,ciphertext))
            _audit(conn,'provider.secret_stored',principal,row['id'])
            return {'id':str(row['id']),'provider':provider,'revision':row['revision'],'key_id':key_id}

    def list_secrets(self, token):
        with connection(self._dsn) as conn:
            principal = self._admin(conn,token)
            return conn.execute('''SELECT id,provider,revision,key_id,created_at,updated_at,revoked_at
                FROM gabriel_identity.provider_secrets WHERE organization_id=%s ORDER BY provider LIMIT 64''', (principal.organization_id,)).fetchall()

    def resolve_for_backend(self, token, provider):
        provider = _provider(provider)
        with connection(self._dsn) as conn:
            principal = self._admin(conn,token)
            self._active(conn,principal)
            row = conn.execute('''SELECT * FROM gabriel_identity.provider_secrets
                WHERE organization_id=%s AND provider=%s AND revoked_at IS NULL FOR UPDATE''', (principal.organization_id,provider)).fetchone()
            if not row:
                raise AccessDenied('provider_secret_not_accessible')
            value = ProviderCredential(self._decrypt(conn,row))
            _audit(conn,'provider.secret_resolved',principal,row['id'])
        return value

    def revoke(self, token, provider):
        provider = _provider(provider)
        with connection(self._dsn) as conn:
            principal = self._admin(conn,token)
            row = conn.execute('''UPDATE gabriel_identity.provider_secrets SET revoked_at=clock_timestamp(),
                key_id=NULL,nonce=NULL,ciphertext=NULL,updated_at=clock_timestamp(),updated_by=%s
                WHERE organization_id=%s AND provider=%s RETURNING id''', (principal.user_id,principal.organization_id,provider)).fetchone()
            if not row:
                raise AccessDenied('provider_secret_not_accessible')
            _audit(conn,'provider.secret_revoked',principal,row['id'])

    def rotate(self, token):
        with connection(self._dsn) as conn:
            principal = self._admin(conn,token)
            self._register_key(conn,self._ring.active)
            current = conn.execute('SELECT active_key_id,generation FROM gabriel_identity.provider_key_state WHERE organization_id=%s', (principal.organization_id,)).fetchone()
            if current and (self._ring.generation < current['generation'] or
                    (self._ring.generation == current['generation'] and self._ring.active != current['active_key_id'])):
                raise IdentityConfigurationError('provider_key_downgrade_denied')
            rows = conn.execute('''SELECT * FROM gabriel_identity.provider_secrets
                WHERE organization_id=%s AND revoked_at IS NULL ORDER BY id FOR UPDATE''', (principal.organization_id,)).fetchall()
            changed = 0
            for row in rows:
                value = self._decrypt(conn,row)
                if row['key_id'] != self._ring.active:
                    key_id,nonce,ciphertext = self._encrypt(conn,row,value)
                    conn.execute('''UPDATE gabriel_identity.provider_secrets SET key_id=%s,nonce=%s,ciphertext=%s,
                        updated_at=clock_timestamp(),updated_by=%s WHERE organization_id=%s AND id=%s''',
                        (key_id,nonce,ciphertext,principal.user_id,principal.organization_id,row['id']))
                    _audit(conn,'provider.secret_rewrapped',principal,row['id'])
                    changed += 1
            personal=conn.execute('SELECT * FROM gabriel_identity.personal_provider_secrets WHERE organization_id=%s AND revoked_at IS NULL ORDER BY id FOR UPDATE',(principal.organization_id,)).fetchall()
            for row in personal:
                value=self._decrypt(conn,row)
                if row['key_id']!=self._ring.active:
                    kid,nonce,cipher=self._encrypt(conn,row,value)
                    conn.execute('UPDATE gabriel_identity.personal_provider_secrets SET key_id=%s,nonce=%s,ciphertext=%s WHERE organization_id=%s AND id=%s',(kid,nonce,cipher,principal.organization_id,row['id']))
                    _audit(conn,'personal_provider.rewrapped',principal,row['id'])
                    changed+=1
            conn.execute('''INSERT INTO gabriel_identity.provider_key_state VALUES (%s,%s,%s)
                ON CONFLICT (organization_id) DO UPDATE SET active_key_id=EXCLUDED.active_key_id,generation=EXCLUDED.generation''',
                (principal.organization_id,self._ring.active,self._ring.generation))
            _audit(conn,'provider.key_rotated',principal)
            return {'rewrapped':changed,'active_key_id':self._ring.active,'generation':self._ring.generation}
