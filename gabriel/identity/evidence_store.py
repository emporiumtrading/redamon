"""Bounded encrypted local object storage; never fetches a source or follows links."""
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gabriel.identity.service import IdentityError, IdentityConfigurationError, identifier
from gabriel.identity.vault import ProviderKeyRing, _unique

MAX_BYTES = 128*1024


class EvidenceError(IdentityError):
    pass


class EvidenceKeys(ProviderKeyRing):
    def __repr__(self):
        return '<EvidenceKeys [REDACTED]>'

    @classmethod
    def from_file(cls,path):
        try:
            fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
                    raise ValueError
                raw = stream.read(8193)
            data = json.loads(raw,object_pairs_hook=_unique)
            if (len(raw)>8192 or not isinstance(data,dict)
                    or set(data)!={'schema_version','purpose','generation','active','keys'}
                    or type(data['schema_version']) is not int or data['schema_version']!=1
                    or data['purpose']!='evidence-v1' or not isinstance(data['keys'],dict)):
                raise ValueError
            return cls(data['active'],{k:base64.b64decode(v,validate=True) for k,v in data['keys'].items()},data['generation'])
        except (OSError,ValueError,TypeError,UnicodeError,RecursionError,IdentityError):
            raise IdentityConfigurationError('invalid_evidence_key_configuration') from None


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


class EvidenceContent:
    __slots__ = ('metadata','_content','export_id')

    def __init__(self,metadata,content,export_id=None):
        self.metadata,self._content,self.export_id = metadata,content,export_id

    def __repr__(self):
        return '<EvidenceContent [REDACTED]>'

    def reveal(self):
        return self._content


class LocalEvidenceStore:
    def __init__(self,root,keys):
        if not isinstance(keys,EvidenceKeys):
            raise IdentityConfigurationError('evidence_key_configuration_required')
        try:
            self.root = Path(root)
            info = self.root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                raise ValueError
        except (OSError,TypeError,ValueError):
            raise IdentityConfigurationError('private_evidence_store_required') from None
        self.keys = keys

    def _name(self,object_id):
        return identifier(object_id).hex+'.gbe'

    def _open_root(self):
        return os.open(self.root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def read(self,row,aad):
        try:
            root = self._open_root()
            try:
                fd = os.open(self._name(row['object_id']),os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=root)
            finally:
                os.close(root)
            with os.fdopen(fd,'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError
                sealed = stream.read(MAX_BYTES+29)
            if not 29<=len(sealed)<=MAX_BYTES+28:
                raise ValueError
            value = AESGCM(self.keys._key(row['key_id'])).decrypt(sealed[:12],sealed[12:],aad)
            if len(value)!=row['byte_length'] or sha256(value).hexdigest()!=row['digest']:
                raise ValueError
            return value
        except (OSError,ValueError,TypeError,InvalidTag,IdentityError):
            raise EvidenceError('evidence_object_unavailable_or_invalid') from None

    def write(self,row,content,aad):
        if type(content) is not bytes or not 1<=len(content)<=MAX_BYTES:
            raise EvidenceError('evidence_content_limit')
        try:
            sealed = os.urandom(12)
            sealed += AESGCM(self.keys._key(row['key_id'])).encrypt(sealed,content,aad)
            root = self._open_root()
            try:
                try:
                    fd = os.open(self._name(row['object_id']),os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o444,dir_fd=root)
                except FileExistsError:
                    if self.read(row,aad)!=content:
                        raise ValueError
                    return
                with os.fdopen(fd,'wb') as stream:
                    stream.write(sealed)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(root)
            finally:
                os.close(root)
        except (OSError,ValueError,TypeError,IdentityError):
            raise EvidenceError('evidence_object_write_failed') from None

    def identity(self,*,enroll=False):
        try:
            root = self._open_root()
            try:
                if enroll:
                    try:
                        fd = os.open('store-id',os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o444,dir_fd=root)
                    except FileExistsError:
                        pass
                    else:
                        with os.fdopen(fd,'wb') as stream:
                            stream.write(str(uuid4()).encode('ascii'))
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.fsync(root)
                fd = os.open('store-id',os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=root)
                with os.fdopen(fd,'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise ValueError
                    value = stream.read(38).decode('ascii')
                return str(identifier(value))
            finally:
                os.close(root)
        except (OSError,ValueError,UnicodeError,IdentityError):
            raise EvidenceError('evidence_store_identity_unavailable') from None

    def absent(self,row,*,sync=False):
        try:
            root = self._open_root()
            try:
                try:
                    os.stat(self._name(row['object_id']),dir_fd=root,follow_symlinks=False)
                except FileNotFoundError:
                    if sync:
                        os.fsync(root)
                    return True
                return False
            finally:
                os.close(root)
        except OSError:
            raise EvidenceError('evidence_store_inspection_failed') from None

    def remove(self,row,aad,*,admit=None):
        # Only absence is idempotent; a present corrupt/symlink object is never removed.
        if self.absent(row):
            return 'absence_confirmed'
        self.read(row,aad)
        if not callable(admit):
            raise EvidenceError('evidence_removal_admission_required')
        admit()
        try:
            root = self._open_root()
            try:
                os.unlink(self._name(row['object_id']),dir_fd=root)
                os.fsync(root)
            finally:
                os.close(root)
        except OSError:
            raise EvidenceError('evidence_object_removal_unconfirmed') from None
        return 'removed'
