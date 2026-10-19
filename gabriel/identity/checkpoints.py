"""Offline checkpoint signatures; no database, session or evidence key access."""
import base64
from datetime import datetime,timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption

PURPOSE = 'gabriel-custody-checkpoint-v1'
MAX_DOCUMENT = 65536


class CheckpointError(ValueError):
    pass


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def fingerprint(value):
    return sha256(value).hexdigest()


def _hex(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def _uuid(value):
    return isinstance(value,str) and str(UUID(value))==value


def _unique(pairs):
    value = {}
    for key,item in pairs:
        if key in value:
            raise CheckpointError('checkpoint_duplicate_key')
        value[key] = item
    return value


def _invalid_number(value):
    raise ValueError('nonfinite_json_number')


def read_document(path,*,private=False):
    try:
        fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & (0o077 if private else 0o022):
                raise ValueError
            raw = stream.read(MAX_DOCUMENT+1)
        if not 1<=len(raw)<=MAX_DOCUMENT:
            raise ValueError
        return json.loads(raw,object_pairs_hook=_unique,parse_constant=_invalid_number)
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError):
        raise CheckpointError('checkpoint_file_invalid') from None


def write_document(path,value):
    """Exclusive, durable publication; a failed write must be inspected, never overwritten."""
    try:
        data = canonical(value)+b'\n'
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts or len(data)>MAX_DOCUMENT:
            raise ValueError
        parent = os.open(path.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(path.name,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)
    except (OSError,ValueError,TypeError,RecursionError):
        raise CheckpointError('checkpoint_write_unconfirmed') from None


def validate_snapshot(value):
    try:
        fields = {'schema_version','purpose','organization_id','case_id','case_digest','captured_at','nonce','evidence'}
        if (not isinstance(value,dict) or set(value)!=fields or type(value['schema_version']) is not int
                or value['schema_version']!=1 or value['purpose']!=PURPOSE or not _hex(value['case_digest'])
                or not all(_uuid(value[k]) for k in ('organization_id','case_id','nonce'))
                or not isinstance(value['captured_at'],str) or not isinstance(value['evidence'],list)
                or len(value['evidence'])>64 or len(canonical(value))>MAX_DOCUMENT-1024):
            raise ValueError
        instant = datetime.fromisoformat(value['captured_at'])
        if instant.utcoffset() is None or not 1970<=instant.year<=2100:
            raise ValueError
        ids = []
        for entry in value['evidence']:
            if (not isinstance(entry,dict) or set(entry)!={'evidence_id','context_digest','sequence','head'}
                    or not _uuid(entry['evidence_id']) or not _hex(entry['context_digest']) or not _hex(entry['head'])
                    or type(entry['sequence']) is not int or not 1<=entry['sequence']<=4096):
                raise ValueError
            ids.append(entry['evidence_id'])
        if ids!=sorted(set(ids)):
            raise ValueError
        return value
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError):
        raise CheckpointError('checkpoint_snapshot_invalid') from None


def new_keypair():
    private = Ed25519PrivateKey.generate()
    secret = private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
    public = private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    return ({'purpose':PURPOSE,'private_key':base64.b64encode(secret).decode()},
            {'purpose':PURPOSE,'public_key':base64.b64encode(public).decode()})


def _key(document,private=False):
    field = 'private_key' if private else 'public_key'
    try:
        if not isinstance(document,dict) or set(document)!={'purpose',field} or document['purpose']!=PURPOSE:
            raise ValueError
        raw = base64.b64decode(document[field],validate=True)
        if len(raw)!=32:
            raise ValueError
        return Ed25519PrivateKey.from_private_bytes(raw) if private else Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError,ValueError,KeyError):
        raise CheckpointError('checkpoint_key_invalid') from None


def seal(snapshot,private_document):
    validate_snapshot(snapshot)
    private = _key(private_document,private=True)
    public = private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    body = {'schema_version':1,'purpose':PURPOSE,'key_fingerprint':fingerprint(public),
            'sealed_at':datetime.now(timezone.utc).isoformat(timespec='microseconds'),'snapshot':snapshot}
    return {'body':body,'signature':base64.b64encode(private.sign(canonical(body))).decode()}


def verify(envelope,public_document,expected_digest):
    """Both trust inputs are external; an embedded key or self-reported latest digest is insufficient."""
    try:
        encoded = canonical(envelope)
        if len(encoded)>MAX_DOCUMENT or not _hex(expected_digest) or fingerprint(encoded)!=expected_digest:
            raise CheckpointError('checkpoint_digest_mismatch')
        public = _key(public_document)
        public_raw = public.public_bytes(Encoding.Raw,PublicFormat.Raw)
        if not isinstance(envelope,dict) or set(envelope)!={'body','signature'}:
            raise ValueError
        body = envelope['body']
        if (not isinstance(body,dict) or set(body)!={'schema_version','purpose','key_fingerprint','sealed_at','snapshot'}
                or type(body['schema_version']) is not int or body['schema_version']!=1 or body['purpose']!=PURPOSE
                or body['key_fingerprint']!=fingerprint(public_raw) or not isinstance(body['sealed_at'],str)):
            raise ValueError
        instant = datetime.fromisoformat(body['sealed_at'])
        if instant.utcoffset() is None or not 1970<=instant.year<=2100:
            raise ValueError
        signature = base64.b64decode(envelope['signature'],validate=True)
        public.verify(signature,canonical(body))
        return validate_snapshot(body['snapshot'])
    except CheckpointError:
        raise
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,RecursionError):
        raise CheckpointError('checkpoint_signature_or_envelope_invalid') from None
