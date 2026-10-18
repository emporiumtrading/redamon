#!/usr/bin/env python3
"""Generate a new external key directory; never modify an existing key file."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import stat
from uuid import uuid4


def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError('invalid_previous_keyring')
        result[key] = value
    return result


def prepare(directory, previous=None):
    repo = Path(__file__).resolve().parents[2]
    directory = Path(directory).resolve()
    if directory == repo or repo in directory.parents:
        raise ValueError('external_key_directory_required')
    data = {'schema_version':1,'generation':1,'active':'','keys':{}}
    if previous:
        fd = os.open(previous,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            mode = os.fstat(stream.fileno())
            if not stat.S_ISREG(mode.st_mode) or mode.st_mode & 0o022:
                raise ValueError('invalid_previous_keyring')
            raw = stream.read(8193)
        data = json.loads(raw,object_pairs_hook=unique)
        if (len(raw)>8192 or not isinstance(data,dict) or set(data)!={'schema_version','generation','active','keys'}
                or type(data['schema_version']) is not int or data['schema_version']!=1
                or type(data['generation']) is not int or not 1<=data['generation']<1000000
                or not isinstance(data['keys'],dict) or not 1<=len(data['keys'])<16
                or not isinstance(data['active'],str) or data['active'] not in data['keys']):
            raise ValueError('invalid_previous_keyring')
        import re
        for key,value in data['keys'].items():
            if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}',key) or not isinstance(value,str) or len(base64.b64decode(value,validate=True))!=32:
                raise ValueError('invalid_previous_keyring')
        if len(set(data['keys'].values()))!=len(data['keys']):
            raise ValueError('invalid_previous_keyring')
        data['generation'] += 1
    data['active'] = 'k_' + uuid4().hex
    data['keys'][data['active']] = base64.b64encode(secrets.token_bytes(32)).decode('ascii')
    directory.mkdir(mode=0o700,parents=False,exist_ok=False)
    path = directory/'keyring.json'
    fd = os.open(path,os.O_WRONLY | os.O_CREAT | os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,separators=(',',':'))
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)
    return directory


def main():
    parser = argparse.ArgumentParser(description='Prepare new Gabriel model-provider keys outside Git')
    parser.add_argument('directory')
    parser.add_argument('--from-file')
    args = parser.parse_args()
    try:
        prepare(args.directory,args.from_file)
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError):
        print('BLOCKED: provider key preparation failed; existing files were not replaced.')
        return 2
    print('Provider key directory created; no key material printed.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
