"""Admin secret writes/rotation and metadata only; never print plaintext credentials."""
import argparse
import getpass
import json
import os

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityError, InvalidIdentityInput
from gabriel.identity.vault import ProviderKeyRing, ProviderVault


def main():
    parser = argparse.ArgumentParser(description='Gabriel model-provider vault operator')
    parser.add_argument('command', choices=('put','list','revoke','rotate'))
    parser.add_argument('--token-file')
    parser.add_argument('--provider')
    parser.add_argument('--secret-file')
    args = parser.parse_args()
    try:
        if (args.command in {'put','revoke'}) != bool(args.provider) or (args.secret_file and args.command != 'put'):
            raise InvalidIdentityInput('invalid_vault_arguments')
        ring = ProviderKeyRing.from_file(os.environ.get('GABRIEL_PROVIDER_KEYRING_FILE'))
        vault = ProviderVault(read_secret(os.environ.get('GABRIEL_IDENTITY_DSN_FILE')),ring)
        token = read_secret(args.token_file,128) if args.token_file else getpass.getpass('Gabriel admin session: ')
        if args.command == 'put':
            secret = read_secret(args.secret_file,8192) if args.secret_file else getpass.getpass('Model-provider secret: ')
            result = vault.put(token,args.provider,secret)
        elif args.command == 'list':
            result = vault.list_secrets(token)
        elif args.command == 'rotate':
            result = vault.rotate(token)
        else:
            vault.revoke(token,args.provider)
            result = {'revoked':True}
        print(json.dumps({'status':'ok','result':result},default=str))
        return 0
    except IdentityError as exc:
        print(json.dumps({'status':'denied','code':str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
