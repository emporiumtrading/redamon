"""Operator CLI. Password/token values are prompts or bounded secret files."""
import argparse
from dataclasses import asdict
import getpass
import json
import os
from pathlib import Path
import sys

from gabriel.capabilities import CapabilityDenied, InvalidRequest
from gabriel.identity.service import (IdentityError, IdentityConfigurationError,
    InvalidIdentityInput, IdentityService, migrate, provision_organization)


def read_secret(path, limit=8192):
    if not path:
        raise IdentityConfigurationError('secret_file_required')
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError
        value = data.decode('utf-8').removesuffix('\n').removesuffix('\r')
        if not value:
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError):
        raise IdentityConfigurationError('secret_file_unavailable') from None


def _password(args, *, confirm=False):
    if args.password_file:
        return read_secret(args.password_file, 1024)
    value = getpass.getpass('Password: ')
    if confirm and value != getpass.getpass('Confirm password: '):
        raise InvalidIdentityInput('passwords_do_not_match')
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidIdentityInput('duplicate_json_key')
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description='Gabriel database identity operator')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('migrate')
    provision = commands.add_parser('provision')
    provision.add_argument('--organization-name', required=True)
    provision.add_argument('--username', required=True)
    provision.add_argument('--password-file')
    login = commands.add_parser('login')
    login.add_argument('--organization', required=True)
    login.add_argument('--username', required=True)
    login.add_argument('--password-file')
    for command in ('whoami', 'logout', 'members', 'execute', 'create-member', 'set-membership', 'reset-password'):
        sub = commands.add_parser(command)
        sub.add_argument('--token-file')
        if command == 'create-member':
            sub.add_argument('--username', required=True)
            sub.add_argument('--role', choices=('owner','admin','analyst','viewer'), default='analyst')
            sub.add_argument('--password-file')
        if command in {'set-membership', 'reset-password'}:
            sub.add_argument('--user-id', required=True)
        if command == 'set-membership':
            sub.add_argument('--role', choices=('owner','admin','analyst','viewer'), required=True)
            sub.add_argument('--active', choices=('true','false'), required=True)
        if command == 'reset-password':
            sub.add_argument('--password-file')
    args = parser.parse_args()
    try:
        if args.command in {'migrate', 'provision'}:
            owner_dsn = read_secret(os.environ.get('GABRIEL_MIGRATION_DSN_FILE'))
            if args.command == 'migrate':
                migrate(owner_dsn)
                result = {'migration': 1}
            else:
                org, user = provision_organization(owner_dsn, args.organization_name,
                    args.username, _password(args, confirm=True))
                result = {'organization_id': str(org), 'user_id': str(user)}
        else:
            service = IdentityService(read_secret(os.environ.get('GABRIEL_IDENTITY_DSN_FILE')))
            if args.command == 'login':
                grant = service.login(args.organization, args.username, _password(args))
                result = {'session_token': grant.token, 'expires_at': grant.expires_at.isoformat()}
            else:
                token = read_secret(args.token_file, 128) if args.token_file else getpass.getpass('Session token: ')
                if args.command == 'whoami':
                    result = asdict(service.whoami(token))
                elif args.command == 'members':
                    result = service.list_members(token)
                elif args.command == 'logout':
                    service.logout(token)
                    result = {'revoked': True}
                elif args.command == 'execute':
                    raw = sys.stdin.buffer.read(256 * 1024 + 1)
                    if len(raw) > 256 * 1024:
                        raise InvalidIdentityInput('request_limit_exceeded')
                    result = service.execute(token, json.loads(raw, object_pairs_hook=_unique))
                elif args.command == 'create-member':
                    result = {'user_id': str(service.create_member(token, args.username,
                        _password(args, confirm=True), args.role))}
                elif args.command == 'set-membership':
                    service.set_membership(token, args.user_id, args.role, args.active == 'true')
                    result = {'updated': True}
                elif args.command == 'reset-password':
                    service.reset_password(token, args.user_id, _password(args, confirm=True))
                    result = {'updated': True}
        print(json.dumps({'status':'ok', 'result':result}, default=str, allow_nan=False))
        return 0
    except (IdentityError, CapabilityDenied, InvalidRequest) as exc:
        print(json.dumps({'status':'denied', 'code':str(exc)}))
        return 1
    except (ValueError, UnicodeError, RecursionError):
        print(json.dumps({'status':'denied', 'code':'invalid_request'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
