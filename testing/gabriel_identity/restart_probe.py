"""Real database restart checkpoint; secret state never enters CI artifacts."""
import json
import os
from pathlib import Path
import secrets
import sys

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityService, AuthenticationDenied, provision_organization

service = IdentityService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']))
state = Path('/checkpoint/state.json')
if sys.argv[1] == 'before':
    password = secrets.token_urlsafe(24)
    org, user = provision_organization(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),
                                      'Restart fixture', 'restart-owner', password)
    token = service.login(org, 'restart-owner', password).token
    state.write_text(json.dumps({'org':str(org),'user':str(user),'token':token}))
    state.chmod(0o600)
    print('PASS: real database checkpoint created without logging credentials')
elif sys.argv[1] == 'after':
    saved = json.loads(state.read_text())
    principal = service.whoami(saved['token'])
    assert str(principal.organization_id) == saved['org']
    assert str(principal.user_id) == saved['user'] and principal.role == 'owner'
    service.logout(saved['token'])
    try:
        service.whoami(saved['token'])
    except AuthenticationDenied:
        pass
    else:
        raise AssertionError('revoked session survived')
    print('PASS: account, membership and session survived PostgreSQL restart; revocation enforced')
else:
    raise SystemExit(2)
