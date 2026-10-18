"""Real database restart checkpoint; secret state never enters CI artifacts."""
import json
import os
from pathlib import Path
import secrets
import sys
from uuid import uuid4

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityService, AuthenticationDenied, provision_organization
from gabriel.identity.machine import ServiceIdentityService

service = ServiceIdentityService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']))
state = Path('/checkpoint/state.json')
if sys.argv[1] == 'before':
    password = secrets.token_urlsafe(24)
    org, user = provision_organization(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),
                                      'Restart fixture', 'restart-owner', password)
    token = service.login(org, 'restart-owner', password).token
    task = uuid4()
    machine = service.issue_service(token,'restart worker',task,['evidence.hash'])
    state.write_text(json.dumps({'org':str(org),'user':str(user),'token':token,
        'task':str(task),'service_token':machine.token,'grant_id':str(machine.id)}))
    state.chmod(0o600)
    print('PASS: real database checkpoint created without logging credentials')
elif sys.argv[1] == 'after':
    saved = json.loads(state.read_text())
    principal = service.whoami(saved['token'])
    assert str(principal.organization_id) == saved['org']
    assert str(principal.user_id) == saved['user'] and principal.role == 'owner'
    request = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'restart fixture'}}
    result = service.execute_service(saved['service_token'],saved['task'],request)
    assert result['service_id'] == saved['grant_id'] and result['organization_id'] == saved['org']
    service.revoke_service(saved['token'],saved['grant_id'])
    try:
        service.execute_service(saved['service_token'],saved['task'],request)
    except AuthenticationDenied:
        pass
    else:
        raise AssertionError('revoked service survived')
    service.logout(saved['token'])
    try:
        service.whoami(saved['token'])
    except AuthenticationDenied:
        pass
    else:
        raise AssertionError('revoked session survived')
    print('PASS: account, membership, session and scoped service grant survived PostgreSQL restart; both revocations enforced')
else:
    raise SystemExit(2)
