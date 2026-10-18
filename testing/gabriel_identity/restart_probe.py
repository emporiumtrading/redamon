"""Real database restart checkpoint; secret state never enters CI artifacts."""
import json
from hashlib import sha256
import os
from pathlib import Path
import secrets
import sys
from uuid import uuid4
from psycopg.conninfo import make_conninfo

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityService, AuthenticationDenied, provision_organization
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.vault import ProviderKeyRing, ProviderVault
from gabriel.identity.service import AccessDenied, connection, migrate
from gabriel.identity.cases import CaseService
from gabriel.identity.evidence_store import EvidenceKeys,LocalEvidenceStore

app_dsn = read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE'])
app_dsn = make_conninfo(app_dsn,dbname='gabriel_vault_restore' if sys.argv[1]=='restored' else 'gabriel_checkpoint')
service = ServiceIdentityService(app_dsn)
vault = ProviderVault(app_dsn,
    ProviderKeyRing.from_file(os.environ['GABRIEL_PROVIDER_KEYRING_FILE']))
cases = CaseService(app_dsn,LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],
    EvidenceKeys.from_file(os.environ['GABRIEL_EVIDENCE_KEYRING_FILE'])))
state = Path('/checkpoint/state.json')


def counts():
    tables = ('organizations','users','memberships','sessions','service_grants','audit_events',
              'provider_secrets','provider_key_registry','provider_key_state','investigation_tasks','task_executions',
              'cases','case_tasks','evidence_objects','custody_events','evidence_exports','evidence_key_registry','migrations')
    # Migrations are deliberately not readable by the runtime role.
    with connection(app_dsn) as conn:
        return {name:conn.execute(f'SELECT count(*) AS n FROM gabriel_identity.{name}').fetchone()['n']
                for name in tables if name != 'migrations'}


if sys.argv[1] == 'before':
    owner_dsn = make_conninfo(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),dbname='gabriel_checkpoint')
    migrate(owner_dsn)
    password = secrets.token_urlsafe(24)
    org, user = provision_organization(owner_dsn,
                                      'Restart fixture', 'restart-owner', password)
    token = service.login(org, 'restart-owner', password).token
    task = service.create_task(token,'restart task',['evidence.hash'],3600,5)['id']
    machine = service.issue_service(token,'restart worker',task,['evidence.hash'])
    request_id = uuid4()
    request = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'restart fixture'}}
    response = service.execute_service(machine.token,task,request,request_id)
    provider_value = 'restart-generated-fixture-' + secrets.token_urlsafe(32)
    vault.put(token,'model_restart',provider_value)
    case = cases.create_case(token,'Recovery checkpoint fixture')
    cases.link_task(token,case['id'],task)
    evidence = cases.acquire(token,case['id'],uuid4(),'approved recovery fixture','Recovery fixture',approved=True)
    state.write_text(json.dumps({'org':str(org),'user':str(user),'token':token,
        'task':str(task),'service_token':machine.token,'grant_id':str(machine.id),
        'request_id':str(request_id),'response':response,
        'case_id':str(case['id']),'evidence_id':str(evidence['id']),
        'provider_digest':sha256(provider_value.encode()).hexdigest(),'counts':counts()}))
    state.chmod(0o600)
    print('PASS: real database checkpoint created without logging credentials')
elif sys.argv[1] in {'after','restored'}:
    saved = json.loads(state.read_text())
    if sys.argv[1] == 'restored':
        assert counts()==saved['counts']
    principal = service.whoami(saved['token'])
    assert str(principal.organization_id) == saved['org']
    assert str(principal.user_id) == saved['user'] and principal.role == 'owner'
    assert cases.verify_case(saved['token'],saved['case_id'])['complete']
    assert cases.read_evidence(saved['token'],saved['evidence_id']).reveal()==b'approved recovery fixture'
    assert service.get_task(saved['token'],saved['task'])['id'] in cases.get_case(saved['token'],saved['case_id'])['task_ids']
    cases.close_case(saved['token'],saved['case_id'])
    assert sha256(vault.resolve_for_backend(saved['token'],'model_restart').reveal().encode()).hexdigest()==saved['provider_digest']
    vault.revoke(saved['token'],'model_restart')
    try:
        vault.resolve_for_backend(saved['token'],'model_restart')
    except AccessDenied:
        pass
    else:
        raise AssertionError('revoked provider secret survived')
    request = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'restart fixture'}}
    result = service.execute_service(saved['service_token'],saved['task'],request,saved['request_id'])
    assert result['service_id'] == saved['grant_id'] and result['organization_id'] == saved['org']
    assert result==saved['response'] and service.get_task(saved['token'],saved['task'])['used_steps']==1
    service.end_task(saved['token'],saved['task'],'cancelled')
    assert service.get_task(saved['token'],saved['task'])['state']=='cancelled'
    service.revoke_service(saved['token'],saved['grant_id'])
    try:
        service.execute_service(saved['service_token'],saved['task'],request,saved['request_id'])
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
    print('PASS: identities, service grant and encrypted provider value survived PostgreSQL restart; all revocations enforced')
    print('PASS: durable task/receipt replay survived recovery without another step; task cancellation enforced')
    print('PASS: case linkage and encrypted evidence/custody survived recovery; integrity-checked closure enforced')
    if sys.argv[1] == 'restored':
        print('PASS: real pg_dump/pg_restore recovered matching row counts and encrypted values with separately retained keys')
else:
    raise SystemExit(2)
