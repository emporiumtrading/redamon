"""Real database restart checkpoint; secret state never enters CI artifacts."""
import json
import base64
from hashlib import sha256
import os
from pathlib import Path
import secrets
import sys
from types import SimpleNamespace
from uuid import uuid4
from psycopg.conninfo import make_conninfo

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityService, AuthenticationDenied, provision_organization
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.vault import ProviderKeyRing, ProviderVault
from gabriel.identity.service import AccessDenied, IdentityUnavailable, connection, migrate
from gabriel.identity.cases import CaseService
from gabriel.identity.actions import ActionService
from gabriel.identity.retention import RetentionService
from gabriel.identity.checkpoint_service import CheckpointService
from gabriel.identity.checkpoint_policy import CheckpointPolicyService
from gabriel.identity.evidence_keys import EvidenceKeyService
from gabriel.identity.checkpoints import canonical,fingerprint,new_keypair,public_fingerprint,read_document,seal,write_document
from gabriel.identity.cases import custody_hash
from datetime import timedelta
from gabriel.identity.evidence_store import EvidenceError,EvidenceKeys,LocalEvidenceStore
from testing.gabriel_identity.test_retention_integration import historical_artifact

app_dsn = read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE'])
app_dsn = make_conninfo(app_dsn,dbname='gabriel_vault_restore' if sys.argv[1]=='restored' else 'gabriel_checkpoint')
service = ServiceIdentityService(app_dsn)
vault = ProviderVault(app_dsn,
    ProviderKeyRing.from_file(os.environ['GABRIEL_PROVIDER_KEYRING_FILE']))
evidence_key_file = os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']
cases = CaseService(app_dsn,LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(evidence_key_file)))
state = Path('/checkpoint/state.json')
actions = ActionService(app_dsn,cases.store)
retention = RetentionService(app_dsn,cases.store)
checkpoints = CheckpointPolicyService(app_dsn,cases.store)


def counts():
    tables = ('organizations','users','memberships','sessions','service_grants','audit_events',
              'provider_secrets','provider_key_registry','provider_key_state','investigation_tasks','task_executions',
              'cases','case_tasks','evidence_objects','custody_events','evidence_exports','evidence_key_registry',
              'action_policies','action_policy_state','action_requests','action_approvals','action_decisions','action_executions',
              'retention_policies','case_hold_versions','legal_holds','hold_releases','purge_requests','purge_approvals','purge_attempts','retention_events',
              'checkpoint_keys','checkpoint_key_revocations','checkpoint_policies','checkpoint_captures','checkpoint_receipts',
              'evidence_key_epochs','evidence_rewraps','evidence_rewrap_results','migrations')
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
    actions.set_policy(token,distinct_approver=False,approval_ttl=900)
    action = actions.propose_close(token,case['id'],uuid4(),'Reviewed recovery closure',ttl=3600)
    actions.submit(token,action['id'])
    actions.approve(token,action['id'],action['digest'])
    completed_case = cases.create_case(token,'Completed recovery fixture')
    completed_artifact = cases.acquire(token,completed_case['id'],uuid4(),'completed recovery artifact','Recovery fixture',approved=True)
    completed_action = actions.propose_close(token,completed_case['id'],uuid4(),'Reviewed completed fixture',ttl=3600)
    actions.submit(token,completed_action['id'])
    actions.approve(token,completed_action['id'],completed_action['digest'])
    receipt = actions.execute(token,completed_action['id'])
    retention.set_retention(token,1)
    hold = retention.place_hold(token,case['id'],'Recovery preservation fixture')
    review_password = secrets.token_urlsafe(24)
    retention.create_member(token,'retention-reviewer',review_password,'admin')
    review_token = retention.login(org,'retention-reviewer',review_password).token
    purge_case = cases.create_case(token,'Historical disposition recovery fixture')
    historical = SimpleNamespace(org=org,db=SimpleNamespace(owner=owner_dsn,app=app_dsn))
    artifacts = [cases.acquire(token,purge_case['id'],uuid4(),'generated historical purge fixture','Recovery disposition fixture',approved=True) for _ in range(2)]
    for artifact in artifacts:
        historical_artifact(historical,cases.store,artifact)
    close = actions.propose_close(token,purge_case['id'],uuid4(),'Reviewed historical recovery case closure')
    actions.submit(token,close['id'])
    actions.approve(token,close['id'],close['digest'])
    actions.execute(token,close['id'])
    attempts = []
    for index,artifact in enumerate(artifacts):
        request = retention.propose_purge(token,artifact['id'],uuid4(),'Reviewed primary recovery disposition')
        retention.approve_purge(review_token,request['id'],request['digest'])
        attempt = retention.prepare_purge(token,request['id'])
        attempts.append(attempt['id'])
        if index==0:
            retention.execute_purge(token,attempt['id'])
        else:
            with connection(owner_dsn,runtime=False) as conn:
                conn.execute('REVOKE INSERT ON gabriel_identity.retention_events FROM gabriel_identity_app')
            try:
                try:
                    retention.execute_purge(token,attempt['id'])
                except IdentityUnavailable:
                    pass
                else:
                    raise AssertionError('receipt failure did not block success')
            finally:
                with connection(owner_dsn,runtime=False) as conn:
                    conn.execute('GRANT INSERT ON gabriel_identity.retention_events TO gabriel_identity_app')
    signing_key,public_key = new_keypair()
    pin = public_fingerprint(public_key)
    checkpoints.trust_checkpoint_key(token,public_key,pin)
    checkpoints.set_checkpoint_policy(token,pin,3600)
    _,retired_public = new_keypair()
    retired_pin = public_fingerprint(retired_public)
    checkpoints.trust_checkpoint_key(token,retired_public,retired_pin)
    checkpoints.revoke_checkpoint_key(token,retired_pin,'Generated recovery key retirement')
    write_document('/checkpoint/custody-public.json',public_key)
    checkpoint_digests = {}
    for label,target in [('active',case['id']),('purged',purge_case['id'])]:
        envelope = seal(checkpoints.capture_checkpoint(token,target),signing_key)
        write_document('/checkpoint/custody-'+label+'.json',envelope)
        checkpoint_digests[label] = fingerprint(canonical(envelope))
        checkpoints.accept_checkpoint(token,target,envelope,checkpoint_digests[label])
    del signing_key
    key_password = secrets.token_urlsafe(24)
    key_org,_ = provision_organization(owner_dsn,'Separate key rollover recovery fixture','key-owner',key_password)
    key_token = service.login(key_org,'key-owner',key_password).token
    key_case = cases.create_case(key_token,'Encryption rollover recovery fixture')
    key_artifacts = [cases.acquire(key_token,key_case['id'],uuid4(),'generated key recovery artifact','Key recovery fixture',approved=True) for _ in range(2)]
    old_ring = cases.store.keys
    target = 'k_'+uuid4().hex
    new_ring = EvidenceKeys(target,dict(old_ring._keys,**{target:secrets.token_bytes(32)}),old_ring.generation+1)
    rekeys = EvidenceKeyService(app_dsn,LocalEvidenceStore(cases.store.root,new_ring))
    rekeys.activate_evidence_key(key_token)
    completed_rewrap = rekeys.prepare_rewrap(key_token,key_artifacts[0]['id'])
    rekeys.execute_rewrap(key_token,completed_rewrap['id'])
    pending_rewrap = rekeys.prepare_rewrap(key_token,key_artifacts[1]['id'])
    with connection(owner_dsn,runtime=False) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.evidence_rewrap_results FROM gabriel_identity_app')
    try:
        try:
            rekeys.execute_rewrap(key_token,pending_rewrap['id'])
        except IdentityUnavailable:
            pass
        else:
            raise AssertionError('rewrap receipt failure did not block success')
    finally:
        with connection(owner_dsn,runtime=False) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.evidence_rewrap_results TO gabriel_identity_app')
    write_document('/checkpoint/evidence-rotated-keys.json',{'schema_version':1,'purpose':'evidence-v1',
        'generation':new_ring.generation,'active':new_ring.active,'keys':{k:base64.b64encode(v).decode() for k,v in new_ring._keys.items()}})
    state.write_text(json.dumps({'org':str(org),'user':str(user),'token':token,
        'task':str(task),'service_token':machine.token,'grant_id':str(machine.id),
        'request_id':str(request_id),'response':response,
        'case_id':str(case['id']),'evidence_id':str(evidence['id']),
        'action_id':str(action['id']),'completed_action_id':str(completed_action['id']),'action_receipt':receipt,
        'hold_id':str(hold['id']),'purge_case_id':str(purge_case['id']),
        'completed_purge':str(attempts[0]),'pending_purge':str(attempts[1]),
        'purged_evidence':[str(artifact['id']) for artifact in artifacts],
        'checkpoint_digests':checkpoint_digests,'retired_checkpoint_key':retired_pin,
        'completed_rewrap':str(completed_rewrap['id']),'pending_rewrap':str(pending_rewrap['id']),
        'key_token':key_token,'key_artifact':str(key_artifacts[1]['id']),'old_evidence_key':old_ring.active,
        'provider_digest':sha256(provider_value.encode()).hexdigest(),'counts':counts()}))
    state.chmod(0o600)
    print('PASS: real database checkpoint created without logging credentials')
elif sys.argv[1] in {'after','restored'}:
    saved = json.loads(state.read_text())
    if sys.argv[1] == 'restored':
        assert counts()==saved['counts']
    rotated_store = LocalEvidenceStore(cases.store.root,EvidenceKeys.from_file('/checkpoint/evidence-rotated-keys.json'))
    rekeys = EvidenceKeyService(app_dsn,rotated_store)
    assert rekeys.reconcile_rewrap(saved['key_token'],saved['completed_rewrap'])['state']=='completed'
    assert rekeys.reconcile_rewrap(saved['key_token'],saved['pending_rewrap'])['state']=='completed'
    active = rotated_store.keys.active
    minimal = EvidenceKeys(active,{active:rotated_store.keys._key(active)},rotated_store.keys.generation)
    reduced = EvidenceKeyService(app_dsn,LocalEvidenceStore(cases.store.root,minimal))
    assert reduced.read_evidence(saved['key_token'],saved['key_artifact']).reveal()==b'generated key recovery artifact'
    assert rekeys.key_retirement_check(saved['key_token'],saved['old_evidence_key'])['tenant_live_ready']
    trusted_key = read_document('/checkpoint/custody-public.json')
    for label,target in [('active',saved['case_id']),('purged',saved['purge_case_id'])]:
        assert checkpoints.check_checkpoint_policy(saved['token'],target,saved['checkpoint_digests'][label])['full_current_evidence_coverage']
        assert checkpoints.verify_checkpoint(saved['token'],target,read_document('/checkpoint/custody-'+label+'.json'),
            trusted_key,saved['checkpoint_digests'][label])['custody_prefixes_match']
    try:
        checkpoints.set_checkpoint_policy(saved['token'],saved['retired_checkpoint_key'],3600)
    except AccessDenied:
        pass
    else:
        raise AssertionError('retired checkpoint signer regained authority after recovery')
    principal = service.whoami(saved['token'])
    assert str(principal.organization_id) == saved['org']
    assert str(principal.user_id) == saved['user'] and principal.role == 'owner'
    assert retention.governance(saved['token'],saved['case_id'])['holds'][0]['state']=='active'
    assert retention.reconcile_purge(saved['token'],saved['completed_purge'])['outcome']=='removed'
    assert retention.reconcile_purge(saved['token'],saved['pending_purge'])['outcome']=='absence_confirmed'
    for evidence_id in saved['purged_evidence']:
        try:
            cases.read_evidence(saved['token'],evidence_id)
        except EvidenceError as exc:
            assert str(exc)=='evidence_purged'
        else:
            raise AssertionError('purged evidence became readable')
    assert cases.verify_case(saved['token'],saved['case_id'])['complete']
    assert cases.read_evidence(saved['token'],saved['evidence_id']).reveal()==b'approved recovery fixture'
    assert service.get_task(saved['token'],saved['task'])['id'] in cases.get_case(saved['token'],saved['case_id'])['task_ids']
    assert actions.get_action(saved['token'],saved['action_id'])['state']=='approved'
    assert actions.execute(saved['token'],saved['completed_action_id'])==saved['action_receipt']
    actions.execute(saved['token'],saved['action_id'],checkpoint_digest=saved['checkpoint_digests']['active'])
    assert cases.get_case(saved['token'],saved['case_id'])['case']['state']=='closed'
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
    if sys.argv[1]=='restored':
        envelope = read_document('/checkpoint/custody-active.json')
        anchored = envelope['body']['snapshot']['evidence'][0]
        owner_dsn = make_conninfo(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),dbname='gabriel_vault_restore')
        with connection(owner_dsn,runtime=False) as conn:
            events = conn.execute('SELECT * FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s ORDER BY sequence',
                (saved['org'],anchored['evidence_id'])).fetchall()
            previous = None
            for event in events:
                if event['sequence']<anchored['sequence']:
                    previous = event['event_hash']
                    continue
                instant = event['created_at']+timedelta(microseconds=1)
                head = custody_hash(saved['org'],anchored['evidence_id'],event['sequence'],event['actor_id'],event['event'],previous,instant)
                conn.execute('UPDATE gabriel_identity.custody_events SET previous_hash=%s,event_hash=%s,created_at=%s WHERE organization_id=%s AND evidence_id=%s AND sequence=%s',
                    (previous,head,instant,saved['org'],anchored['evidence_id'],event['sequence']))
                previous = head
        assert cases.custody(saved['token'],anchored['evidence_id'])[-1]['event_hash']==head
        try:
            checkpoints.verify_checkpoint(saved['token'],saved['case_id'],envelope,trusted_key,saved['checkpoint_digests']['active'])
        except EvidenceError as exc:
            assert str(exc)=='checkpoint_custody_changed'
        else:
            raise AssertionError('trusted checkpoint missed privileged restored history rewrite')
        print('PASS: independent signed checkpoint detected privileged valid rehash after restore')
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
    print('PASS: exact policy/approval survived recovery; pending local closure executed and completed receipt replayed')
    print('PASS: legal hold and retention survived recovery; completed purge retained and interrupted unlink reconciled without another deletion')
    print('PASS: externally retained signed custody checkpoints matched active and purged evidence after recovery')
    print('PASS: checkpoint trust/policy/receipts and signer revocation survived recovery; pending closure required the retained external digest')
    print('PASS: encryption rollover and interrupted replacement survived recovery; target-only live ring read verified bytes with immutable custody')
    if sys.argv[1] == 'restored':
        print('PASS: real pg_dump/pg_restore recovered matching row counts and encrypted values with separately retained keys')
else:
    raise SystemExit(2)
