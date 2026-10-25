"""Real encrypted storage/rotation with generated fixture credentials and PostgreSQL."""
import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from gabriel.identity.service import (AccessDenied, AuthenticationDenied, IdentityConfigurationError,
    IdentityUnavailable, InvalidIdentityInput, migrate, provision_organization)
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.vault import ProviderKeyRing, ProviderVault, SecretUnavailable
from testing.gabriel_identity.test_identity_integration import database, tenant, owner_connection
from testing.gabriel_identity.db_history import remove_v4

pytestmark = pytest.mark.integration


def fresh_ring(previous=None):
    key_id = 'test_' + uuid4().hex
    keys = dict(previous._keys) if previous else {}
    keys[key_id] = secrets.token_bytes(32)
    return ProviderKeyRing(key_id,keys,previous.generation+1 if previous else 1)


@pytest.fixture
def vault(tenant):
    ring = fresh_ring()
    service = ProviderVault(tenant.db.app,ring)
    value = 'generated-fixture-' + secrets.token_urlsafe(32)
    service.put(tenant.token,'model_alpha',value)
    return service,ring,value


def stored(tenant):
    with owner_connection(tenant.db) as conn:
        return conn.execute('SELECT * FROM gabriel_identity.provider_secrets WHERE organization_id=%s ORDER BY provider', (tenant.org,)).fetchall()


def test_real_ciphertext_and_redacted_backend_credential(tenant,vault):
    service,ring,value = vault
    row = stored(tenant)[0]
    assert value.encode() not in bytes(row['ciphertext'])
    assert len(row['nonce'])==12 and len(row['ciphertext'])==len(value.encode())+16
    credential = service.resolve_for_backend(tenant.token,'model_alpha')
    assert credential.reveal()==value
    assert value not in repr(credential) and value not in str(credential)
    assert ring._key(ring.active).hex() not in repr(ring)
    with pytest.raises(TypeError):
        json.dumps(credential)
    assert value not in json.dumps(service.list_secrets(tenant.token),default=str)
    with owner_connection(tenant.db) as conn:
        rows = conn.execute('SELECT * FROM gabriel_identity.audit_events WHERE organization_id=%s',(tenant.org,)).fetchall()
        assert value not in repr(rows) and ring._key(ring.active) not in repr(rows).encode()
    assert ProviderVault(tenant.db.app,ring).resolve_for_backend(tenant.token,'model_alpha').reveal()==value


def test_replacement_has_new_nonce_and_revision(tenant,vault):
    service,_,value = vault
    before = stored(tenant)[0]
    result = service.put(tenant.token,'model_alpha',value)
    after = stored(tenant)[0]
    assert before['id']==after['id'] and result['revision']==2
    assert before['nonce']!=after['nonce'] and before['ciphertext']!=after['ciphertext']
    assert service.resolve_for_backend(tenant.token,'model_alpha').reveal()==value


def test_tenant_separation_including_same_provider_name(tenant,vault):
    service,ring,value = vault
    secret = secrets.token_urlsafe(24)
    org,_ = provision_organization(tenant.db.owner,'Other vault fixture','owner',secret)
    token = service.login(org,'owner',secret).token
    assert service.list_secrets(token)==[]
    for call in (lambda:service.resolve_for_backend(token,'model_alpha'),lambda:service.revoke(token,'model_alpha')):
        with pytest.raises(AccessDenied):
            call()
    other = 'other-fixture-'+secrets.token_urlsafe(24)
    service.put(token,'model_alpha',other)
    assert service.resolve_for_backend(token,'model_alpha').reveal()==other
    assert service.resolve_for_backend(tenant.token,'model_alpha').reveal()==value


@pytest.mark.parametrize('role',['analyst','viewer','service'])
def test_unprivileged_credentials_cannot_access_vault(tenant,vault,role):
    service,_,_ = vault
    if role=='service':
        worker = ServiceIdentityService(tenant.db.app)
        task = worker.create_task(tenant.token,'vault denial',['evidence.hash'])['id']
        token = worker.issue_service(tenant.token,'vault denial',task,['evidence.hash']).token
        error = AuthenticationDenied
    else:
        secret = secrets.token_urlsafe(24)
        service.create_member(tenant.token,role,secret,role)
        token = service.login(tenant.org,role,secret).token
        error = AccessDenied
    for call in (lambda:service.put(token,'model_beta','fixture'),lambda:service.list_secrets(token),
                 lambda:service.resolve_for_backend(token,'model_alpha'),lambda:service.rotate(token),
                 lambda:service.revoke(token,'model_alpha')):
        with pytest.raises(error):
            call()


def test_admin_access_and_immediate_role_revocation(tenant,vault):
    service,_,_ = vault
    password = secrets.token_urlsafe(24)
    member = service.create_member(tenant.token,'vault-admin',password,'admin')
    token = service.login(tenant.org,'vault-admin',password).token
    service.put(token,'model_beta','fixture-beta')
    assert service.resolve_for_backend(token,'model_beta').reveal()=='fixture-beta'
    service.set_membership(tenant.token,member,'viewer',True)
    with pytest.raises(AuthenticationDenied):
        service.resolve_for_backend(token,'model_beta')


@pytest.mark.parametrize('field',['ciphertext','nonce','provider','revision','id'])
def test_ciphertext_integrity_and_record_binding(tenant,vault,field):
    service,_,_ = vault
    row = stored(tenant)[0]
    if field in {'ciphertext','nonce'}:
        damaged = bytearray(row[field])
        damaged[0] ^= 1
        value = bytes(damaged)
    else:
        value = {'provider':'renamed_model','revision':2,'id':uuid4()}[field]
    with owner_connection(tenant.db) as conn:
        conn.execute(f'UPDATE gabriel_identity.provider_secrets SET {field}=%s WHERE organization_id=%s AND id=%s',
                     (value,tenant.org,row['id']))
    with pytest.raises(SecretUnavailable):
        service.resolve_for_backend(tenant.token,'renamed_model' if field=='provider' else 'model_alpha')


def test_cross_tenant_row_transplant_cannot_be_decrypted(tenant,vault):
    service,_,_ = vault
    password = secrets.token_urlsafe(24)
    org,user = provision_organization(tenant.db.owner,'Transplant fixture','owner',password)
    token = service.login(org,'owner',password).token
    service.put(token,'model_beta','other-fixture')
    with owner_connection(tenant.db) as conn:
        conn.execute('UPDATE gabriel_identity.provider_secrets SET organization_id=%s,updated_by=%s WHERE organization_id=%s',
                     (org,user,tenant.org))
    with pytest.raises(SecretUnavailable):
        service.resolve_for_backend(token,'model_alpha')


def test_rotation_preserves_values_and_rejects_stale_process(tenant,vault):
    service,ring,value = vault
    service.put(tenant.token,'model_beta','fixture-beta')
    replacement = fresh_ring(ring)
    updated = ProviderVault(tenant.db.app,replacement)
    result = updated.rotate(tenant.token)
    assert result['rewrapped']==2 and result['generation']==2
    assert {row['key_id'] for row in stored(tenant)}=={replacement.active}
    assert updated.resolve_for_backend(tenant.token,'model_alpha').reveal()==value
    assert updated.resolve_for_backend(tenant.token,'model_beta').reveal()=='fixture-beta'
    for call in (lambda:service.put(tenant.token,'model_alpha','stale fixture'),
                 lambda:service.resolve_for_backend(tenant.token,'model_alpha'),lambda:service.rotate(tenant.token)):
        with pytest.raises(IdentityConfigurationError):
            call()
    only_new = ProviderKeyRing(replacement.active,{replacement.active:replacement._key(replacement.active)},2)
    assert ProviderVault(tenant.db.app,only_new).resolve_for_backend(tenant.token,'model_alpha').reveal()==value
    assert updated.rotate(tenant.token)['rewrapped']==0


def test_missing_old_key_blocks_rotation_atomically(tenant,vault):
    service,ring,value = vault
    replacement = fresh_ring(ring)
    only_new = ProviderKeyRing(replacement.active,{replacement.active:replacement._key(replacement.active)},2)
    before = stored(tenant)
    with pytest.raises(SecretUnavailable):
        ProviderVault(tenant.db.app,only_new).rotate(tenant.token)
    assert stored(tenant)==before
    assert service.resolve_for_backend(tenant.token,'model_alpha').reveal()==value


def test_changed_key_bytes_under_same_id_are_rejected(tenant,vault):
    service,ring,value = vault
    wrong = ProviderKeyRing(ring.active,{ring.active:secrets.token_bytes(32)})
    for call in (lambda:ProviderVault(tenant.db.app,wrong).put(tenant.token,'model_alpha','fixture'),
                 lambda:ProviderVault(tenant.db.app,wrong).resolve_for_backend(tenant.token,'model_alpha')):
        with pytest.raises(IdentityConfigurationError):
            call()
    assert service.resolve_for_backend(tenant.token,'model_alpha').reveal()==value


def test_corrupt_record_rolls_back_complete_rotation(tenant,vault):
    service,ring,_ = vault
    service.put(tenant.token,'model_beta','fixture-beta')
    with owner_connection(tenant.db) as conn:
        conn.execute("UPDATE gabriel_identity.provider_secrets SET ciphertext=decode(repeat('00',32),'hex') WHERE organization_id=%s AND provider='model_beta'",(tenant.org,))
    before = stored(tenant)
    with pytest.raises(SecretUnavailable):
        ProviderVault(tenant.db.app,fresh_ring(ring)).rotate(tenant.token)
    assert stored(tenant)==before


def test_audit_failure_blocks_all_secret_results_and_changes(tenant,vault):
    service,ring,value = vault
    before = stored(tenant)
    with owner_connection(tenant.db) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.audit_events FROM gabriel_identity_app')
    try:
        for call in (lambda:service.put(tenant.token,'model_alpha','changed-fixture'),
                     lambda:service.resolve_for_backend(tenant.token,'model_alpha'),
                     lambda:service.revoke(tenant.token,'model_alpha'),
                     lambda:ProviderVault(tenant.db.app,fresh_ring(ring)).rotate(tenant.token)):
            with pytest.raises(IdentityUnavailable):
                call()
    finally:
        with owner_connection(tenant.db) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.audit_events TO gabriel_identity_app')
    assert stored(tenant)==before
    assert service.resolve_for_backend(tenant.token,'model_alpha').reveal()==value


def test_revoke_erases_current_ciphertext_and_replacement_restores_access(tenant,vault):
    service,_,_ = vault
    service.revoke(tenant.token,'model_alpha')
    row = stored(tenant)[0]
    assert row['revoked_at'] and row['ciphertext'] is row['nonce'] is row['key_id'] is None
    with pytest.raises(AccessDenied):
        service.resolve_for_backend(tenant.token,'model_alpha')
    service.put(tenant.token,'model_alpha','replacement-fixture')
    assert service.resolve_for_backend(tenant.token,'model_alpha').reveal()=='replacement-fixture'


def test_concurrent_put_and_rotation_use_one_lock_order(tenant,vault):
    service,ring,value = vault
    replacement = ProviderVault(tenant.db.app,fresh_ring(ring))
    def write():
        try:
            return service.put(tenant.token,'model_alpha','concurrent-fixture')
        except IdentityConfigurationError:
            return 'stale key denied'
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(write)
        replacement.rotate(tenant.token)
        assert future.result() is not None
    assert replacement.resolve_for_backend(tenant.token,'model_alpha').reveal() in {value,'concurrent-fixture'}
    assert {row['key_id'] for row in stored(tenant)}=={replacement._ring.active}


@pytest.mark.parametrize('operation',['UPDATE','DELETE','TRUNCATE'])
def test_runtime_cannot_rewrite_key_registry(tenant,vault,operation):
    query = {'UPDATE':"UPDATE gabriel_identity.provider_key_registry SET fingerprint=repeat('0',64)",
        'DELETE':'DELETE FROM gabriel_identity.provider_key_registry','TRUNCATE':'TRUNCATE gabriel_identity.provider_key_registry'}[operation]
    with psycopg.connect(tenant.db.app) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query)
        conn.rollback()


def test_provider_count_is_bounded(tenant,vault):
    service,_,_ = vault
    for i in range(63):
        service.put(tenant.token,f'model_{i}','bounded-fixture')
    assert len(service.list_secrets(tenant.token))==64
    with pytest.raises(AccessDenied):
        service.put(tenant.token,'overflow','bounded-fixture')
    assert service.put(tenant.token,'model_alpha','replacement-fixture')['revision']==2


@pytest.mark.parametrize('provider,value',[('bad/provider','fixture'),('model',''),('model','x'*8193),
    ('model','secret\nvalue'),('model','\ud800'),(None,'fixture'),('model',None)])
def test_invalid_secret_inputs_are_bounded_and_redacted(tenant,vault,provider,value):
    with pytest.raises(InvalidIdentityInput) as exc:
        vault[0].put(tenant.token,provider,value)
    assert str(exc.value) in {'invalid_model_provider','invalid_provider_secret'}


def keyfile(path,ring):
    path.write_text(json.dumps({'schema_version':1,'generation':ring.generation,'active':ring.active,
        'keys':{k:base64.b64encode(v).decode() for k,v in ring._keys.items()}}))
    path.chmod(0o600)
    return path


def test_key_file_and_prepare_rotation_never_overwrite(tmp_path):
    module_path = Path(__file__).resolve().parents[2]/'tooling/scripts/gabriel_provider_keys.py'
    spec = importlib.util.spec_from_file_location('provider_keys',module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    first = module.prepare(tmp_path/'first')
    original = (first/'keyring.json').read_bytes()
    second = module.prepare(tmp_path/'second',first/'keyring.json')
    old,new = ProviderKeyRing.from_file(first/'keyring.json'),ProviderKeyRing.from_file(second/'keyring.json')
    assert old.active!=new.active and new.generation==2
    assert old._key(old.active)==new._key(old.active)
    assert first.stat().st_mode & 0o777==0o700
    assert (first/'keyring.json').stat().st_mode & 0o777==0o444
    with pytest.raises(FileExistsError):
        module.prepare(first)
    assert (first/'keyring.json').read_bytes()==original
    with pytest.raises(ValueError):
        module.prepare(module_path.parents[2]/'unsafe-provider-keys')


@pytest.mark.parametrize('kind',['missing','malformed','duplicate','oversize','symlink','writable','bad_key','wrong_schema'])
def test_invalid_or_missing_key_files_fail_closed(tmp_path,kind):
    path = tmp_path/'ring'
    if kind=='missing':
        with pytest.raises(IdentityConfigurationError):
            ProviderKeyRing.from_file(None)
        return
    keyfile(path,fresh_ring())
    if kind=='malformed':
        path.write_text('{')
    elif kind=='duplicate':
        path.write_text('{"schema_version":1,"schema_version":1,"active":"a","keys":{},"generation":1}')
    elif kind=='oversize':
        path.write_text('x'*8193)
    elif kind=='symlink':
        link = tmp_path/'link'
        link.symlink_to(path)
        path = link
    elif kind=='writable':
        path.chmod(0o666)
    elif kind=='bad_key':
        path.write_text('{"schema_version":1,"generation":1,"active":"a","keys":{"a":"AAAA"}}')
    elif kind=='wrong_schema':
        data = json.loads(path.read_text())
        data['schema_version'] = True
        path.write_text(json.dumps(data))
    with pytest.raises(IdentityConfigurationError):
        ProviderKeyRing.from_file(path)


def test_cli_put_metadata_rotate_and_revoke_never_print_secret(tenant,tmp_path):
    ring = fresh_ring()
    config = keyfile(tmp_path/'keys',ring)
    tokenfile = tmp_path/'token'
    tokenfile.write_text(tenant.token)
    secretfile = tmp_path/'fixture'
    secretfile.write_text('private-generated-fixture-'+secrets.token_urlsafe(24))
    env = {**os.environ,'GABRIEL_PROVIDER_KEYRING_FILE':str(config)}
    def run(*args,custom_env=None):
        result = subprocess.run([sys.executable,'-m','gabriel.identity.vault_cli',*args,'--token-file',str(tokenfile)],
            capture_output=True,text=True,timeout=10,env=custom_env or env)
        assert not result.stderr
        assert tenant.token not in result.stdout and secretfile.read_text() not in result.stdout
        assert tenant.db.app not in result.stdout and base64.b64encode(ring._key(ring.active)).decode() not in result.stdout
        return result.returncode,json.loads(result.stdout)
    assert run('put','--provider','model_alpha','--secret-file',str(secretfile))[0]==0
    assert run('list')[0]==0
    replacement = fresh_ring(ring)
    config2 = keyfile(tmp_path/'new_keys',replacement)
    new_env = {**env,'GABRIEL_PROVIDER_KEYRING_FILE':str(config2)}
    code,result = run('rotate',custom_env=new_env)
    assert code==0 and result['result']['rewrapped']==1
    assert run('put','--provider','model_alpha','--secret-file',str(secretfile))[0]==1
    assert run('revoke','--provider','model_alpha',custom_env=new_env)[0]==0
    missing = {**env,'GABRIEL_PROVIDER_KEYRING_FILE':str(tmp_path/'missing')}
    code,result = run('list',custom_env=missing)
    assert code==1 and result['status']=='denied'


def test_v2_upgrade_preserves_identity_and_revokes_unbound_service_grant(tenant):
    identity = ServiceIdentityService(tenant.db.app)
    task = identity.create_task(tenant.token,'upgrade fixture',['evidence.hash'])['id']
    grant = identity.issue_service(tenant.token,'upgrade fixture',task,['evidence.hash'])
    with owner_connection(tenant.db) as conn:
        remove_v4(conn)
        conn.execute('''DROP TABLE gabriel_identity.provider_secrets,gabriel_identity.provider_key_state,
            gabriel_identity.provider_key_registry''')
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=3')
    migrate(tenant.db.owner)
    migrate(tenant.db.owner)
    assert identity.whoami(tenant.token).user_id==tenant.owner
    with pytest.raises(AuthenticationDenied):
        identity.execute_service(grant.token,task,{'schema_version':1,'operation':'evidence.hash','arguments':{'content':'upgrade fixture'}},uuid4())
    new_task = identity.create_task(tenant.token,'post upgrade',['evidence.hash'])['id']
    new_grant = identity.issue_service(tenant.token,'post upgrade',new_task,['evidence.hash'])
    assert identity.execute_service(new_grant.token,new_task,{'schema_version':1,'operation':'evidence.hash','arguments':{'content':'upgrade fixture'}},uuid4())['service_id']==str(new_grant.id)
    vault = ProviderVault(tenant.db.app,fresh_ring())
    vault.put(tenant.token,'model_alpha','upgrade-fixture')
    assert vault.resolve_for_backend(tenant.token,'model_alpha').reveal()=='upgrade-fixture'
