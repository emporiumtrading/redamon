"""Generated-data Docker upgrade rehearsal; never operates on an existing user installation."""
from pathlib import Path
import json
import os
import secrets
import sys

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo))
from testing.gabriel_identity.installation_journey import connect,request
from tooling.scripts.gabriel_install import Installation,prepare,digest


def main():
    root=Path(sys.argv[1]);root.mkdir(mode=0o700)
    image=sys.argv[2];password=secrets.token_urlsafe(32);app=None
    try:
        directory=root/'existing'
        prepare(directory,18446,image)
        app=Installation(directory);app.start_db()
        owner=app.operator('initialize',dict(organization='Generated rebuild lab',username='owner',password=password))
        cookie,_=connect(directory,app,password)
        program="""import json
from uuid import uuid4
from gabriel.identity.installation import active,service
from gabriel.identity.checkpoints import read_document
s=service();token=read_document(active()/'human.json',private=True)['token']
case=s.create_case(token,'Generated retained rebuild case')
value=s.acquire(token,case['id'],uuid4(),'Generated retained encrypted rebuild evidence','Generated rebuild fixture',approved=True)
print(json.dumps({'case':str(case['id']),'evidence':str(value['id'])}))
"""
        evidence=json.loads(app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',program))
        keys={name:digest(directory/name/'keyring.json') for name in ('provider','evidence')}
        historical="""import os
from gabriel.identity.cli import read_secret
from gabriel.identity.service import connection
with connection(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),runtime=False) as c:
 assert c.execute('SELECT max(version) AS n FROM gabriel_identity.migrations').fetchone()['n']==28
 c.execute('DROP TRIGGER require_completed_model_ceiling ON gabriel_identity.model_settlements')
 c.execute('DROP FUNCTION gabriel_identity.require_completed_model_ceiling()')
 c.execute('ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_outcome_check')
 c.execute('ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_check')
 c.execute("ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_outcome_check CHECK (outcome IN ('operator_reported','not_sent'))")
 c.execute("ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_check CHECK ((outcome='not_sent' AND actual_microusd=0 AND receipt_digest IS NULL) OR (outcome='operator_reported' AND receipt_digest IS NOT NULL))")
 c.execute('ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_plan_bounds')
 c.execute("ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_plan_bounds CHECK ((plan_version='local-coordinator-v1' AND input_evidence_id IS NULL AND max_steps BETWEEN 1 AND 2) OR (plan_version='local-specialist-coordinator-v2' AND input_evidence_id IS NOT NULL AND max_steps=12))")
 c.execute('DELETE FROM gabriel_identity.migrations WHERE version=28')
 assert c.execute('SELECT max(version) AS n FROM gabriel_identity.migrations').fetchone()['n']==27
"""
        app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',historical)
        rebuilt=app.rebuild(root/'before-rebuild',image)
        assert rebuilt['rebuilt'] and rebuilt['original_identity_retained'] and rebuilt['original_keys_retained']
        assert not rebuilt['browser_ai']['production_admitted']
        app=Installation(directory)
        assert {name:digest(directory/name/'keyring.json') for name in keys}==keys
        fresh,_=connect(directory,app,password)
        assert request(directory,18446,'/cases',cookie=cookie)[0]==403
        assert 'Generated retained rebuild case' in request(directory,18446,'/cases',cookie=fresh)[1]
        verify="""import json,os,sys
from gabriel.identity.installation import active,service
from gabriel.identity.checkpoints import read_document
from gabriel.identity.cli import read_secret
from gabriel.identity.service import connection
s=service();token=read_document(active()/'human.json',private=True)['token']
assert s.read_evidence(token,sys.argv[1]).reveal()==b'Generated retained encrypted rebuild evidence'
with connection(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),runtime=False) as c:
 assert c.execute('SELECT max(version) AS n FROM gabriel_identity.migrations').fetchone()['n']==28
print('PASS')
"""
        assert app.compose('run','--rm','--no-deps','-T','--entrypoint','python','operator','-c',verify,evidence['evidence']).strip()==b'PASS'
        assert app.operator('receipt')==owner
        report=dict(status='PASS',schema_from=27,schema_to=28,image=image,owner_retained=True,
            original_keys_retained=True,encrypted_evidence_retained=True,old_cookie_denied=True,
            browser_ai=rebuilt['browser_ai'],environment='generated Docker schema-upgrade rehearsal; native Mac execution not established')
        (root/'rebuild-result.json').write_text(json.dumps(report,indent=2))
        print('PASS: existing project rebuilt; schema 27 to 28; owner, keys and encrypted evidence retained; old cookie denied')
    finally:
        if app:
            try:app.compose('down','--volumes','--remove-orphans')
            except Exception:pass


if __name__=='__main__':main()
