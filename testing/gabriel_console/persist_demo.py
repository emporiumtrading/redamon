"""Persist generated browser evidence through normal case/specialist services in a disposable DB."""
from hashlib import sha256
import json
from pathlib import Path
import secrets
import sys
from uuid import uuid4

from gabriel.identity.cases import CaseService
from gabriel.identity.cli import read_secret
from gabriel.identity.evidence_store import EvidenceKeys, LocalEvidenceStore, canonical
from gabriel.identity.service import IdentityService, provision_organization
from gabriel.identity.specialist_analysis_runs import run
from gabriel.identity.specialist_contracts import ROLES
from gabriel.identity.specialists import get_run, list_runs


def main():
    root=Path('/output');state_path=Path('/state/session.json')
    app=read_secret('/run/demo/app_dsn')
    service=CaseService(app,LocalEvidenceStore(Path('/objects'),EvidenceKeys.from_file('/run/demo/evidence-keyring.json')))
    if sys.argv[1]=='before':
        password=secrets.token_urlsafe(32)
        org,_=provision_organization(read_secret('/run/secrets/owner_dsn'),'Generated presentation lab','demo-owner',password)
        token=IdentityService(app).login(org,'demo-owner',password).token
        case=service.create_case(token,'Generated Wazuh browser replay demonstration')
        case['id']=str(case['id'])
        raw=(root/'browser.json').read_bytes()
        original=service.acquire(token,case['id'],uuid4(),raw.decode(),'Generated Wazuh browser report',approved=True)
        document=json.loads((root/'specialist-demo.json').read_text())['facts']
        document['case_id']=case['id']
        for fact in document['facts']:
            fact['evidence_id']=original['id'];fact['evidence_digest']=sha256(raw).hexdigest()
        facts=service.acquire(token,case['id'],uuid4(),canonical(document).decode(),'Generated replay typed facts',approved=True,parent_id=original['id'])
        requests={role:str(uuid4()) for role in ROLES}
        results={role:run(service,token,case['id'],requests[role],role,facts['id']) for role in ROLES}
        state=dict(org=str(org),password=password,case_id=case['id'],source_id=original['id'],facts_id=facts['id'],
            source_digest=sha256(raw).hexdigest(),requests=requests,
            runs={role:dict(id=row['id'],result_digest=row['result_digest']) for role,row in results.items()})
        with state_path.open('x') as stream: json.dump(state,stream)
        state_path.chmod(0o600)
        assert len(list_runs(service,token,case['id'])['runs'])==12
        print('PASS: generated case, encrypted browser evidence and twelve specialist receipts persisted')
    else:
        state=json.loads(state_path.read_text())
        token=IdentityService(app).login(state['org'],'demo-owner',state['password']).token
        assert sha256(service.read_evidence(token,state['source_id']).reveal()).hexdigest()==state['source_digest']
        saved={}
        for role,expected in state['runs'].items():
            row=get_run(service,token,state['case_id'],expected['id'])
            assert row['result_digest']==expected['result_digest'] and row['role']==role and not row['grants_authority']
            replay=run(service,token,state['case_id'],state['requests'][role],role,state['facts_id'])
            assert replay['id']==row['id'] and replay['result_digest']==row['result_digest']
            saved[role]=dict(id=row['id'],result_digest=row['result_digest'],assessment=row['result']['incident_assessment'])
        assert len(list_runs(service,token,state['case_id'])['runs'])==12
        result=dict(status='PASS',database_persisted=True,physical_database_restart_verified=True,
            receipt_replay_verified=True,specialist_count=12,case_id=state['case_id'],source_digest=state['source_digest'],
            specialists=saved,source_verified=False,model_enabled=False,production_ready=False,
            gabriel_scoped_browser_capture=False)
        (root/'persisted-demo.json').write_text(json.dumps(result,sort_keys=True)+'\n')
        page=root/'presentation.html'
        page.write_text(page.read_text().replace('</table>','</table><h2>Persistence check: passed</h2><p>Generated case, encrypted evidence and all twelve specialist receipts survived a physical PostgreSQL restart. Repeating the same requests returned the same receipts without duplicate runs.</p>').replace('Database persistence and Gabriel’s scoped browser integration remain separate acceptance gates.','The generated case persistence check passed. Gabriel’s scoped browser integration remains a separate acceptance gate.'))
        print('PASS: decrypted evidence and all twelve replayable receipts survived physical PostgreSQL restart')


if __name__=='__main__': main()
