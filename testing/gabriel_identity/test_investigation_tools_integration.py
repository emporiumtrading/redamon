"""Real private toolbox, PostgreSQL/custody, encrypted reports and HTTPS permissions."""
import base64
import http.client
import json
import os
from uuid import uuid4

import pytest

from gabriel.identity import investigation_tools as tools
from gabriel.identity.service import AccessDenied
from testing.gabriel_identity.test_identity_integration import database,tenant,owner_connection
from testing.gabriel_identity.test_cases_integration import cases,case,evidence
from testing.gabriel_identity.test_specialist_analysis_integration import intake
from testing.gabriel_identity.test_investigation_tools import capture,logs
from testing.gabriel_identity.test_workbench_integration import boot,server,connect,call,csrf
from testing.gabriel_identity.test_specialist_agents_integration import setup

pytestmark=pytest.mark.integration


@pytest.fixture(autouse=True)
def toolbox():
    status=tools.remote('inspect_toolkit')
    if status.get('status')!='ready':
        if os.environ.get('GABRIEL_REQUIRE_TOOLBOX')=='1':pytest.fail('private_toolbox_required')
        pytest.skip('private toolbox service required')


@pytest.mark.parametrize('name,content,role',[
    ('scan_artifacts','generated powershell -EncodedCommand example','dfir_evidence'),
    ('inspect_packets',capture().decode(),'incident_scoping'),
    ('inspect_logs',logs().decode(),'identity_access'),
])
def test_source_bytes_reach_real_tools_and_only_minimized_results_return(tenant,cases,case,name,content,role):
    source=cases.acquire(tenant.token,case['id'],uuid4(),content,'Generated tool source',approved=True)
    kind,data=('artifact',dict(integrity='match',custody='complete')) if role=='dfir_evidence' else ('activity',dict(category='network',outcome='failure',count=5)) if role=='incident_scoping' else ('identity',dict(event='mfa_disabled',authorized='no'))
    _,holder=intake(tenant,cases,case,source,kind,data)
    result=tools.inspect(cases,tenant.token,case['id'],holder['id'],role,name,uuid4())
    item=result['result']['result']['artifacts'][0]
    assert item['status']=='analyzed' and not result['model_used']
    if name=='scan_artifacts':assert item['matched_rule_ids']==['powershell_encoded_command']
    elif name=='inspect_packets':assert item['packet_count']==1
    else:assert item['failure_burst_then_success_groups']==1
    assert content not in json.dumps(result['result']) and str(source['id']) not in json.dumps(result['result'])
    report=json.loads(cases.read_evidence(tenant.token,result['report_evidence_id']).reveal())
    assert report['requires_review'] and report['tool_result']==result['result']


def test_unowned_case_and_disallowed_role_tools_do_not_contact_worker(tenant,cases,case,evidence,monkeypatch):
    _,holder=intake(tenant,cases,case,evidence)
    def denied(*args):raise AssertionError('unauthorized remote call')
    monkeypatch.setattr(tools,'remote',denied)
    with pytest.raises(AccessDenied,match='not_admitted'):
        tools.execute(cases,tenant.token,case['id'],holder['id'],'exposure_vulnerability','scan_artifacts')
    other=cases.create_case(tenant.token,'Generated other case')
    with pytest.raises(AccessDenied):tools.execute(cases,tenant.token,other['id'],holder['id'],'alert_triage','inspect_logs')


def test_worker_refuses_unknown_commands_and_never_returns_source_text():
    client=http.client.HTTPConnection('investigation-tools',8450,timeout=8)
    client.request('POST','/analyze',body=json.dumps(dict(tool='shell',data=base64.b64encode(b'private generated source').decode())),headers={'Content-Type':'application/json'})
    response=client.getresponse();body=response.read();client.close()
    assert response.status==422 and b'private generated source' not in body


@pytest.mark.parametrize('boot',['owner','analyst'],indirect=True)
def test_local_tool_form_works_without_a_model_call_and_requires_csrf(server,cases,tenant,case,evidence):
    _,holder=intake(tenant,cases,case,evidence)
    cookie,_,_=connect(server)
    status,html,_=call(server,'/cases/'+str(case['id'])+'/agents',cookie=cookie)
    assert status==200 and 'Run local investigation tool' in html and 'Apache-2.0' in html
    fields=dict(csrf=csrf(html),request_id=str(uuid4()),input_evidence_id=str(holder['id']),role_tool='alert_triage/review_rules',approved='yes')
    status,html,_=call(server,'/cases/'+str(case['id'])+'/tools',fields,cookie=cookie)
    assert status==200 and 'No model call was made' in html
    fields['csrf']='invalid'
    assert call(server,'/cases/'+str(case['id'])+'/tools',fields,cookie=cookie)[0]==403


def test_logout_during_parser_call_blocks_result_publication(tenant,cases,case,evidence,monkeypatch):
    doc,holder=intake(tenant,cases,case,evidence)
    extra=cases.acquire(tenant.token,case['id'],uuid4(),'Generated second source','Generated second source',approved=True)
    doc['facts'].append(dict(doc['facts'][0],id=str(uuid4()),evidence_id=str(extra['id']),evidence_digest=extra['digest']))
    holder=cases.acquire(tenant.token,case['id'],uuid4(),json.dumps(doc),'Generated multi-source facts',approved=True)
    original=tools.remote;calls=[]
    def revoke(name,data=None):
        result=original(name,data)
        if name=='inspect_logs':
            calls.append(name);cases.logout(tenant.token)
        return result
    monkeypatch.setattr(tools,'remote',revoke)
    from gabriel.identity.service import AuthenticationDenied
    with pytest.raises(AuthenticationDenied):
        tools.inspect(cases,tenant.token,case['id'],holder['id'],'alert_triage','inspect_logs',uuid4())
    assert calls==['inspect_logs']


def test_agent_model_tool_model_loop_executes_real_yara_without_exporting_raw_bytes(tenant,cases,case,setup):
    from gabriel.identity import specialist_agents as agents
    content='Generated private artifact: powershell -EncodedCommand example-only'
    source=cases.acquire(tenant.token,case['id'],uuid4(),content,'Generated artifact source',approved=True)
    _,holder=intake(tenant,cases,case,source,'artifact',dict(integrity='match',custody='complete'))
    setup['client'].chosen_tool='scan_artifacts'
    result=agents.start(cases,setup['vault'],setup['token'],case['id'],uuid4(),'dfir_evidence',holder['id'],approved=True)
    assert len(result['steps'])==2 and len(setup['posts'])==2
    second=json.loads(setup['posts'][1]['messages'][1]['content'])
    scan=next(t for t in second['tool_results'] if t['tool']=='scan_artifacts')
    assert scan['result']['artifacts'][0]['matched_rule_ids']==['powershell_encoded_command']
    assert scan['result']['artifacts'][0]['references']==['o1']
    assert content not in json.dumps(setup['posts']) and setup['secret'] not in json.dumps(second)
    assert 'Use scan_artifacts' in setup['posts'][0]['messages'][0]['content']
