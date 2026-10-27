"""Offline fault injection; no real credential or transport is used."""
from copy import deepcopy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import runner
from packet import export


class Client:
    def __init__(self, alter=None):self.posts=[];self.gets=[];self.alter=alter
    def request(self,method,path,body=None):
        if method=='GET':
            self.gets.append(path)
            if path.endswith('/key'):return {'data':dict(is_management_key=False,is_provisioning_key=False,limit=18,limit_reset='monthly',usage_daily=0,usage_monthly=0,limit_remaining=18)}
            if path.endswith('/credits'):return {'data':dict(total_credits=18,total_usage=0)}
            return {'data':[dict(model_id='openai/gpt-oss-120b',provider_name='Cerebras',tag='cerebras/fp16',status=0,
                supported_parameters=['temperature','response_format','max_tokens','reasoning'],pricing=dict(prompt='0.0000005',completion='0.000003'))]}
        self.posts.append(deepcopy(body))
        packet=json.loads(body['messages'][1]['content'])
        plan=packet.get('stage')=='plan'
        decision=dict(disposition='abstain',claims=[dict(id='claim-1',statement='Bounded fixture observation.',references=['o1'])],
            alternatives=['Routine activity is possible.'],contradictions=['None supplied.'],uncertainty=['Source authenticity is unverified.'],
            reported_gaps=[],requested_actions=['exposure_vulnerability'] if plan else [])
        reply=dict(id='generation-'+str(len(self.posts)),model='openai/gpt-oss-120b',provider='Cerebras',usage=dict(prompt_tokens=100,completion_tokens=100,cost='0.0001'),
            choices=[dict(finish_reason='stop',message=dict(content=json.dumps(decision)))])
        if self.alter:self.alter(reply)
        return reply


class Runner(unittest.TestCase):
    def setUp(self):self.packet=export();self.approval=self.packet['request_set_sha256']
    def run_fake(self,client):return runner.run(client,self.packet,self.approval,lambda _:None)
    def test_wrong_approval_or_changed_body_never_reaches_transport(self):
        client=Client()
        for packet,approval in [(self.packet,'wrong'),(dict(self.packet,model='changed'),self.approval)]:
            with self.assertRaises(runner.ProbeError):runner.run(client,packet,approval,lambda _:None)
        self.assertEqual(client.gets+client.posts,[])
    def test_exactly_26_bodies_and_no_followup_or_qualification(self):
        client=Client();journal=[]
        result=runner.run(client,self.packet,self.approval,journal.append)
        self.assertEqual(result['failures'],[]);self.assertEqual(result['validated_calls'],26)
        self.assertEqual(client.posts,[r['body'] for r in self.packet['requests']])
        self.assertEqual(len(journal),52);self.assertFalse(result['production_admission'])
        self.assertNotIn('statement',json.dumps(result));self.assertEqual(result['independent_review'],'pending')
    def test_uncertain_dispatch_and_contract_errors_stop_without_retry(self):
        def bad_ref(reply):reply['choices'][0]['message']['content']=reply['choices'][0]['message']['content'].replace('o1','unknown')
        for alter,stage in [(lambda r:r.update(provider='Other'),'dispatch'),(lambda r:r['usage'].update(cost='0.007'),'dispatch'),
            (bad_ref,'contract'),(lambda r:r['choices'][0].update(finish_reason='length'),'contract')]:
            client=Client(alter);result=self.run_fake(client)
            self.assertEqual(len(client.posts),1);self.assertEqual(result['validated_calls'],0)
            self.assertEqual(result['failures'][0]['stage'],stage)
            self.assertEqual(result['unresolved_reserved_usd'],'0.006304' if stage=='dispatch' else '0')
    def test_duplicate_generation_stops_second_dispatch(self):
        client=Client(lambda r:r.update(id='same-generation'));result=self.run_fake(client)
        self.assertEqual(len(client.posts),2);self.assertEqual(result['validated_calls'],1)
        self.assertEqual(result['failures'][0]['reason'],'duplicate_generation')
    def test_funding_and_route_fail_closed_before_post(self):
        for path,replacement in [('/key',{'data':dict(is_management_key=True)}),('/credits',{'data':dict(total_credits=0,total_usage=0)}),('/zdr',{'data':[]})]:
            client=Client();original=client.request
            def request(method,url,body=None):return replacement if url.endswith(path) else original(method,url,body)
            client.request=request;result=self.run_fake(client)
            self.assertEqual(client.posts,[]);self.assertEqual(result['failures'][0]['stage'],'preflight')
    def test_failed_durable_reservation_prevents_post(self):
        client=Client()
        def checkpoint(_):raise OSError('disk full')
        with self.assertRaises(OSError):runner.run(client,self.packet,self.approval,checkpoint)
        self.assertEqual(client.posts,[])
    def test_private_cli_single_use_and_no_secret_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'private';client=Client()
            args=['--approve-request-set',self.approval,'--private-results',str(root)]
            with patch.dict(os.environ,{'OPENROUTER_API_KEY':'dummy-offline-credential'}),patch.object(runner,'OpenRouterTransport',return_value=client),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(args),0)
                with self.assertRaises(FileExistsError):runner.main(args)
            self.assertEqual(len(client.posts),26)
            self.assertEqual(root.stat().st_mode&0o777,0o700)
            journal=root/'events.jsonl';self.assertEqual(journal.stat().st_mode&0o777,0o600)
            self.assertNotIn('dummy-offline-credential',journal.read_text())
    def test_cli_approval_and_permissions_checked_before_credential_transport(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(runner,'OpenRouterTransport') as transport:
            root=Path(temp)/'private'
            with self.assertRaises(runner.ProbeError):runner.main(['--approve-request-set','wrong','--private-results',str(root)])
            self.assertFalse(root.exists())
            root.mkdir(mode=0o755);root.chmod(0o755)
            with self.assertRaises(runner.ProbeError):runner.main(['--approve-request-set',self.approval,'--private-results',str(root)])
            transport.assert_not_called()


if __name__=='__main__':unittest.main()
