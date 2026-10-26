"""Behavior gates for the one approved batch; hermetic and credential-free."""
from copy import deepcopy
import json
import unittest

from approved_trial import run,verify,export,MODEL,ProbeError


class Client:
    def __init__(self):
        self.posts=[];self.unknown=False;self.wrong_ref=False;self.bad_route=False;self.low_credit=False;self.overcharge=False
    def request(self,method,path,payload=None):
        if path=='/api/v1/key':return dict(data=dict(is_management_key=False,is_provisioning_key=False,
            limit=18,limit_reset='monthly',usage_daily=0,usage_monthly=0,limit_remaining=18))
        if path=='/api/v1/credits':return dict(data=dict(total_credits=0 if self.low_credit else 18,total_usage=0))
        if path=='/api/v1/endpoints/zdr':return dict(data=[] if self.bad_route else [dict(model_id=MODEL,
            provider_name='Cerebras',tag='cerebras/fp16',status=0,
            supported_parameters=['temperature','response_format','max_tokens','reasoning'],
            pricing=dict(prompt='0.0000003',completion='0.000003',request='0'))])
        assert method=='POST' and path=='/api/v1/chat/completions'
        self.posts.append(payload)
        if self.unknown:raise ProbeError('provider_transport_unresolved')
        answer=dict(disposition='abstain',claims=[dict(id='claim-1',statement='Candidate report requires verification.',
            references=['invented' if self.wrong_ref else 'o1'])],alternatives=['Routine activity is possible.'],
            contradictions=['No independent evidence supplied.'],uncertainty=['Event semantics remain unknown.'],
            reported_gaps=['source-unverified'],requested_actions=[])
        return dict(id='fixture-trial',model=MODEL,provider='Cerebras',
            choices=[dict(finish_reason='stop',message=dict(content=json.dumps(answer)))],
            usage=dict(prompt_tokens=500,completion_tokens=100,cost=.01 if self.overcharge else .0002))


class ApprovedBatch(unittest.TestCase):
    def test_five_exact_bodies_and_no_production_admission(self):
        client=Client();packet=export();report=run(client,packet)
        self.assertEqual(client.posts,[row['body'] for row in packet['requests']])
        self.assertEqual(report['validated_calls'],5)
        self.assertEqual(report['reported_cost_usd'],'0.0010')
        self.assertFalse(report['quality_qualified']);self.assertFalse(report['production_admission'])
        self.assertNotIn('claims',json.dumps(report));self.assertNotIn('fixture-trial',json.dumps(report))
    def test_unknown_dispatch_stops_without_retry(self):
        client=Client();client.unknown=True;report=run(client,export())
        self.assertEqual(len(client.posts),1);self.assertEqual(report['unresolved_reserved_usd'],'0.006304')
        self.assertEqual(report['validated_calls'],0)
    def test_changed_approved_body_is_denied_before_network(self):
        packet=deepcopy(export());packet['requests'][0]['body']['model']='changed'
        client=Client()
        with self.assertRaisesRegex(ProbeError,'packet_mismatch'):run(client,packet)
        self.assertEqual(client.posts,[])
    def test_missing_exact_route_sends_nothing(self):
        client=Client();client.bad_route=True;report=run(client,export())
        self.assertEqual(client.posts,[]);self.assertEqual(report['failures'][0]['stage'],'preflight')
    def test_insufficient_credit_sends_nothing(self):
        client=Client();client.low_credit=True;report=run(client,export())
        self.assertEqual(client.posts,[]);self.assertEqual(report['failures'][0]['stage'],'preflight')
    def test_invented_reference_is_rejected_and_not_retried(self):
        client=Client();client.wrong_ref=True;report=run(client,export())
        self.assertEqual(len(client.posts),1);self.assertEqual(report['validated_calls'],0)
        self.assertEqual(report['failures'][0]['stage'],'contract')
        self.assertEqual(report['reported_cost_usd'],'0.0002')
    def test_over_ceiling_response_stops_with_conservative_hold(self):
        client=Client();client.overcharge=True;report=run(client,export())
        self.assertEqual(len(client.posts),1);self.assertEqual(report['unresolved_reserved_usd'],'0.006304')
    def test_failed_journal_prevents_billable_dispatch(self):
        client=Client()
        def broken(event):raise OSError('generated journal failure')
        with self.assertRaises(OSError):run(client,export(),broken)
        self.assertEqual(client.posts,[])


if __name__=='__main__':unittest.main()
