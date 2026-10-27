"""Credential-free behavior tests for the approved conditional batch."""
from copy import deepcopy
import json
import unittest
from approved_trial import run,export,MODEL,ProbeError,REQUESTS


class Client:
    def __init__(self):
        self.posts=[];self.mode='final';self.low=False;self.route=True;self.daily=0
    def request(self,method,path,payload=None):
        if path=='/api/v1/key':return dict(data=dict(is_management_key=False,is_provisioning_key=False,
            limit=18,limit_reset='monthly',usage_daily=self.daily,usage_monthly=0,limit_remaining=18))
        if path=='/api/v1/credits':return dict(data=dict(total_credits=0 if self.low else 18,total_usage=0))
        if path=='/api/v1/endpoints/zdr':return dict(data=[] if not self.route else [dict(model_id=MODEL,
            provider_name='Cerebras',tag='cerebras/fp16',status=0,
            supported_parameters=['temperature','response_format','max_tokens','reasoning'],
            pricing=dict(prompt='0.0000003',completion='0.000003',request='0'))])
        assert method=='POST' and path=='/api/v1/chat/completions'
        self.posts.append(payload)
        if self.mode=='unknown':raise ProbeError('provider_transport_unresolved')
        packet=json.loads(payload['messages'][1]['content']);n=len(packet['tool_results'])
        actions=[]
        if self.mode=='loop' and n<2:actions=[['verify_sources','review_rules'][n]]
        if self.mode=='limit':actions=[['verify_sources','review_rules','review_memory' if packet['role']=='recovery_learning' else 'inspect_timeline'][n]]
        if self.mode=='repeat':actions=['verify_sources']
        if self.mode=='illegal':actions=['external_navigation']
        answer=dict(disposition='abstain',claims=[dict(id='claim-1',statement='Synthetic assertion requires review.',
            references=['invented' if self.mode=='badref' else 'o1'])],alternatives=['Routine activity is possible.'],
            contradictions=['No independent evidence supplied.'],uncertainty=['Source authenticity remains unknown.'],
            reported_gaps=['source-unverified'],requested_actions=actions)
        return dict(id='fixture-'+str(len(self.posts)),model=MODEL,provider='Cerebras',
            choices=[dict(finish_reason='stop',message=dict(content=json.dumps(answer)))],
            usage=dict(prompt_tokens=500,completion_tokens=100,cost=.01 if self.mode=='overcharge' else .0002))


class ApprovedAgentBatch(unittest.TestCase):
    def test_packet_fingerprint_and_24_final_answers(self):
        c=Client();p=export();r=run(c,p)
        self.assertEqual(p['request_set_sha256'],REQUESTS)
        self.assertEqual(c.posts,[x['body'] for x in p['requests'] if not x['tool_history']])
        self.assertEqual(r['completed_scenarios'],24);self.assertEqual(r['validated_calls'],24)
        self.assertEqual(r['reported_cost_usd'],'0.0048')
        self.assertFalse(r['quality_qualified']);self.assertFalse(r['production_admission'])
        self.assertNotIn('claims',json.dumps(r));self.assertNotIn('fixture-',json.dumps(r))
    def test_actual_tool_history_selects_exact_72_bodies(self):
        c=Client();c.mode='loop';p=export();r=run(c,p)
        expected=[x['body'] for x in p['requests'] if x['tool_history'] in [[],['verify_sources'],['verify_sources','review_rules']]]
        self.assertEqual(c.posts,expected);self.assertEqual(r['attempted_calls'],72)
        self.assertEqual(r['completed_scenarios'],24);self.assertEqual(r['reported_cost_usd'],'0.0144')
    def test_round_limit_and_repeat_stop_each_scenario(self):
        for mode,calls,state in [('limit',72,'round_limit'),('repeat',48,'repeated_tool')]:
            c=Client();c.mode=mode;r=run(c,export())
            self.assertEqual(r['attempted_calls'],calls);self.assertEqual(r['completed_scenarios'],24)
            self.assertEqual(r['results'][-1]['loop_state'],state)
    def test_unknown_or_over_ceiling_holds_reservation_and_stops(self):
        for mode in ['unknown','overcharge']:
            c=Client();c.mode=mode;r=run(c,export())
            self.assertEqual(len(c.posts),1);self.assertEqual(r['unresolved_reserved_usd'],'0.006304')
            self.assertEqual(r['validated_calls'],0)
    def test_invalid_reference_or_tool_stops_without_retry(self):
        for mode in ['badref','illegal']:
            c=Client();c.mode=mode;r=run(c,export())
            self.assertEqual(len(c.posts),1);self.assertEqual(r['failures'][0]['stage'],'contract')
            self.assertEqual(r['reported_cost_usd'],'0.0002')
    def test_credit_route_or_daily_budget_denies_before_dispatch(self):
        for field,value in [('low',True),('route',False),('daily',.004)]:
            c=Client();setattr(c,field,value);r=run(c,export())
            self.assertEqual(c.posts,[]);self.assertEqual(r['failures'][0]['stage'],'preflight')
    def test_changed_body_is_rejected_before_network(self):
        c=Client();p=deepcopy(export());p['requests'][0]['body']['model']='changed'
        with self.assertRaisesRegex(ProbeError,'packet_mismatch'):run(c,p)
        self.assertEqual(c.posts,[])
    def test_journal_failure_prevents_dispatch(self):
        c=Client()
        def broken(event):raise OSError('journal unavailable')
        with self.assertRaises(OSError):run(c,export(),broken)
        self.assertEqual(c.posts,[])


if __name__=='__main__':unittest.main()
