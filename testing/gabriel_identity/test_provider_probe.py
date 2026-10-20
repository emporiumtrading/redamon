"""Software protocol tests with explicit fake HTTP responses, never model evidence."""
from copy import deepcopy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch,Mock

from gabriel.identity.model_evaluation import load_json,packets
from gabriel.identity.provider_probe import (
    HOST,MODELS,COMPARISON_MODEL,ROUTES,OpenRouterProbe,ProbeError,budget_check,decode,request_body,response_record,run_probe,route_check,
)

SECRET='generated-unit-credential-not-a-live-key'


def corpus():
    path=Path('/app/development_corpus.json')
    if not path.exists():
        path=Path(__file__).resolve().parents[1]/'gabriel_model_lab'/'development_corpus.json'
    return load_json(path)


def key_data():
    return dict(is_management_key=False,is_provisioning_key=False,limit=18,
                limit_reset='monthly',limit_remaining=18,usage_daily=0,usage_monthly=0,
                byok_usage_daily=0,byok_usage_monthly=0)


def answer(model=MODELS[0]):
    decision=dict(disposition='escalate',claims=[dict(id='c1',statement='Investigate correlated suspicious access',references=['auth-1','auth-2'])],
        alternatives=['An authorized change should be checked.'],contradictions=['No matching change is supplied.'],
        uncertainty=['Identity attribution remains unverified.'],reported_gaps=[],requested_actions=[])
    return dict(id='generated-protocol-fixture',model=model,provider=ROUTES[model][0],
                choices=[dict(finish_reason='stop',message=dict(content=json.dumps(decision)))],
                usage=dict(prompt_tokens=400,completion_tokens=160,cost=0.00012))


class FixtureClient:
    """Only a software test double; no test outcome qualifies a provider."""
    def __init__(self, fail_at=None):
        self.requests=[]
        self.fail_at=fail_at

    def request(self, method,path,payload=None):
        self.requests.append((method,path,payload))
        if len(self.requests)==self.fail_at:
            raise ProbeError('fixture_transport_failure')
        if method=='GET':
            if path.endswith('/endpoints'):
                model=path.removeprefix('/api/v1/models/').removesuffix('/endpoints')
                provider,slug,_=ROUTES[model]
                return {'data':dict(id=model,endpoints=[dict(provider_name=provider,tag=slug,status=0)])}
            return {'data':key_data()}
        result=answer(payload['model'])
        result['id']='fixture-'+str(len(self.requests))
        return result


class ProviderProbeTests(unittest.TestCase):
    def test_comparison_is_one_explicit_fixed_route_without_relaxed_privacy(self):
        client=FixtureClient()
        result=run_probe(client,corpus(),models=(COMPARISON_MODEL,))
        self.assertEqual(result['status'],'probe_complete')
        self.assertEqual(result['completed_calls'],1)
        self.assertEqual(result['attempted_calls'],1)
        self.assertFalse(result['production_admission'])
        body=client.requests[-1][2]
        self.assertEqual(body['provider']['only'],['azure'])
        self.assertTrue(body['provider']['zdr'])
        self.assertEqual(body['provider']['data_collection'],'deny')
        self.assertFalse(body['provider']['allow_fallbacks'])
        self.assertTrue(body['provider']['require_parameters'])
        self.assertEqual(body['max_completion_tokens'],768)
        self.assertNotIn('reasoning',body)
        self.assertNotIn('max_tokens',body)
        self.assertEqual(result['results'][0]['configuration']['endpoint_policy'],'generated-lab-zdr-azure-v1')

    def test_arbitrary_schedule_never_reads_key_or_calls_provider(self):
        for schedule in ((COMPARISON_MODEL,COMPARISON_MODEL),MODELS+(COMPARISON_MODEL,),('unapproved/model',)):
            client=FixtureClient()
            with self.assertRaises(ProbeError): run_probe(client,corpus(),models=schedule)
            self.assertFalse(client.requests)

    def test_comparison_never_uses_first_party_openai_instead_of_azure(self):
        packet=packets(corpus(),'development')[0]
        body=request_body(COMPARISON_MODEL,packet)
        reply=answer(COMPARISON_MODEL)
        reply['provider']='OpenAI'
        with self.assertRaises(ProbeError): response_record(reply,COMPARISON_MODEL,packet,body,10)
        with self.assertRaises(ProbeError):
            route_check({'data':dict(id=COMPARISON_MODEL,endpoints=[dict(
                provider_name='OpenAI',tag='openai',status=0)])},COMPARISON_MODEL)

    def test_key_preflight_requires_explicit_small_monthly_inference_key(self):
        self.assertEqual(budget_check(key_data())['monthly_limit_usd'],'18')
        changes=[('limit',None),('limit',19),('limit',True),('limit_reset',None),
                 ('is_management_key',True),('is_provisioning_key',True),
                 ('usage_daily',0.49),('usage_monthly',18),('limit_remaining',0.01),
                 ('usage_daily',float('nan')),('byok_usage_daily',0.49)]
        for key,value in changes:
            with self.subTest(key=key,value=value),self.assertRaises(ProbeError):
                budget_check({**key_data(),key:value})

    def test_key_and_client_representations_never_expose_credentials(self):
        self.assertNotIn(SECRET,repr(OpenRouterProbe(SECRET)))
        for value in ('','short','x'*513,' '*24,'x'*24+'\n'):
            with self.assertRaises(ProbeError): OpenRouterProbe(value)

    def test_request_preserves_privacy_prices_and_no_fallback(self):
        packet=packets(corpus(),'development')[0]
        body=request_body(MODELS[0],packet)
        self.assertTrue(body['provider']['zdr'])
        self.assertEqual(body['provider']['data_collection'],'deny')
        self.assertEqual(body['provider']['only'],['google-vertex'])
        self.assertFalse(body['provider']['allow_fallbacks'])
        self.assertTrue(body['provider']['require_parameters'])
        self.assertEqual(body['max_tokens'],768)
        self.assertFalse(body['reasoning']['enabled'])
        sent=json.loads(body['messages'][1]['content'])
        self.assertEqual(set(sent),{'question','observations'})
        self.assertNotIn(packet['case_id'],body['messages'][1]['content'])
        self.assertLess(len(json.dumps(body).encode()),7000)
        with self.assertRaises(ProbeError): request_body('unapproved/model',packet)

    def test_two_calls_preflight_each_and_never_grant_production_authority(self):
        client=FixtureClient()
        result=run_probe(client,corpus())
        self.assertEqual(result['status'],'probe_complete')
        self.assertEqual(result['attempted_calls'],2)
        self.assertEqual(result['completed_calls'],2)
        self.assertEqual([r[0] for r in client.requests],['GET','GET','POST','GET','GET','POST'])
        self.assertEqual(len(result['route_preflights']),2)
        self.assertFalse(result['quality_qualified'])
        self.assertFalse(result['production_admission'])
        self.assertFalse(result['unknown_cost_possible'])
        self.assertEqual(result['results'][0]['cost_microusd'],120)

    def test_failed_first_or_second_call_has_no_retry_and_retains_partial_results(self):
        for at,attempted,completed in [(1,0,0),(2,0,0),(3,1,0),(4,1,1),(5,1,1),(6,2,1)]:
            with self.subTest(at=at):
                client=FixtureClient(at)
                result=run_probe(client,corpus())
                self.assertEqual(result['status'],'probe_incomplete')
                self.assertEqual(len(client.requests),at)
                self.assertEqual(result['attempted_calls'],attempted)
                self.assertEqual(result['completed_calls'],completed)
                self.assertEqual(result['unknown_cost_possible'],attempted>completed)

    def test_missing_approved_provider_prevents_paid_call(self):
        client=FixtureClient()
        original=client.request
        def no_vertex(method,path,payload=None):
            reply=original(method,path,payload)
            if path.endswith('/endpoints'):
                reply['data']['endpoints']=[dict(provider_name='Google AI Studio',tag='google-ai-studio',status=0)]
            return reply
        client.request=no_vertex
        result=run_probe(client,corpus())
        self.assertEqual(result['reason'],'approved_vertex_route_unavailable')
        self.assertEqual(result['attempted_calls'],0)
        self.assertFalse(result['unknown_cost_possible'])
        self.assertEqual([r[0] for r in client.requests],['GET','GET'])

    def test_route_catalog_must_match_model_provider_tag_and_status(self):
        good={'data':dict(id=MODELS[0],endpoints=[dict(provider_name='Google Vertex',tag='google-vertex/us-east5',status=0)])}
        self.assertFalse(route_check(good,MODELS[0])['privacy_attested'])
        for change in ('model','provider','tag','status','missing'):
            value=deepcopy(good)
            if change=='model': value['data']['id']='other'
            elif change=='missing': value['data']['endpoints']=None
            else: value['data']['endpoints'][0][{'provider':'provider_name','tag':'tag','status':'status'}[change]]='other'
            with self.subTest(change=change),self.assertRaises(ProbeError):
                route_check(value,MODELS[0])

    def test_wrong_development_decision_stops_without_second_paid_call(self):
        client=FixtureClient()
        original=client.request
        def wrong(method,path,payload=None):
            result=original(method,path,payload)
            if method=='POST':
                value=json.loads(result['choices'][0]['message']['content'])
                value['disposition']='benign'
                result['choices'][0]['message']['content']=json.dumps(value)
            return result
        client.request=wrong
        result=run_probe(client,corpus())
        self.assertEqual(result['reason'],'development_decision_mismatch')
        self.assertEqual(result['attempted_calls'],1)

    def test_real_or_public_corpus_cannot_be_sent(self):
        data=corpus()
        data['provenance']['kind']='licensed_public'
        client=FixtureClient()
        with self.assertRaises(ProbeError): run_probe(client,data)
        self.assertFalse(client.requests)

    def test_mismatched_provider_model_usage_and_incomplete_answer_rejected(self):
        packet=packets(corpus(),'development')[0]
        body=request_body(MODELS[0],packet)
        mutations=[lambda r:r.update(model='other'),lambda r:r.update(provider='other'),
                   lambda r:r.update(usage={}),lambda r:r['usage'].update(cost=0.011),
                   lambda r:r['usage'].update(prompt_tokens=8001),lambda r:r['usage'].update(completion_tokens=769),
                   lambda r:r['choices'][0].update(finish_reason='length'),
                   lambda r:r['choices'][0]['message'].update(tool_calls=[{'id':'unapproved'}])]
        for mutation in mutations:
            value=answer()
            mutation(value)
            with self.assertRaises(ProbeError): response_record(value,MODELS[0],packet,body,10)

    def test_arbitrary_claim_reference_or_external_action_rejected(self):
        packet=packets(corpus(),'development')[0]
        body=request_body(MODELS[0],packet)
        for change in ('reference','action'):
            value=answer()
            decision=json.loads(value['choices'][0]['message']['content'])
            if change=='reference': decision['claims'][0]['references']=['invented']
            else: decision['requested_actions']=['isolate-host']
            value['choices'][0]['message']['content']=json.dumps(decision)
            with self.assertRaises(ProbeError): response_record(value,MODELS[0],packet,body,10)

    def test_json_duplicate_keys_and_nonfinite_values_rejected(self):
        for value in ('{"cost":0,"cost":1}','{"cost":NaN}'):
            with self.assertRaises(ProbeError): decode(value)

    def test_http_fixed_host_tls_auth_and_bounded_response(self):
        raw=json.dumps({'data':key_data()}).encode()
        connection=Mock()
        response=Mock(status=200)
        response.getheader.return_value='application/json'
        response.read.return_value=raw
        connection.getresponse.return_value=response
        with patch('gabriel.identity.provider_probe.http.client.HTTPSConnection',return_value=connection) as factory:
            result=OpenRouterProbe(SECRET).request('GET','/api/v1/key')
        self.assertEqual(result['data']['limit'],18)
        self.assertEqual(factory.call_args.args,(HOST,443))
        self.assertEqual(factory.call_args.kwargs['context'].verify_mode,2)
        self.assertEqual(connection.request.call_args.kwargs['headers']['Authorization'],'Bearer '+SECRET)
        response.read.assert_called_once_with(131073)
        connection.close.assert_called_once()

    def test_http_redirect_error_oversize_and_credential_echo_never_retry(self):
        for status,raw in [(302,b'{}'),(401,b'{}'),(200,b'x'*131073),(200,SECRET.encode())]:
            connection=Mock()
            response=Mock(status=status)
            response.getheader.return_value='application/json'
            response.read.return_value=raw
            connection.getresponse.return_value=response
            with patch('gabriel.identity.provider_probe.http.client.HTTPSConnection',return_value=connection):
                with self.assertRaises(ProbeError) as caught:
                    OpenRouterProbe(SECRET).request('GET','/api/v1/key')
            self.assertNotIn(SECRET,str(caught.exception))
            self.assertEqual(connection.request.call_count,1)

    def test_arbitrary_endpoint_denied_before_network(self):
        with patch('gabriel.identity.provider_probe.http.client.HTTPSConnection') as factory:
            with self.assertRaises(ProbeError): OpenRouterProbe(SECRET).request('GET','https://elsewhere.invalid')
            self.assertFalse(factory.called)


if __name__=='__main__':
    unittest.main()
