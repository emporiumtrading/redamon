"""Hermetic comparison/transport checks; fabricated replies are not model evidence."""
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from gabriel.identity.model_evaluation import digest,load_json
from gabriel.identity.model_lab import CASES,CORPUS_DIGEST,compare,preflight
from gabriel.identity.model_routes import ROUTES,RouteError,eligible,parameters
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.model_protocol import ProbeError

ROOT=Path(__file__).resolve().parents[2]


def catalog():
    return dict(data=[dict(model_id=model,provider_name=value[0],tag=value[1],status=0,
        pricing=dict(prompt='0.0000001',completion='0.0000004'),
        supported_parameters=['temperature','response_format',value[2],'reasoning']) for model,value in ROUTES.items()])


def key_data():
    return dict(is_management_key=False,is_provisioning_key=False,limit=18,limit_reset='monthly',
                usage_daily=0,usage_monthly=0,limit_remaining=18)


class Client:
    def __init__(self): self.posts=[]; self.invalid=False; self.unknown=False; self.route_catalog=catalog()
    def request(self,method,path,payload=None):
        if path=='/api/v1/key': return dict(data=key_data())
        if path=='/api/v1/endpoints/zdr': return self.route_catalog
        assert method=='POST' and path=='/api/v1/chat/completions'
        self.posts.append(deepcopy(payload))
        if self.unknown: raise ProbeError('provider_transport_unresolved')
        packet=json.loads(payload['messages'][1]['content'])
        obs=packet['observations'][0]['id']
        disposition={'auth-1':'escalate','backup-1':'benign','logout-1':'abstain'}[obs]
        decision=dict(disposition=disposition,claims=[dict(id='claim-1',statement='Generated software fixture claim.',references=[obs])],
            alternatives=['Generated alternative.'],contradictions=['Generated contradiction review.'],uncertainty=['Generated uncertainty.'],
            reported_gaps=['source-unavailable'] if obs=='logout-1' else [],requested_actions=[])
        if self.invalid: decision['claims'][0]['references']=['invented-reference']
        return dict(id='fixture-'+str(len(self.posts)),model=payload['model'],provider=ROUTES[payload['model']][0],
            choices=[dict(finish_reason='stop',message=dict(content=json.dumps(decision)))],
            usage=dict(prompt_tokens=299,completion_tokens=227,cost=0.0002))


def corpus(): return load_json(ROOT/'testing/gabriel_model_lab/development_corpus.json')


def test_full_fixed_comparison_is_bounded_and_never_qualifies():
    client=Client(); events=[]
    report=compare(client,corpus(),events.append)
    assert len(client.posts)==report['attempted_calls']==report['validated_calls']==24
    assert report['reported_cost_usd']=='0.0048'
    assert not report['unknown_cost_possible'] and not report['quality_qualified'] and not report['production_admission']
    assert {r['run']['case_id'] for r in report['results']}==set(CASES)
    assert all(r['matched_development_label'] for r in report['results'])
    assert len([e for e in events if e['event']=='dispatch_started'])==24
    for body in client.posts:
        assert body['provider']['zdr'] and body['provider']['data_collection']=='deny'
        assert not body['provider']['allow_fallbacks'] and body['provider']['require_parameters']
        assert not any(k in body for k in ('tools','plugins','models','transforms'))
        assert 'label' not in json.loads(body['messages'][1]['content'])


def test_modified_corpus_is_rejected_before_credentials_or_dispatch():
    data=corpus(); data['cases'][0]['question']='Modified input must not reach any provider.'
    client=Client()
    with pytest.raises(ProbeError,match='pinned_generated_corpus_required'): compare(client,data)
    assert not client.posts
    assert digest(corpus())==CORPUS_DIGEST


def test_unknown_charge_stops_entire_batch_without_retry():
    client=Client(); client.unknown=True
    report=compare(client,corpus())
    assert len(client.posts)==1 and report['attempted_calls']==1
    assert report['unknown_cost_possible'] and report['validated_calls']==0


def test_invalid_decision_keeps_known_cost_and_moves_to_next_distinct_model():
    client=Client(); client.invalid=True
    report=compare(client,corpus())
    assert len(client.posts)==8 and len({p['model'] for p in client.posts})==8
    assert report['reported_cost_usd']=='0.0016' and not report['unknown_cost_possible']
    assert report['validated_calls']==0 and len(report['failures'])==8


def test_missing_catalog_routes_skip_without_paid_calls():
    client=Client(); client.route_catalog={'data':[]}
    report=compare(client,corpus())
    assert not client.posts and report['attempted_calls']==0 and len(report['failures'])==8


@pytest.mark.parametrize('change',[dict(limit=20),dict(limit_reset=None),dict(usage_daily=0.35),dict(usage_monthly=17.9),dict(limit_remaining=0.1),dict(is_management_key=True)])
def test_account_preflight_cannot_expand_budget(change):
    with pytest.raises(ProbeError): preflight({**key_data(),**change})


@pytest.mark.parametrize('model',list(ROUTES))
def test_candidate_price_and_parameter_contract(model):
    assert not eligible(catalog(),model)['production_admission']
    body=parameters(model)
    assert body['provider']['only']==[ROUTES[model][1]]
    assert body[ROUTES[model][2]]==768
    data=catalog(); row=next(r for r in data['data'] if r['model_id']==model)
    row['pricing']['completion']='0.0000031'
    with pytest.raises(RouteError,match='price_exceeds'): eligible(data,model)
    row['pricing']['completion']='0.0000004'; row['status']=True
    with pytest.raises(RouteError,match='unavailable'): eligible(data,model)


def test_transport_rejects_unapproved_endpoints_before_opening_connection():
    class Credential:
        def reveal(self): return 'generated-fixture-credential-value'
    client=OpenRouterTransport(Credential())
    assert 'generated-fixture' not in repr(client)
    with patch('gabriel.identity.model_transport.http.client.HTTPSConnection') as connection:
        for method,path in [('GET','/external'),('POST','https://unapproved.invalid'),('PUT','/api/v1/key')]:
            with pytest.raises(ProbeError): client.request(method,path)
        with pytest.raises(ProbeError): client.request('POST','/api/v1/chat/completions',{'value':'x'*8000})
        connection.assert_not_called()


def test_transport_does_not_follow_redirects_or_expose_response_or_key():
    class Credential:
        def reveal(self): return 'generated-fixture-credential-value'
    with patch('gabriel.identity.model_transport.http.client.HTTPSConnection') as connection:
        conn=connection.return_value; response=conn.getresponse.return_value
        response.status=302
        with pytest.raises(ProbeError,match='provider_http_302'):
            OpenRouterTransport(Credential()).request('POST','/api/v1/chat/completions',{'model':'fixture'})
        assert conn.request.call_count==1 and conn.close.call_count==1
        connection.assert_called_once()


def test_remaining_batch_never_retries_prior_models_and_carries_unknown_reservation():
    client=Client()
    report=compare(client,corpus(),remaining=True)
    assert len(client.posts)==18 and report['validated_calls']==18
    assert {p['model'] for p in client.posts}==set(tuple(ROUTES)[2:])
    assert report['carried_reserved_usd']=='0.006304' and report['unresolved_comparison_calls']==1
    assert report['unknown_cost_possible'] and not report['new_unknown_cost_possible']
    assert not report['production_admission']


def test_second_unknown_stops_remaining_batch_without_retry():
    client=Client(); client.unknown=True
    report=compare(client,corpus(),remaining=True)
    assert len(client.posts)==1 and report['unresolved_comparison_calls']==2
    assert report['unknown_cost_possible'] and report['new_unknown_cost_possible']


def test_failure_diagnostics_expose_structure_and_code_without_provider_text():
    client=Client(); client.invalid=True
    report=compare(client,corpus())
    failure=report['failures'][0]
    assert failure['diagnostic_code']=='unknown_reference'
    assert 'claims' in failure['shape']['decision_keys']
    assert 'Generated software fixture claim.' not in json.dumps(failure)
