"""Software fixtures assert schedule/privacy/budget boundaries; they never qualify a model."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from gabriel.identity.model_evaluation import load_json
from gabriel.identity.model_protocol import ProbeError
from gabriel.identity.model_routes import ROUTES
from gabriel.identity.model_validation import validate,MODEL


def corpus(): return load_json(Path(__file__).resolve().parents[2]/'testing/gabriel_model_lab/candidate_corpus_v1.json')


class Client:
    def __init__(self): self.posts=[];self.requests=[];self.unknown=False;self.invalid=False;self.daily=0
    def request(self,method,path,payload=None):
        self.requests.append(path)
        if path=='/api/v1/key': return dict(data=dict(is_management_key=False,is_provisioning_key=False,
            limit=18,limit_reset='monthly',usage_daily=self.daily,usage_monthly=0,limit_remaining=18))
        if path=='/api/v1/endpoints/zdr': return dict(data=[dict(model_id=MODEL,provider_name=ROUTES[MODEL][0],
            tag=ROUTES[MODEL][1],status=0,pricing=dict(prompt='0.0000001',completion='0.0000004'),
            supported_parameters=['temperature','response_format','max_tokens','reasoning'])])
        assert method=='POST' and path=='/api/v1/chat/completions';self.posts.append(deepcopy(payload))
        if self.unknown: raise ProbeError('provider_transport_unresolved')
        packet=json.loads(payload['messages'][1]['content'])
        answer=dict(disposition='abstain',claims=[dict(id='claim-1',statement='Generated software fixture.',
            references=[packet['observations'][0]['id']])],alternatives=['Generated alternative.'],
            contradictions=['Generated contradiction review.'],uncertainty=['Generated uncertainty.'],reported_gaps=[],requested_actions=[])
        if self.invalid: answer['requested_actions']=['write-external']
        return dict(id='fixture-validation-'+str(len(self.posts)),model=MODEL,provider=ROUTES[MODEL][0],
            choices=[dict(finish_reason='stop',message=dict(content=json.dumps(answer)))],
            usage=dict(prompt_tokens=300,completion_tokens=250,cost=0.0002))


def test_only_ten_validation_inputs_and_one_route_are_sent_without_labels_or_actions():
    client=Client();events=[];result=validate(client,corpus(),events.append)
    expected={row['id'] for row in corpus()['cases'] if row['split']=='validation'}
    assert result['attempted_calls']==result['validated_calls']==len(client.posts)==10
    assert {row['run']['case_id'] for row in result['results']}==expected
    assert result['held_out_cases_dispatched']==0 and not result['quality_qualified'] and not result['production_admission']
    assert result['reported_cost_usd']=='0.0020' and result['batch_reservation_usd']=='0.063040'
    assert len([event for event in events if event['event']=='validation_dispatch_reserved'])==10
    for body in client.posts:
        assert body['model']==MODEL and set(json.loads(body['messages'][1]['content']))=={'question','observations'}
        assert body['provider']['zdr'] and body['provider']['data_collection']=='deny' and not body['provider']['allow_fallbacks']
        assert not any(key in body for key in ('tools','plugins','models','transforms'))


def test_changed_corpus_is_rejected_before_account_or_paid_requests():
    data=corpus();data['cases'][0]['question']='Altered';client=Client()
    with pytest.raises(ProbeError): validate(client,data)
    assert not client.requests


def test_unknown_charge_stops_batch_and_retains_reservation_without_retry():
    client=Client();client.unknown=True;report=validate(client,corpus())
    assert report['attempted_calls']==1 and len(client.posts)==1 and report['validated_calls']==0
    assert report['new_unresolved_reserved_usd']=='0.006304' and report['failures'][0]['retry'] is False


def test_bad_answer_keeps_known_cost_and_stops_without_retry():
    client=Client();client.invalid=True;report=validate(client,corpus())
    assert len(client.posts)==1 and report['validated_calls']==0 and report['reported_cost_usd']=='0.0002'
    assert report['failures'][0]['stage']=='contract' and report['new_unresolved_reserved_usd']=='0'


def test_failed_journal_prevents_billable_dispatch():
    client=Client()
    def fail(event): raise RuntimeError('generated journal failure')
    with pytest.raises(RuntimeError): validate(client,corpus(),fail)
    assert not client.posts


def test_account_budget_includes_carried_unknown_holds():
    client=Client();client.daily=0.33;report=validate(client,corpus())
    assert not client.posts and report['attempted_calls']==0 and report['failures'][0]['stage']=='preflight'
