"""One owner-approved synthetic batch; no admission, retries or raw response export."""
from decimal import Decimal
import os
import re
import sys
import time

from gabriel.identity.model_evaluation import canonical,digest,validate_run
from gabriel.identity.model_protocol import ProbeError,budget_check,decode,money
from gabriel.identity.model_routes import eligible
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.provider_onboarding import dispatch_credit
from trial import export,MODEL

REQUESTS='072884fcfc8a9c074c0b0175b8e219d7276651f97b0505f7f4f1c8e0ebdadc96'
CONFIG='b777a5bf2566dd617e32040097f4ca7d79651ff30f300be8035e87fa0dab213a'
CEILING=Decimal('0.006304')
BATCH=Decimal('0.031520')
CARRIED=Decimal('0.022608')


def verify(packet):
    if (packet!=export() or digest(packet['requests'])!=REQUESTS
            or digest(packet['configuration'])!=CONFIG or len(packet['requests'])!=5
            or packet['max_new_reservation_usd']!=str(BATCH)):
        raise ProbeError('approved_request_packet_mismatch')
    return packet


def account(client):
    data=client.request('GET','/api/v1/key').get('data')
    if not isinstance(data,dict):raise ProbeError('key_metadata_missing')
    adjusted=dict(data)
    for key in ('usage_daily','usage_monthly'):
        adjusted[key]=str(money(data.get(key))+BATCH+CARRIED)
    remaining=money(data.get('limit_remaining'))
    if remaining<BATCH+CARRIED:raise ProbeError('approved_batch_credit_unavailable')
    adjusted['limit_remaining']=str(remaining-BATCH-CARRIED)
    budget_check(adjusted)
    dispatch_credit(client.request('GET','/api/v1/credits'),int((BATCH+CARRIED)*1000000))
    eligible(client.request('GET','/api/v1/endpoints/zdr'),MODEL)


def reason(error):
    code=str(error)
    return code if re.fullmatch('[a-z0-9_]{1,80}',code) else 'trial_unresolved'


def run(client,packet,checkpoint=lambda event:None):
    verify(packet)
    report=dict(version='gabriel-approved-browser-ai-trial-v1',configuration_digest=CONFIG,
        request_set_sha256=REQUESTS,attempted_calls=0,validated_calls=0,reported_cost_usd='0',
        unresolved_reserved_usd='0',maximum_new_reservation_usd=str(BATCH),results=[],failures=[],
        quality_qualified=False,production_admission=False,independent_review='pending',
        source='authored_synthetic_not_held_out',raw_responses_exported=False)
    total=Decimal(0)
    for row in packet['requests']:
        try:account(client)
        except Exception as error:
            report['failures'].append(dict(case_id=row['case_id'],stage='preflight',reason=reason(error)))
            break
        if CEILING*(report['attempted_calls']+1)>BATCH:raise ProbeError('approved_batch_limit')
        checkpoint(dict(event='dispatch_reserved',case_id=row['case_id'],reserved_usd=str(CEILING)))
        report['attempted_calls']+=1
        started=time.monotonic()
        try:
            reply=client.request('POST','/api/v1/chat/completions',row['body'])
            if type(reply) is not dict or reply.get('model')!=MODEL or reply.get('provider')!='Cerebras':
                raise ProbeError('unexpected_model_or_provider')
            usage=reply.get('usage',{})
            if any(type(usage.get(k)) is not int or not 0<=usage[k]<=n for k,n in [('prompt_tokens',8000),('completion_tokens',768)]):
                raise ProbeError('actual_token_limit_exceeded')
            cost=money(usage.get('cost'))
            if cost>CEILING:raise ProbeError('actual_call_cost_exceeded')
        except Exception as error:
            report['unresolved_reserved_usd']=str(CEILING)
            report['failures'].append(dict(case_id=row['case_id'],stage='dispatch',reason=reason(error),retry=False))
            break
        total+=cost;report['reported_cost_usd']=str(total)
        try:
            choices=reply.get('choices')
            if type(choices) is not list or len(choices)!=1 or choices[0].get('finish_reason')!='stop':
                raise ProbeError('incomplete_provider_answer')
            message=choices[0].get('message',{})
            if message.get('tool_calls') or type(message.get('content')) is not str:
                raise ProbeError('invalid_provider_answer')
            decision=decode(message['content'])
            signals=decode(row['body']['messages'][1]['content'])['signals']
            validation=dict(case_id=row['case_id'],input_sha256=row['body_sha256'],observations=[dict(id=s['id']) for s in signals])
            result=dict(case_id=row['case_id'],input_sha256=row['body_sha256'],configuration_sha256=CONFIG,
                origin='live_provider',generation_id=reply.get('id'),latency_ms=int((time.monotonic()-started)*1000),
                cost_usd=float(cost),input_tokens=usage['prompt_tokens'],output_tokens=usage['completion_tokens'],decision=decision)
            validate_run(result,validation)
            if decision['requested_actions']:raise ProbeError('external_action_requested')
            report['validated_calls']+=1
            report['results'].append(dict(case_id=row['case_id'],disposition=decision['disposition'],
                cost_usd=str(cost),latency_ms=result['latency_ms'],input_tokens=usage['prompt_tokens'],
                output_tokens=usage['completion_tokens'],response_digest=digest(reply),
                decision_digest=digest(decision),contract_valid=True,semantic_review='pending'))
            checkpoint(dict(event='response_validated',case_id=row['case_id'],cost_usd=str(cost)))
        except Exception as error:
            report['failures'].append(dict(case_id=row['case_id'],stage='contract',reason=reason(error),retry=False))
            break
    return report


def main():
    secret=os.environ.pop('OPENROUTER_API_KEY','')
    def emit(value):
        raw=canonical(value)
        if secret and secret.encode() in raw:raise ProbeError('credential_output_rejected')
        print(raw.decode(),flush=True)
    class Credential:
        def reveal(self):return secret
    try:
        if sys.argv[1:]:raise ProbeError('trial_arguments_denied')
        report=run(OpenRouterTransport(Credential()),export(),emit)
        emit(dict(event='trial_final',report=report))
        return 0 if report['validated_calls']==5 and not report['failures'] else 2
    except Exception as error:
        emit(dict(event='trial_stopped',reason=reason(error),retry=False,production_admission=False))
        return 2


if __name__=='__main__':raise SystemExit(main())
