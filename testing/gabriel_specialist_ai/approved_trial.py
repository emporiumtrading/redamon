"""Single owner-approved conditional agent batch; never production admission."""
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
from gabriel.identity.specialist_agents import DEFAULT_MODEL as MODEL,TOOLS
from trial import export

REQUESTS='e8d67be2c3eac2d65638b10053daff1daba3d82fdbd1eefe2fc2816ee175253d'
CEILING=Decimal('0.006304')
BATCH=Decimal('0.453888')
CARRIED=Decimal('0.022608')


def verify(packet):
    if (packet!=export() or digest(packet['requests'])!=REQUESTS
            or len(packet['requests'])!=240 or packet['maximum_model_calls']!=72
            or packet['initial_case_count']!=24 or packet['maximum_reservation_usd']!=str(BATCH)):
        raise ProbeError('approved_request_packet_mismatch')
    return packet


def account(client,attempted):
    remaining=CEILING*(72-attempted)+CARRIED
    data=client.request('GET','/api/v1/key').get('data')
    if not isinstance(data,dict):raise ProbeError('key_metadata_missing')
    adjusted=dict(data)
    for key in ('usage_daily','usage_monthly'):
        adjusted[key]=str(money(data.get(key))+remaining)
    available=money(data.get('limit_remaining'))
    if available<remaining:raise ProbeError('approved_batch_credit_unavailable')
    adjusted['limit_remaining']=str(available-remaining)
    budget_check(adjusted)
    dispatch_credit(client.request('GET','/api/v1/credits'),int(remaining*1000000))
    eligible(client.request('GET','/api/v1/endpoints/zdr'),MODEL)


def reason(error):
    code=str(error)
    return code if re.fullmatch('[a-z0-9_]{1,80}',code) else 'trial_unresolved'


def run(client,packet,checkpoint=lambda event:None):
    verify(packet)
    report=dict(version='gabriel-approved-specialist-ai-trial-v1',request_set_sha256=REQUESTS,
        attempted_calls=0,validated_calls=0,completed_scenarios=0,reported_cost_usd='0',
        unresolved_reserved_usd='0',maximum_new_reservation_usd=str(BATCH),results=[],failures=[],
        quality_qualified=False,production_admission=False,independent_review='pending',
        source='authored_synthetic_not_held_out',raw_responses_exported=False)
    variants={(r['case_id'],tuple(r['tool_history'])):r for r in packet['requests']}
    total=Decimal(0);generations=set()
    for initial in [r for r in packet['requests'] if not r['tool_history']]:
        history=[]
        for step in range(1,4):
            row=variants[(initial['case_id'],tuple(history))]
            try:account(client,report['attempted_calls'])
            except Exception as error:
                report['failures'].append(dict(case_id=row['case_id'],round=step,stage='preflight',reason=reason(error)))
                return report
            if CEILING*(report['attempted_calls']+1)>BATCH:raise ProbeError('approved_batch_limit')
            checkpoint(dict(event='dispatch_reserved',case_id=row['case_id'],round=step,
                body_sha256=row['body_sha256'],reserved_usd=str(CEILING)))
            report['attempted_calls']+=1;started=time.monotonic()
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
                report['failures'].append(dict(case_id=row['case_id'],round=step,stage='dispatch',reason=reason(error),retry=False))
                return report
            total+=cost;report['reported_cost_usd']=str(total)
            try:
                choices=reply.get('choices')
                if type(choices) is not list or len(choices)!=1 or choices[0].get('finish_reason')!='stop':
                    raise ProbeError('incomplete_provider_answer')
                message=choices[0].get('message',{})
                if message.get('tool_calls') or type(message.get('content')) is not str:
                    raise ProbeError('invalid_provider_answer')
                decision=decode(message['content'])
                observations=decode(row['body']['messages'][1]['content'])['observations']
                validation=dict(case_id=row['case_id'],input_sha256=row['body_sha256'],observations=observations)
                result=dict(case_id=row['case_id'],input_sha256=row['body_sha256'],configuration_sha256=row['configuration_digest'],
                    origin='live_provider',generation_id=reply.get('id'),latency_ms=int((time.monotonic()-started)*1000),
                    cost_usd=float(cost),input_tokens=usage['prompt_tokens'],output_tokens=usage['completion_tokens'],decision=decision)
                validate_run(result,validation)
                generation=reply['id']
                if generation in generations:raise ProbeError('provider_generation_reused')
                generations.add(generation)
                actions=decision['requested_actions']
                if len(actions)>1 or any(a not in TOOLS[row['role']] for a in actions):
                    raise ProbeError('specialist_tool_not_admitted')
                report['validated_calls']+=1
                final=not actions
                stop='final_answer' if final else ('round_limit' if step==3 else 'repeated_tool' if actions[0] in history else 'tool_requested')
                report['results'].append(dict(case_id=row['case_id'],role=row['role'],round=step,
                    configuration_digest=row['configuration_digest'],body_sha256=row['body_sha256'],
                    disposition=decision['disposition'],requested_tools=actions,loop_state=stop,
                    cost_usd=str(cost),latency_ms=result['latency_ms'],input_tokens=usage['prompt_tokens'],
                    output_tokens=usage['completion_tokens'],response_digest=digest(reply),
                    decision_digest=digest(decision),contract_valid=True,semantic_review='pending'))
                checkpoint(dict(event='response_validated',result=report['results'][-1]))
                if stop!='tool_requested':
                    report['completed_scenarios']+=1
                    break
                history+=actions
            except Exception as error:
                report['failures'].append(dict(case_id=row['case_id'],round=step,stage='contract',reason=reason(error),retry=False))
                return report
    return report


def main():
    secret=os.environ.pop('OPENROUTER_API_KEY','')
    def emit(value):
        raw=canonical(value)
        if secret and secret.encode() in raw:raise ProbeError('credential_output_rejected')
        with open('/results/events.jsonl','ab') as journal:
            journal.write(raw+b'\n');journal.flush();os.fsync(journal.fileno())
        print(raw.decode(),flush=True)
    class Credential:
        def reveal(self):return secret
    try:
        if sys.argv[1:]:raise ProbeError('trial_arguments_denied')
        # Exclusive marker plus the CI opened-event/run-attempt gate prevents resume/replay.
        with open('/results/dispatch-started','x') as marker:
            marker.write(REQUESTS);marker.flush();os.fsync(marker.fileno())
        report=run(OpenRouterTransport(Credential()),export(),emit)
        emit(dict(event='trial_final',report=report))
        return 0 if report['completed_scenarios']==24 and not report['failures'] else 2
    except Exception as error:
        emit(dict(event='trial_stopped',reason=reason(error),retry=False,production_admission=False))
        return 2


if __name__=='__main__':raise SystemExit(main())
