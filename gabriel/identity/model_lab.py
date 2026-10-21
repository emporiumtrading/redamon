"""Eight exact routes, three pinned development cases; never qualification or production."""
from decimal import Decimal
from hashlib import sha256
import json
import os
import re
import sys
import time

from gabriel.identity.model_evaluation import canonical,digest,identifier,load_json,packets,validate_run,EvaluationError
from gabriel.identity.model_routes import ROUTES,RouteError,eligible,parameters
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.model_protocol import PROMPT,PROMPT_V2,ProbeError,decode,money

CORPUS_DIGEST='0fd9f635db6d97c36a6fd9ffb9f7d35ba0f528d638d39dbe82ee7b165cec0a0f'
CASES=('dev-auth-attack','dev-backup','dev-logout')
RUN_ALLOWANCE=Decimal('0.16')
CALL_RESERVATION=Decimal('0.006304')
PRIOR_RESERVED=Decimal('0.006304')
PRIOR_REPORTED=Decimal('0.0005068')
HISTORICAL_PROBE_RESERVED=Decimal('0.01')
PRIOR_ARTIFACT_SHA256='3b92f975f9dccca501b2b8fd70117899eb928b60b1bf79f3bead2d73c0baf0d1'
V2_PRIOR_REPORTED=Decimal('0.005710488')
V2_PRIOR_ARTIFACT_SHA256='f6f29fde5ff7c6d13504f9ae6581117248ea9d5559e2f3c942b23f4d555a8ef4'


class LabCredential:
    def __init__(self,value): self._value=value
    def reveal(self): return self._value
    def __repr__(self): return '<LabCredential redacted>'


def preflight(data):
    if not isinstance(data,dict) or data.get('is_management_key') is not False or data.get('is_provisioning_key') is not False:
        raise ProbeError('inference_only_key_required')
    if data.get('limit') is None or not 0<money(data['limit'])<=18 or data.get('limit_reset')!='monthly':
        raise ProbeError('monthly_key_limit_required')
    day=money(data.get('usage_daily'))+money(data.get('byok_usage_daily',0))
    month=money(data.get('usage_monthly'))+money(data.get('byok_usage_monthly',0))
    if day+RUN_ALLOWANCE+HISTORICAL_PROBE_RESERVED>Decimal('0.50') or month+RUN_ALLOWANCE+HISTORICAL_PROBE_RESERVED>18 or money(data.get('limit_remaining'))<RUN_ALLOWANCE+HISTORICAL_PROBE_RESERVED:
        raise ProbeError('comparison_budget_unavailable')
    return dict(day_used_usd=str(day),month_used_usd=str(month),run_reservation_usd=str(RUN_ALLOWANCE),historical_probe_reserved_usd=str(HISTORICAL_PROBE_RESERVED))


def body_for(model,packet,*,protocol_v2=False):
    body=dict(model=model,messages=[dict(role='system',content=PROMPT_V2 if protocol_v2 else PROMPT),
              dict(role='user',content=canonical(dict(question=packet['question'],observations=packet['observations'])).decode())],**parameters(model))
    if len(canonical(body))>7000: raise ProbeError('comparison_input_limit')
    return body


def usage_for(reply,model):
    if not isinstance(reply,dict) or reply.get('model')!=model or reply.get('provider')!=ROUTES[model][0]:
        raise ProbeError('unexpected_model_or_provider')
    usage=reply.get('usage')
    if not isinstance(usage,dict): raise ProbeError('actual_usage_missing')
    for key,maximum in [('prompt_tokens',8000),('completion_tokens',768)]:
        if type(usage.get(key)) is not int or not 0<=usage[key]<=maximum:
            raise ProbeError('actual_token_limit_exceeded')
    cost=money(usage.get('cost'))
    if cost>CALL_RESERVATION: raise ProbeError('actual_call_cost_exceeded')
    return cost


def record_for(reply,model,packet,body,elapsed):
    cost=usage_for(reply,model)
    choices=reply.get('choices')
    if not isinstance(choices,list) or len(choices)!=1 or choices[0].get('finish_reason')!='stop':
        raise ProbeError('incomplete_provider_answer')
    message=choices[0].get('message',{})
    if message.get('tool_calls') or not isinstance(message.get('content'),str): raise ProbeError('invalid_provider_answer')
    decision=decode(message['content'])
    config=dict(provider='openrouter',model=model,endpoint_policy='lab-zdr-exact-v1',
        prompt_sha256=sha256(body['messages'][0]['content'].encode()).hexdigest(),adapter_version='pinned-development-v1',
        redaction_version='generated-only-v1',compression_version='none-v1',
        parameters={k:v for k,v in body.items() if k not in {'model','messages'}})
    run=dict(case_id=packet['case_id'],input_sha256=packet['input_sha256'],configuration_sha256=digest(config),
        origin='live_provider',generation_id=reply.get('id'),latency_ms=elapsed,cost_usd=float(cost),
        input_tokens=reply['usage']['prompt_tokens'],output_tokens=reply['usage']['completion_tokens'],decision=decision)
    validate_run(run,packet)
    if decision['requested_actions']: raise ProbeError('external_action_requested')
    return dict(configuration=config,run=run,provider_response_digest=digest(reply))


def diagnostic(error):
    code=str(error) if isinstance(error,(ProbeError,EvaluationError,RouteError)) else 'comparison_unresolved'
    return code if re.fullmatch('[a-z0-9_]{1,80}',code) else 'comparison_unresolved'


def shape(reply):
    try:
        decision=decode(reply['choices'][0]['message']['content'])
        def names(value):
            return sorted(k if isinstance(k,str) and re.fullmatch('[a-z_]{1,40}',k) else 'unexpected_field_name'
                          for k in value) if isinstance(value,dict) else []
        claims=decision.get('claims',[]) if isinstance(decision,dict) else []
        return dict(decision_keys=names(decision),claim_shapes=[names(v) for v in claims[:3]] if isinstance(claims,list) else [],
                    reasoning_counts={k:len(decision[k]) if isinstance(decision.get(k),list) else None
                                      for k in ['alternatives','contradictions','uncertainty']} if isinstance(decision,dict) else {})
    except Exception: return dict(decision_shape='unreadable')


def invalid_identifier_fields(reply):
    """Report fixed field paths only; never retain rejected identifier values."""
    invalid=[]
    def check(value,path):
        try: identifier(value)
        except EvaluationError: invalid.append(path)
    check(reply.get('id'),'generation_id')
    try: answer=decode(reply['choices'][0]['message']['content'])
    except Exception: return invalid
    if not isinstance(answer,dict): return invalid
    for key in ['reported_gaps','requested_actions']:
        values=answer.get(key)
        if isinstance(values,list):
            for index,value in enumerate(values[:64]): check(value,key+'['+str(index)+']')
    claims=answer.get('claims')
    if isinstance(claims,list):
        for index,claim in enumerate(claims[:32]):
            if not isinstance(claim,dict): continue
            prefix='claims['+str(index)+']'
            check(claim.get('id'),prefix+'.id')
            refs=claim.get('references')
            if isinstance(refs,list):
                for j,value in enumerate(refs[:64]): check(value,prefix+'.references['+str(j)+']')
    return invalid[:32]


def compare(client,corpus,checkpoint=lambda event:None,*,remaining=False,protocol_v2=False):
    if type(remaining) is not bool or type(protocol_v2) is not bool or remaining and protocol_v2:
        raise ProbeError('comparison_schedule_denied')
    if digest(corpus)!=CORPUS_DIGEST: raise ProbeError('pinned_generated_corpus_required')
    selected={p['case_id']:p for p in packets(corpus,'development') if p['case_id'] in CASES}
    labels={c['id']:c['label']['acceptable_decisions'] for c in corpus['cases'] if c['id'] in CASES}
    carrying=remaining or protocol_v2
    prior_cost=V2_PRIOR_REPORTED if protocol_v2 else PRIOR_REPORTED if remaining else Decimal(0)
    report=dict(version='bounded-multi-model-lab-v2' if protocol_v2 else 'bounded-multi-model-lab-v1',results=[],routes=[],failures=[],attempted_calls=0,
        validated_calls=0,reported_cost_usd='0',unknown_cost_possible=carrying,new_unknown_cost_possible=False,
        unresolved_comparison_calls=1 if carrying else 0,carried_reserved_usd=str(PRIOR_RESERVED) if carrying else '0',
        carried_reported_cost_usd=str(prior_cost),
        prior_artifact_sha256=V2_PRIOR_ARTIFACT_SHA256 if protocol_v2 else PRIOR_ARTIFACT_SHA256 if remaining else None,
        historical_probe_reserved_usd=str(HISTORICAL_PROBE_RESERVED),
        quality_qualified=False,production_admission=False,
        limitations=['Known generated development examples, not sealed holdout or analyst adjudication.',
                    'Catalog ZDR classification and reported costs are not independent provider/billing attestations.',
                    'No production data, model activation, tools, retries or automatic fallback.',
                    'Other account/key consumers are outside this serialized batch accounting.'])
    total=Decimal(0)
    models=tuple(model for i,model in enumerate(ROUTES) if i!=1) if protocol_v2 else tuple(ROUTES)[2:] if remaining else tuple(ROUTES)
    for model in models:
        try:
            preflight(client.request('GET','/api/v1/key').get('data'))
            route=eligible(client.request('GET','/api/v1/endpoints/zdr'),model)
            report['routes'].append(route)
        except Exception as error:
            report['failures'].append(dict(model=model,case_id=None,stage='preflight',reason=error.args[0] if isinstance(error,(ProbeError,RouteError)) else 'preflight_unresolved'))
            continue
        for case_id in CASES:
            packet=selected[case_id]
            body=body_for(model,packet,protocol_v2=protocol_v2)
            # The historical hold is reserved separately by account preflight.
            if CALL_RESERVATION*(report['attempted_calls']+1)+(PRIOR_RESERVED if carrying else Decimal(0))+prior_cost>RUN_ALLOWANCE:
                raise ProbeError('batch_reservation_exhausted')
            try:
                preflight(client.request('GET','/api/v1/key').get('data'))
            except Exception:
                report['failures'].append(dict(model=model,case_id=case_id,stage='preflight',reason='comparison_budget_or_key_unavailable'))
                return report
            report['attempted_calls']+=1
            checkpoint(dict(event='dispatch_started',model=model,case_id=case_id,attempted_calls=report['attempted_calls'],
                            reserved_usd=str(CALL_RESERVATION),unknown_cost_possible=True))
            started=time.monotonic()
            try:
                reply=client.request('POST','/api/v1/chat/completions',body)
                cost=usage_for(reply,model)
            except Exception as error:
                report['unknown_cost_possible']=True
                report['new_unknown_cost_possible']=True
                report['unresolved_comparison_calls']+=1
                report['failures'].append(dict(model=model,case_id=case_id,stage='dispatch',reason='charge_or_response_unresolved_no_retry',diagnostic_code=diagnostic(error)))
                checkpoint(dict(event='dispatch_unresolved',model=model,case_id=case_id,unknown_cost_possible=True))
                return report
            total+=cost
            report['reported_cost_usd']=str(total)
            try:
                result=record_for(reply,model,packet,body,int((time.monotonic()-started)*1000))
                result['matched_development_label']=result['run']['decision']['disposition'] in labels[case_id]
                report['results'].append(result)
                report['validated_calls']+=1
                checkpoint(dict(event='response_validated',model=model,case_id=case_id,cost_usd=str(cost)))
            except Exception as error:
                report['failures'].append(dict(model=model,case_id=case_id,stage='contract',reason='decision_contract_rejected_known_reported_cost',diagnostic_code=diagnostic(error),response_digest=digest(reply),shape=shape(reply),invalid_identifier_fields=invalid_identifier_fields(reply)))
                checkpoint(dict(event='response_rejected',model=model,case_id=case_id,cost_usd=str(cost),unknown_cost_possible=False))
                break
    return report


def main():
    secret=os.environ.pop('OPENROUTER_API_KEY','')
    def emit(event):
        raw=canonical(event)
        if secret and secret.encode() in raw: raise ProbeError('credential_output_rejected')
        print(raw.decode(),flush=True)
    try:
        if sys.argv[1:] not in ([],['--remaining-after-checkpoint'],['--protocol-v2-development']): raise ProbeError('comparison_arguments_denied')
        report=compare(OpenRouterTransport(LabCredential(secret)),load_json('/app/development_corpus.json'),emit,
                       remaining=sys.argv[1:]==['--remaining-after-checkpoint'],protocol_v2=sys.argv[1:]==['--protocol-v2-development'])
        emit(dict(event='comparison_final',report=report))
        return 2 if report['new_unknown_cost_possible'] else 0
    except Exception:
        emit(dict(event='comparison_unresolved',quality_qualified=False,production_admission=False))
        return 2


if __name__=='__main__': raise SystemExit(main())
