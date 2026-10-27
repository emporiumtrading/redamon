"""Explicit-approval, single-use compatibility runner; never production admission."""
import argparse
from decimal import Decimal
import os
from pathlib import Path
import re
import time

from packet import export
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest,validate_run
from gabriel.identity.model_protocol import ProbeError,budget_check,decode,money
from gabriel.identity.model_routes import eligible
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.provider_onboarding import dispatch_credit
from gabriel.identity.specialist_agents import TOOLS

CEILING=Decimal('0.006304')


def reason(error):
    code=str(error)
    return code if re.fullmatch('[a-z0-9_]{1,80}',code) else 'compatibility_outcome_unresolved'


def verify(packet,approval):
    current=export()
    if packet!=current or approval!=current['request_set_sha256']:
        raise ProbeError('explicit_current_packet_approval_required')
    return current


def funding(client,remaining,model):
    data=client.request('GET','/api/v1/key').get('data')
    if type(data) is not dict:raise ProbeError('key_metadata_missing')
    adjusted=dict(data)
    for key in ('usage_daily','usage_monthly'):adjusted[key]=str(money(data.get(key))+remaining)
    left=money(data.get('limit_remaining'))
    if left<remaining:raise ProbeError('compatibility_credit_unavailable')
    adjusted['limit_remaining']=str(left-remaining)
    budget_check(adjusted)
    dispatch_credit(client.request('GET','/api/v1/credits'),int(remaining*1000000))
    eligible(client.request('GET','/api/v1/endpoints/zdr'),model)


def actions(row,decision):
    requested=decision['requested_actions']
    packet=decode(row['body']['messages'][1]['content'])
    if row['name']=='hermes/plan':
        if len(requested)>4 or not set(requested)<=set(packet['eligible_roles']):raise ProbeError('hermes_assignment_not_admitted')
    elif row['name']=='hermes/report':
        if requested:raise ProbeError('external_action_requested')
    elif len(requested)>1 or not set(requested)<=set(TOOLS[packet['role']]):raise ProbeError('specialist_tool_not_admitted')
    urgent=any(o['type']=='exposure' and o['data']['severity'] in {'high','critical'}
        and o['data']['reachable']=='yes' and o['data']['mitigated']!='yes' for o in packet['observations'])
    if urgent and (decision['disposition']=='benign' or row['name']=='hermes/plan' and 'exposure_vulnerability' not in requested):
        raise ProbeError('urgent_exposure_review_required')


def run(client,packet,approval,checkpoint):
    verify(packet,approval)
    summary=dict(version='gabriel-release-compatibility-v1',request_set_sha256=approval,
        attempted_calls=0,validated_calls=0,reported_cost_usd='0',unresolved_reserved_usd='0',
        results=[],failures=[],production_admission=False,quality_qualified=False,
        raw_responses_exported=False,model_training_performed=False,independent_review='pending')
    total=Decimal(0);generations=set()
    for row in packet['requests']:
        remaining=CEILING*(26-summary['attempted_calls'])
        try:funding(client,remaining,packet['model'])
        except Exception as error:
            summary['failures'].append(dict(request=row['name'],stage='preflight',reason=reason(error)))
            return summary
        checkpoint(dict(event='dispatch_reserved',request=row['name'],body_sha256=row['body_sha256'],reserved_usd=str(CEILING)))
        summary['attempted_calls']+=1;started=time.monotonic()
        try:
            reply=client.request('POST','/api/v1/chat/completions',row['body'])
            if type(reply) is not dict or reply.get('model')!=packet['model'] or reply.get('provider')!=packet['provider']:
                raise ProbeError('unexpected_model_or_provider')
            usage=reply.get('usage',{})
            if type(usage) is not dict or any(type(usage.get(k)) is not int or not 0<=usage[k]<=n
                    for k,n in [('prompt_tokens',8000),('completion_tokens',768)]):raise ProbeError('actual_token_limit_exceeded')
            cost=money(usage.get('cost'))
            if cost>CEILING:raise ProbeError('actual_call_cost_exceeded')
        except Exception as error:
            summary['unresolved_reserved_usd']=str(CEILING)
            summary['failures'].append(dict(request=row['name'],stage='dispatch',reason=reason(error),retry=False))
            return summary
        total+=cost;summary['reported_cost_usd']=str(total)
        try:
            choices=reply.get('choices')
            if type(choices) is not list or len(choices)!=1 or choices[0].get('finish_reason')!='stop':raise ProbeError('incomplete_provider_answer')
            message=choices[0].get('message')
            if type(message) is not dict or message.get('tool_calls') or type(message.get('content')) is not str:raise ProbeError('invalid_provider_answer')
            decision=decode(message['content'])
            result=dict(case_id=row['name'],input_sha256=row['body_sha256'],configuration_sha256=row['configuration_digest'],
                origin='live_provider',generation_id=reply.get('id'),latency_ms=int((time.monotonic()-started)*1000),
                cost_usd=float(cost),input_tokens=usage['prompt_tokens'],output_tokens=usage['completion_tokens'],decision=decision)
            validate_run(result,dict(case_id=row['name'],input_sha256=row['body_sha256'],observations=[dict(id=r) for r in row['allowed_references']]))
            if result['generation_id'] in generations:raise ProbeError('duplicate_generation')
            generations.add(result['generation_id']);actions(row,decision)
            summary['validated_calls']+=1
            summary['results'].append(dict(request=row['name'],decision_digest=digest(decision),
                disposition=decision['disposition'],requested_actions=decision['requested_actions'],contract_valid=True,semantic_review='pending'))
            checkpoint(dict(event='response_validated',request=row['name'],decision_digest=digest(decision),reported_cost_usd=str(cost)))
        except Exception as error:
            summary['failures'].append(dict(request=row['name'],stage='contract',reason=reason(error),retry=False))
            return summary
    return summary


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approve-request-set',required=True)
    parser.add_argument('--private-results',required=True)
    args=parser.parse_args(argv)
    packet=export();verify(packet,args.approve_request_set)
    root=Path(args.private_results)
    if not root.is_absolute() or '..' in root.parts:raise ProbeError('absolute_private_results_required')
    root.mkdir(mode=0o700,parents=False,exist_ok=True)
    parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    secret=''
    try:
        if os.fstat(parent).st_mode&0o077 or os.fstat(parent).st_uid!=os.getuid():raise ProbeError('private_results_permissions_required')
        fd=os.open('dispatch-started',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'w') as out:out.write(args.approve_request_set);out.flush();os.fsync(out.fileno())
        os.fsync(parent)
        fd=os.open('events.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as journal:
            def emit(value):
                raw=canonical(value)
                if secret and secret.encode() in raw:raise ProbeError('credential_output_rejected')
                journal.write(raw+b'\n');journal.flush();os.fsync(journal.fileno())
            secret=os.environ.pop('OPENROUTER_API_KEY','')
            if not secret:raise ProbeError('private_provider_credential_required')
            class Credential:
                def reveal(self):return secret
            report=run(OpenRouterTransport(Credential()),packet,args.approve_request_set,emit)
            emit(dict(event='compatibility_final',summary=report))
            print(canonical(report).decode())
            return 0 if report['validated_calls']==26 and not report['failures'] else 2
    finally:os.close(parent)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('Compatibility run stopped; inspect the private journal before any further action. No automatic retry is authorized.')
        raise SystemExit(2)
