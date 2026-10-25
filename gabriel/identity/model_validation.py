"""Ten authored validation cases on one exact route; never held-out qualification."""
from decimal import Decimal
import os
import sys
import time

from gabriel.identity.model_evaluation import canonical,digest,load_json,packets
from gabriel.identity.model_lab import LabCredential,body_for,diagnostic,preflight,record_for,usage_for,CALL_RESERVATION
from gabriel.identity.model_protocol import ProbeError,money
from gabriel.identity.model_routes import eligible
from gabriel.identity.model_transport import OpenRouterTransport

CORPUS_DIGEST='3563d5c5e272f42321a4a793c3fe254afc10b321787e11ec86354e67082cdda7'
MODEL='openai/gpt-oss-120b'
CARRIED_UNRESOLVED=Decimal('0.012608')


def account(data):
    if type(data) is not dict: raise ProbeError('account_preflight_required')
    adjusted=dict(data)
    for name in ('usage_daily','usage_monthly'):
        adjusted[name]=str(money(data.get(name))+CARRIED_UNRESOLVED)
    adjusted['limit_remaining']=str(money(data.get('limit_remaining'))-CARRIED_UNRESOLVED)
    return preflight(adjusted)


def validate(client,corpus,checkpoint=lambda event:None):
    if digest(corpus)!=CORPUS_DIGEST: raise ProbeError('pinned_validation_corpus_required')
    selected=packets(corpus,'validation')
    if len(selected)!=10: raise ProbeError('validation_case_count_changed')
    labels={row['id']:row['label']['acceptable_decisions'] for row in corpus['cases'] if row['split']=='validation'}
    report=dict(version='gabriel-authored-validation-v1',model=MODEL,corpus_sha256=CORPUS_DIGEST,
        partition='validation',planned_cases=10,attempted_calls=0,validated_calls=0,reported_cost_usd='0',
        new_unresolved_reserved_usd='0',carried_unresolved_reserved_usd=str(CARRIED_UNRESOLVED),
        batch_reservation_usd=str(10*CALL_RESERVATION),results=[],failures=[],quality_qualified=False,
        production_admission=False,independent_analyst_reviews='pending',held_out_cases_dispatched=0)
    try:
        account(client.request('GET','/api/v1/key').get('data'))
        report['route']=eligible(client.request('GET','/api/v1/endpoints/zdr'),MODEL)
    except Exception as error:
        report['failures'].append(dict(stage='preflight',reason=diagnostic(error)))
        return report
    total=Decimal(0)
    for packet in selected:
        try: account(client.request('GET','/api/v1/key').get('data'))
        except Exception as error:
            report['failures'].append(dict(case_id=packet['case_id'],stage='preflight',reason=diagnostic(error)));break
        body=body_for(MODEL,packet,protocol_v2=True)
        # A failed journal write must stop before any potentially billable request.
        checkpoint(dict(event='validation_dispatch_reserved',case_id=packet['case_id'],model=MODEL,
            input_sha256=packet['input_sha256'],reserved_usd=str(CALL_RESERVATION)))
        report['attempted_calls']+=1;started=time.monotonic()
        try:
            reply=client.request('POST','/api/v1/chat/completions',body)
            cost=usage_for(reply,MODEL)
        except Exception as error:
            report['new_unresolved_reserved_usd']=str(CALL_RESERVATION)
            report['failures'].append(dict(case_id=packet['case_id'],stage='dispatch',reason=diagnostic(error),retry=False))
            checkpoint(dict(event='validation_dispatch_unresolved',case_id=packet['case_id'],reserved_usd=str(CALL_RESERVATION)))
            break
        total+=cost;report['reported_cost_usd']=str(total)
        try:
            result=record_for(reply,MODEL,packet,body,int((time.monotonic()-started)*1000))
            result['matched_provisional_label']=result['run']['decision']['disposition'] in labels[packet['case_id']]
            report['results'].append(result);report['validated_calls']+=1
            checkpoint(dict(event='validation_response_recorded',case_id=packet['case_id'],cost_usd=str(cost),run_sha256=digest(result['run'])))
        except Exception as error:
            report['failures'].append(dict(case_id=packet['case_id'],stage='contract',reason=diagnostic(error),known_reported_cost_usd=str(cost),retry=False))
            break
    return report


def main():
    secret=os.environ.pop('OPENROUTER_API_KEY','')
    def emit(value):
        raw=canonical(value)
        if secret and secret.encode() in raw: raise ProbeError('credential_output_rejected')
        print(raw.decode(),flush=True)
    try:
        if sys.argv[1:]: raise ProbeError('validation_arguments_denied')
        report=validate(OpenRouterTransport(LabCredential(secret)),load_json('/app/corpus.json'),emit)
        emit(dict(event='validation_final',report=report))
        return 0 if report['validated_calls']==10 and not report['failures'] else 2
    except Exception:
        emit(dict(event='validation_unresolved',quality_qualified=False,production_admission=False))
        return 2


if __name__=='__main__': raise SystemExit(main())
