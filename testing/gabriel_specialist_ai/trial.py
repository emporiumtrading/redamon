"""Offline authored per-agent development requests, never qualification or dispatch."""
from itertools import permutations
from decimal import Decimal
from hashlib import sha256
import json
from uuid import NAMESPACE_DNS,uuid5

from gabriel.identity.evidence_store import canonical
from gabriel.identity.specialist_agents import DEFAULT_MODEL,ROLES,TOOLS,configuration,project,prompt
from gabriel.identity.specialist_analysis import analyze
from gabriel.identity.model_evaluation import digest

EXAMPLES={
    'telemetry_health':('coverage',dict(state='missing'),dict(state='available')),
    'alert_triage':('alert',dict(severity='critical',state='open'),dict(severity='informational',state='resolved')),
    'incident_scoping':('activity',dict(category='network',outcome='failure',count=10),dict(category='network',outcome='success',count=1)),
    'threat_intelligence':('intelligence',dict(match=True,valid_until='2026-10-27T12:00:00Z'),dict(match=False,valid_until='2026-10-27T12:00:00Z')),
    'threat_hunting':('activity',dict(category='process',outcome='observed',count=10),dict(category='process',outcome='blocked',count=1)),
    'dfir_evidence':('artifact',dict(integrity='mismatch',custody='gap'),dict(integrity='match',custody='complete')),
    'detection_engineering':('detection',dict(cohort='malicious',matched=False,expected_match=True),dict(cohort='benign',matched=False,expected_match=False)),
    'exposure_vulnerability':('exposure',dict(severity='critical',reachable='yes',mitigated='no'),dict(severity='low',reachable='no',mitigated='yes')),
    'identity_access':('identity',dict(event='mfa_disabled',authorized='no'),dict(event='privilege_grant',authorized='yes')),
    'cloud_supply_chain':('cloud',dict(finding='unsigned_component',state='present',authorized='no'),dict(finding='unsigned_component',state='absent',authorized='unknown')),
    'response_remediation':('response_check',dict(check='recovery',passed='no'),dict(check='recovery',passed='yes')),
    'recovery_learning':('recovery',dict(check='restore',result='fail',baseline='stale'),dict(check='restore',result='pass',baseline='current')),
}


def export():
    requests=[];configs={}
    assert set(EXAMPLES)==set(ROLES)
    for role in ROLES:
        configs[role]=configuration(role)
        for index,data in enumerate(EXAMPLES[role][1:]):
            name=role+'-'+str(index+1)
            case=uuid5(NAMESPACE_DNS,'gabriel-agent-development/'+name)
            source=uuid5(case,'source');job=uuid5(case,'agent')
            document=dict(version='specialist-facts-v1',case_id=str(case),as_of='2026-10-25T12:00:00Z',facts=[
                dict(id=str(uuid5(case,'fact')),type=EXAMPLES[role][0],evidence_id=str(source),
                    evidence_digest=sha256(b'authored generated source').hexdigest(),entity_id=str(uuid5(case,'entity')),
                    event_time='2026-10-25T11:00:00Z',data=data)])
            def result(name):
                if name=='verify_sources':value=dict(verified_artifact_count=2,source_authenticity='unverified')
                elif name=='review_memory':value=dict(reviewed_local_references=0,contents_exported=False)
                elif name=='inspect_timeline':value=dict(earliest=document['facts'][0]['event_time'],latest=document['facts'][0]['event_time'],reported_as_of=document['as_of'],source_clock_verified=False)
                else:
                    assessment=analyze(role,document,'local-input')
                    value=dict(urgency=assessment['urgency'],observations=[r['statement'] for r in assessment['observations']],hypotheses=[r['statement'] for r in assessment['hypotheses']],qualified=False)
                return dict(tool=name,result=value)
            paths=[()]+list(permutations(TOOLS[role],1))+list(permutations(TOOLS[role],2))
            for path in paths:
                prepared=project(document,role,job,[result(t) for t in path])
                body=dict(model=DEFAULT_MODEL,messages=[dict(role='system',content=prompt(role)),
                    dict(role='user',content=canonical(prepared['packet']).decode())],**configs[role]['parameters'])
                wire=canonical(body)
                assert len(wire)<=7000 and str(source).encode() not in wire and str(case).encode() not in wire
                requests.append(dict(case_id=name,role=role,round=len(path)+1,tool_history=list(path),configuration_digest=digest(configs[role]),body=body,
                    body_sha256=sha256(wire).hexdigest(),source_classification='authored_synthetic_development',
                    ground_truth='independent_adjudication_pending'))
    assert len(requests)==240
    return dict(version='gabriel-specialist-agent-development-packet-v1',requests=requests,
        approved_body_count=len(requests),initial_case_count=24,maximum_model_calls=72,configurations=configs,request_set_sha256=digest(requests),
        destination='https://openrouter.ai/api/v1/chat/completions',provider='Cerebras',model=DEFAULT_MODEL,
        maximum_reservation_usd=str(Decimal('0.006304')*72),per_request_ceiling_usd='0.006304',
        live_calls_made=0,production_admission=False,quality_qualified=False,
        scope='24 authored cases; at most three model rounds per case. Only the exact enumerated body for the actual non-repeated local-tool history may dispatch. Stop the entire batch on any unresolved provider outcome; no retries, fallback or additional cases.',
        qualification_status='development_compatibility_only_not_sealed_holdout')


if __name__=='__main__':print(json.dumps(export(),sort_keys=True,indent=2))
