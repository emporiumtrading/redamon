"""Offline proposed compatibility requests; no credentials, network or dispatch."""
from copy import deepcopy
from decimal import Decimal
from uuid import UUID
import json

from gabriel.identity import hermes_supervisor as hermes,specialist_agents as agents
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest
from gabriel.identity.reviewed_memory import VERSION as MEMORY_VERSION

SAMPLES={
    'telemetry_health':('coverage',dict(state='missing')),
    'alert_triage':('alert',dict(severity='critical',state='open')),
    'incident_scoping':('activity',dict(category='network',outcome='observed',count=10)),
    'threat_intelligence':('intelligence',dict(match=True,valid_until='2026-10-28T12:00:00Z')),
    'threat_hunting':('activity',dict(category='process',outcome='observed',count=10)),
    'dfir_evidence':('artifact',dict(integrity='mismatch',custody='gap')),
    'detection_engineering':('detection',dict(cohort='malicious',matched=False,expected_match=True)),
    'exposure_vulnerability':('exposure',dict(severity='critical',reachable='yes',mitigated='no')),
    'identity_access':('identity',dict(event='mfa_disabled',authorized='no')),
    'cloud_supply_chain':('cloud',dict(finding='unsigned_component',state='present',authorized='no')),
    'response_remediation':('response_check',dict(check='recovery',passed='no')),
    'recovery_learning':('recovery',dict(check='restore',result='fail',baseline='stale')),
}


def document(index,role):
    kind,data=SAMPLES[role]
    return dict(version='specialist-facts-v1',case_id=str(UUID(int=1000+index)),as_of='2026-10-27T12:00:00Z',
        facts=[dict(id=str(UUID(int=2000+index)),type=kind,evidence_id=str(UUID(int=3000+index)),
            evidence_digest=digest(['authored source',role]),entity_id=str(UUID(int=4000+index)),
            event_time='2026-10-27T11:00:00Z',data=deepcopy(data))])


def history(index,doc):
    fact=doc['facts'][0]
    assertion=dict(id='h1',type=fact['type'],event_time='2026-10-26T11:00:00Z',entity='e1',data=deepcopy(fact['data']))
    result=dict(version=MEMORY_VERSION,state='historical_references',historical_assertions=[assertion],
        coverage='bounded_partial_references',source_authenticity='unverified',independent_corroboration=False,
        entity_binding='matching_supplied_identifier_unverified',grants_authority=False,
        model_training_performed=False,contents_exported=True,free_text_exported=False)
    return dict(tool='review_memory',result=result,_reviewed_memory=dict(records=[str(UUID(int=5000+index))],
        lineage={'h1':dict(record_id=str(UUID(int=6000+index)),evidence_id=fact['evidence_id'],
            evidence_digest=fact['evidence_digest'],historical_reviewed_memory=True)}))


def export():
    configurations={};requests=[];private=[]
    def add(name,configuration,prompt,prepared):
        body=dict(model=configuration['model'],messages=[dict(role='system',content=prompt),
            dict(role='user',content=canonical(prepared['packet']).decode())],**configuration['parameters'])
        wire=canonical(body)
        if len(wire)>7000:raise ValueError('proposed_request_exceeds_existing_wire_limit')
        if any(value.encode() in wire for value in private):raise ValueError('private_fixture_identifier_in_request')
        requests.append(dict(name=name,configuration_digest=digest(configuration),body=body,body_sha256=digest(body),
            source_classification='authored_synthetic_development_only',independent_adjudication='pending'))
    composite=None
    for index,role in enumerate(agents.ROLES,1):
        doc=document(index,role);fact=doc['facts'][0]
        private.extend([doc['case_id'],fact['id'],fact['evidence_id'],fact['entity_id'],str(UUID(int=5000+index)),str(UUID(int=6000+index))])
        if composite is None:composite=deepcopy(doc)
        else:composite['facts'].extend(deepcopy(doc['facts']))
        config=agents.configuration(role);configurations[role]=config
        for name,tools in [('current',[]),('historical',[history(index,doc)])]:
            add(role+'/'+name,config,agents.prompt(role),agents.project(doc,role,UUID(int=7000+index),tools))
    for stage in ('plan','report'):
        config=hermes.configuration(stage);configurations['hermes/'+stage]=config
        add('hermes/'+stage,config,hermes.prompt(stage),hermes.project(composite,stage))
    return dict(version='gabriel-proposed-release-compatibility-v1',requests=requests,configurations=configurations,
        request_set_sha256=digest(requests),request_count=len(requests),configuration_count=len(configurations),
        destination='https://openrouter.ai/api/v1/chat/completions',model=agents.DEFAULT_MODEL,provider='Cerebras',
        authorization='not_approved_for_dispatch',maximum_proposed_calls=26,
        per_request_reservation_usd='0.006304',maximum_proposed_reservation_usd=str(Decimal('0.006304')*26),
        live_calls_made=0,network_calls=0,production_admission=False,quality_qualified=False,
        scope='One response per exact listed body; no tool follow-up, retry, fallback, top-up or additional requests. A later explicitly authorized runner must recheck funding, route/privacy, exact configuration/body hashes and durable no-resend accounting.',
        limitations=['This export performs no native SDK request preparation or provider inference.',
            'Historical data is an authored fixture, not an approved operational reference.',
            'No TryHackMe content, answer keys, telemetry or training data is included.',
            'Compatibility results cannot replace independent qualification or release acceptance.'])


if __name__=='__main__':print(json.dumps(export(),sort_keys=True,indent=2))
