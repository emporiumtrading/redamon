"""Versioned metadata-only role contracts; registry membership does not enable an engine."""
from hashlib import sha256
import re

from gabriel.identity.evidence_store import canonical
from gabriel.identity.cases import timestamp
from gabriel.identity.service import InvalidIdentityInput,identifier

ROLES=('telemetry_health','alert_triage','incident_scoping','threat_intelligence','threat_hunting',
    'dfir_evidence','detection_engineering','exposure_vulnerability','identity_access','cloud_supply_chain',
    'response_remediation','recovery_learning')
CONTRACT_VERSION='specialist-metadata-v1'


def catalog():
    return [dict(role=role,contract_version=CONTRACT_VERSION,
        engine='telemetry-health-v1' if role=='telemetry_health' else None,
        status='implemented_local_read' if role=='telemetry_health' else 'contract_only',
        model_enabled=False,external_actions_enabled=False) for role in ROLES]


def role_name(value):
    if not isinstance(value,str) or value not in ROLES: raise InvalidIdentityInput('unknown_specialist_role')
    return value


def digest(value): return sha256(canonical(value)).hexdigest()


def validate_packet(packet):
    expected={'schema_version','purpose','contract_version','role','organization_id','case_id','generated_at','references',
        'source_limit','sources_truncated','coverage','sampling','evidence_bodies_included'}
    if (not isinstance(packet,dict) or set(packet)!=expected or type(packet['schema_version']) is not int or packet['schema_version']!=1
            or packet['purpose']!='specialist-input-v1' or packet['contract_version']!=CONTRACT_VERSION
            or packet['coverage']!='partial' or packet['sampling']!='individual_live_checks' or packet['evidence_bodies_included'] is not False
            or type(packet['source_limit']) is not int or packet['source_limit']!=32 or type(packet['sources_truncated']) is not bool
            or not isinstance(packet['references'],list) or not 1<=len(packet['references'])<=97):
        raise InvalidIdentityInput('invalid_specialist_packet')
    role_name(packet['role'])
    for key in ('organization_id','case_id'):
        if packet[key]!=str(identifier(packet[key])): raise InvalidIdentityInput('invalid_specialist_scope')
    if timestamp(packet['generated_at']) is None: raise InvalidIdentityInput('specialist_time_required')
    seen=set()
    case_ref='case/'+packet['case_id']
    counts={'case_record':0,'evidence_metadata':0,'browser_lease_sample':0}
    for row in packet['references']:
        if not isinstance(row,dict) or row.get('kind') not in counts: raise InvalidIdentityInput('invalid_specialist_reference')
        kind=row['kind']
        fields={'ref','kind','record_id'}|({'digest','source_verified','content_integrity'} if kind=='evidence_metadata' else {'sample'} if kind=='browser_lease_sample' else set())
        prefix={'case_record':'case/','evidence_metadata':'evidence/','browser_lease_sample':'browser_lease/'}[kind]
        if (set(row)!=fields or row['record_id']!=str(identifier(row['record_id'])) or row['ref']!=prefix+row['record_id'] or row['ref'] in seen):
            raise InvalidIdentityInput('invalid_specialist_reference')
        seen.add(row['ref']); counts[kind]+=1
        if kind=='case_record' and row['ref']!=case_ref: raise InvalidIdentityInput('specialist_case_mismatch')
        if kind=='evidence_metadata' and (not isinstance(row['digest'],str) or not re.fullmatch('[a-f0-9]{64}',row['digest'])
                or row['source_verified'] is not False or row['content_integrity']!='not_checked'):
            raise InvalidIdentityInput('invalid_specialist_evidence')
        if kind=='browser_lease_sample':
            sample=row['sample']
            keys={'id','case_id','browser','health','state','expires_at','last_seen','authorization_current','heartbeat_fresh','page_visibility','sampled_at'}
            if (not isinstance(sample,dict) or set(sample)!=keys or sample['id']!=row['record_id'] or sample['case_id']!=packet['case_id']
                    or sample['browser'] not in {'chrome','brave'} or sample['state'] not in {'pending','active','disconnected'}
                    or sample['health'] not in {'disconnected','authority_unavailable','awaiting_connection','recent_heartbeat','coverage_gap'}
                    or type(sample['authorization_current']) is not bool or type(sample['heartbeat_fresh']) is not bool or sample['page_visibility']!='unverified'):
                raise InvalidIdentityInput('invalid_specialist_source_sample')
            for key in ('expires_at','sampled_at'):
                if timestamp(sample[key]) is None: raise InvalidIdentityInput('specialist_time_required')
            timestamp(sample['last_seen'])
    if counts['case_record']!=1 or counts['evidence_metadata']>64 or counts['browser_lease_sample']>32 or len(canonical(packet))>131072:
        raise InvalidIdentityInput('specialist_packet_limit')
    return packet


def validate_result(packet,result):
    validate_packet(packet)
    expected={'schema_version','purpose','role','contract_version','observations','hypotheses','alternatives',
        'contradictions','uncertainty','next_steps','coverage','incident_assessment','attack_status','execution'}
    if (not isinstance(result,dict) or set(result)!=expected or type(result['schema_version']) is not int
            or result['schema_version']!=1 or result['purpose']!='specialist-result-v1'
            or result['contract_version']!=CONTRACT_VERSION or result['role']!=role_name(packet['role'])
            or result['role']!='telemetry_health'
            or result['coverage']!='partial' or result['incident_assessment']!='not_performed' or result['attack_status']!='unknown'):
        raise InvalidIdentityInput('invalid_specialist_result')
    admitted={row['ref'] for row in packet['references']}
    for key in ('observations','hypotheses','alternatives','contradictions'):
        rows=result[key]
        if not isinstance(rows,list) or len(rows)>64: raise InvalidIdentityInput('invalid_specialist_claims')
        for row in rows:
            if (not isinstance(row,dict) or set(row)!={'statement','references','source_verified'} or row['source_verified'] is not False
                    or not isinstance(row['statement'],str) or not 1<=len(row['statement'])<=512
                    or any(ord(c)<32 or ord(c)==127 for c in row['statement'])
                    or not isinstance(row['references'],list) or not 1<=len(row['references'])<=32
                    or any(not isinstance(ref,str) or ref not in admitted for ref in row['references'])
                    or len(set(row['references']))!=len(row['references'])):
                raise InvalidIdentityInput('unsupported_specialist_claim')
    if (not isinstance(result['uncertainty'],list) or not 1<=len(result['uncertainty'])<=16
            or any(not isinstance(item,str) or not 1<=len(item)<=512 or any(ord(c)<32 for c in item) for item in result['uncertainty'])
            or not isinstance(result['next_steps'],list) or len(result['next_steps'])>8
            or any(not isinstance(item,str) or item not in {'review_browser_scope','restore_engineer_session','review_source_visibility'} for item in result['next_steps'])):
        raise InvalidIdentityInput('invalid_specialist_limits')
    execution=result['execution']
    if (not isinstance(execution,dict) or set(execution)!={'engine','provider','model','prompt_version','playbook_version','tools','model_cost_usd','elapsed_ms'}
            or execution['engine']!='telemetry-health-v1' or any(execution[key] is not None for key in ('provider','model','prompt_version'))
            or execution['playbook_version']!='telemetry-health-v1' or execution['tools']!=[{'name':'source_health','version':'source-health-v1'}]
            or execution['model_cost_usd']!='0' or type(execution['elapsed_ms']) is not int or not 0<=execution['elapsed_ms']<=120000):
        raise InvalidIdentityInput('invalid_specialist_execution')
    if len(canonical(result))>65536: raise InvalidIdentityInput('specialist_result_limit')
    return result
