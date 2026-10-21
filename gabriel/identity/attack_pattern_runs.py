"""Persist candidate correlations only after checking current authority and source ciphertext."""
import re
from uuid import uuid4

from psycopg.types.json import Jsonb

from gabriel.identity.attack_patterns import VERSION,ALTERNATIVES,investigate,normalized
from gabriel.identity.cases import iso,timestamp
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier
from gabriel.identity.specialist_analysis import at,require,uid
from gabriel.identity.specialist_contracts import digest

RULES={
    'repeated-account-failures-10-in-300s':'brute_force',
    'multi-account-failures-10-accounts-5-in-300s':'password_spray',
    'reported-unauthorized-authentication':'password_misuse',
    'success-after-repeated-failures':'password_misuse',
    'authenticated-remote-execution-chain-in-300s':'lateral_movement',
    'same-process-multisource-spread-in-300s':'worm_propagation',
    'bulk-file-change-with-ransom-or-backup-indicator':'ransomware',
    'reported-kernel-or-boot-integrity-violation':'possible_rootkit',
}
GAPS={'authentication','process','network','file','kernel','boot'}


def validate(packet,result):
    require(type(packet) is dict and set(packet)=={'version','organization_id','case_id','input_evidence_id','input_digest',
        'events_digest','event_count','as_of','generated_at','references','source_authenticity','normalization_status'},'invalid_attack_packet')
    require(packet['version']=='attack-pattern-input-v1' and packet['source_authenticity']=='unverified'
        and packet['normalization_status']=='unverified_user_supplied','invalid_attack_packet')
    for key in ('organization_id','case_id','input_evidence_id'): uid(packet[key])
    for key in ('input_digest','events_digest'):
        require(type(packet[key]) is str and re.fullmatch('[a-f0-9]{64}',packet[key]) is not None,'invalid_attack_digest')
    require(type(packet['event_count']) is int and 1<=packet['event_count']<=256,'invalid_attack_count')
    at(packet['as_of'])
    require(type(packet['generated_at']) is str and timestamp(packet['generated_at']) is not None,'invalid_attack_review_time')
    refs=packet['references']
    require(type(refs) is list and 2<=len(refs)<=33,'invalid_attack_references')
    admitted={}
    for ref in refs:
        require(type(ref) is dict and set(ref)=={'ref','record_id','digest','source_verified','content_integrity'},'invalid_attack_reference')
        uid(ref['record_id'])
        require(ref['ref']=='evidence/'+ref['record_id'] and ref['ref'] not in admitted and ref['source_verified'] is False
            and ref['content_integrity']=='verified_at_review' and type(ref['digest']) is str
            and re.fullmatch('[a-f0-9]{64}',ref['digest']) is not None,'invalid_attack_reference')
        admitted[ref['ref']]=ref['digest']
    require(admitted.get('evidence/'+packet['input_evidence_id'])==packet['input_digest'],'attack_input_binding_failed')
    require(type(result) is dict and set(result)=={'version','findings','unique_event_count','forwarded_duplicate_count','coverage',
        'missing_sources','source_authenticity','quality_qualified','live_detection_accepted','external_actions_authorized','limitations'}
        and result['version']==VERSION and result['coverage']=='partial' and result['source_authenticity']=='unverified'
        and all(result[key] is False for key in ('quality_qualified','live_detection_accepted','external_actions_authorized')),'invalid_attack_result')
    require(type(result['unique_event_count']) is int and 1<=result['unique_event_count']<=256
        and type(result['forwarded_duplicate_count']) is int and result['forwarded_duplicate_count']>=0
        and result['unique_event_count']+result['forwarded_duplicate_count']==packet['event_count'],'invalid_attack_count')
    require(type(result['missing_sources']) is list and len(result['missing_sources'])<=6
        and all(type(item) is str and item in GAPS for item in result['missing_sources'])
        and len(set(result['missing_sources']))==len(result['missing_sources']),'invalid_attack_gaps')
    require(type(result['findings']) is list and len(result['findings'])<=128,'invalid_attack_findings')
    for finding in result['findings']:
        require(type(finding) is dict and set(finding)=={'rule_id','family','status','priority','affected_asset_count','observed_event_count',
            'first_event_time','last_event_time','references','reported_approved_event_count','alternative','source_verified','confidence'},'invalid_attack_finding')
        require(type(finding['rule_id']) is str and type(finding['family']) is str and finding['family'] in ALTERNATIVES
            and RULES.get(finding['rule_id'])==finding['family']
            and finding['status']=='suspected_requires_review' and finding['priority']=='urgent_review'
            and finding['source_verified'] is False and finding['confidence']=='unqualified'
            and finding['alternative']==ALTERNATIVES[finding['family']],'invalid_attack_claim')
        require(all(type(finding[key]) is int for key in ('affected_asset_count','observed_event_count','reported_approved_event_count'))
            and 1<=finding['affected_asset_count']<=finding['observed_event_count']<=result['unique_event_count']
            and 0<=finding['reported_approved_event_count']<=finding['observed_event_count'],'invalid_attack_count')
        require(at(finding['first_event_time'])<=at(finding['last_event_time'])<=at(packet['as_of']),'invalid_attack_interval')
        require(type(finding['references']) is list and 1<=len(finding['references'])<=32
            and all(type(ref) is str and ref in admitted and ref!='evidence/'+packet['input_evidence_id'] for ref in finding['references'])
            and len(set(finding['references']))==len(finding['references']),'invalid_attack_finding_reference')
    require(result['limitations']==[
        'Candidate thresholds require independent evaluation; unmatched activity is not a benign verdict.',
        'Only supplied typed events are examined; collection, normalization and current visibility are unverified.',
        'No console observation, model invocation, page navigation or response execution occurs in this kernel.'],'invalid_attack_limitations')
    require(len(canonical(packet))<=65536 and len(canonical(result))<=131072,'attack_record_limit')


def public(row):
    packet,result=row['packet'],row['result']
    validate(packet,result)
    if (digest(packet)!=row['packet_digest'] or digest(result)!=row['result_digest'] or row['engine_version']!=VERSION
            or packet['organization_id']!=str(row['organization_id']) or packet['case_id']!=str(row['case_id'])
            or packet['input_evidence_id']!=str(row['input_evidence_id'])):
        raise AccessDenied('attack_record_integrity_failed')
    return dict(id=str(row['id']),case_id=str(row['case_id']),requested_by=str(row['requested_by']),created_at=iso(row['created_at']),
        packet=packet,result=result,packet_digest=row['packet_digest'],result_digest=row['result_digest'],
        time_basis='historical_supplied_event_snapshot',grants_authority=False,model_cost_usd='0')


def run(service,token,case_id,request_id,input_evidence_id):
    request_id,input_evidence_id=identifier(request_id),identifier(input_evidence_id)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        old=conn.execute('SELECT * FROM gabriel_identity.attack_pattern_runs WHERE organization_id=%s AND case_id=%s AND request_id=%s',
            (p.organization_id,case['id'],request_id)).fetchone()
        if old:
            if old['requested_by']!=p.user_id or old['input_evidence_id']!=input_evidence_id: raise AccessDenied('attack_request_conflict')
            _audit(conn,'attack.review_replayed',p,old['id']);return public(old)
        count=conn.execute('SELECT count(*) AS n FROM gabriel_identity.attack_pattern_runs WHERE organization_id=%s AND case_id=%s',
            (p.organization_id,case['id'])).fetchone()['n']
        if count>=64: raise AccessDenied('case_attack_review_limit')
        def source(eid):
            row=service._evidence(conn,p,eid)
            if row['case_id']!=case['id']: raise AccessDenied('attack_source_case_mismatch')
            if row['source_kind']=='model_generated_text' or conn.execute('SELECT 1 FROM gabriel_identity.model_answer_intents WHERE organization_id=%s AND ingestion_id=%s',
                (p.organization_id,row['ingestion_id'])).fetchone(): raise AccessDenied('model_answer_is_not_attack_source')
            body=service._verify(conn,row);service._custody(conn,p,row,'accessed');return row,body
        original,body=source(input_evidence_id)
        try: document=decode(body.decode('utf-8'))
        except (ValueError,UnicodeError,RecursionError): raise InvalidIdentityInput('invalid_security_events') from None
        normalized(document,case['id'])
        expected={}
        for event in document['events']:
            eid=identifier(event['evidence_id'])
            if eid in expected and expected[eid]!=event['evidence_digest']: raise AccessDenied('attack_source_binding_mismatch')
            expected[eid]=event['evidence_digest']
        if input_evidence_id in expected or not 1<=len(expected)<=32: raise AccessDenied('attack_source_limit_or_self_reference')
        verified=[original]
        for eid,expected_digest in sorted(expected.items(),key=lambda item:str(item[0])):
            row,_=source(eid)
            if row['digest']!=expected_digest: raise AccessDenied('attack_source_binding_mismatch')
            verified.append(row)
        packet=dict(version='attack-pattern-input-v1',organization_id=str(p.organization_id),case_id=str(case['id']),
            input_evidence_id=str(input_evidence_id),input_digest=original['digest'],events_digest=digest(document['events']),event_count=len(document['events']),
            as_of=document['as_of'],generated_at=iso(conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']),
            references=[dict(ref='evidence/'+str(row['id']),record_id=str(row['id']),digest=row['digest'],source_verified=False,
                content_integrity='verified_at_review') for row in verified],source_authenticity='unverified',normalization_status='unverified_user_supplied')
        result=investigate(document,case['id']);validate(packet,result)
        row=conn.execute('''INSERT INTO gabriel_identity.attack_pattern_runs
            (organization_id,id,case_id,request_id,requested_by,input_evidence_id,engine_version,packet,result,packet_digest,result_digest)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
            (p.organization_id,uuid4(),case['id'],request_id,p.user_id,input_evidence_id,VERSION,Jsonb(packet),Jsonb(result),digest(packet),digest(result))).fetchone()
        _audit(conn,'attack.review_completed',p,row['id']);return public(row)


def get(service,token,case_id,run_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token);case=service._case(conn,p,case_id)
        row=conn.execute('SELECT * FROM gabriel_identity.attack_pattern_runs WHERE organization_id=%s AND case_id=%s AND id=%s',
            (p.organization_id,case['id'],identifier(run_id))).fetchone()
        if not row: raise AccessDenied('attack_review_not_accessible')
        value=public(row);_audit(conn,'attack.review_read',p,row['id']);return value


def history(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token);case=service._case(conn,p,case_id)
        rows=conn.execute('SELECT id,created_at FROM gabriel_identity.attack_pattern_runs WHERE organization_id=%s AND case_id=%s ORDER BY created_at DESC,id DESC LIMIT 33',
            (p.organization_id,case['id'])).fetchall()
        return dict(runs=[dict(id=str(row['id']),created_at=iso(row['created_at'])) for row in rows[:32]],truncated=len(rows)>32,limit=32)
