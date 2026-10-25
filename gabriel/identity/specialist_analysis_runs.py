"""Persist bounded specialist summaries after authoritative source-byte checks."""
import re
import time
from uuid import uuid4

from psycopg.types.json import Jsonb

from gabriel.identity.cases import iso, timestamp
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied, InvalidIdentityInput, _audit, connection, identifier
from gabriel.identity.specialist_analysis import CONTRACT, NEXT_STEPS, VERSION, analyze, require, uid, validate_document
from gabriel.identity.specialist_contracts import digest, role_name


def validate_packet(packet):
    keys={'schema_version','purpose','contract_version','role','organization_id','case_id','generated_at','references',
          'input_evidence_id','input_digest','facts_digest','fact_count','as_of','coverage','evidence_bodies_included',
          'source_authenticity','normalization_status'}
    require(type(packet) is dict and set(packet)==keys and type(packet['schema_version']) is int and packet['schema_version']==2
            and packet['purpose']=='specialist-input-v2' and packet['contract_version']==CONTRACT
            and packet['coverage']=='partial' and packet['evidence_bodies_included'] is False
            and packet['source_authenticity']=='unverified' and packet['normalization_status']=='unverified_user_supplied',
            'invalid_specialist_analysis_packet')
    role_name(packet['role'])
    for key in ('organization_id','case_id','input_evidence_id'):
        uid(packet[key])
    for key in ('input_digest','facts_digest'):
        require(type(packet[key]) is str and re.fullmatch('[a-f0-9]{64}',packet[key]) is not None,'invalid_specialist_analysis_digest')
    require(type(packet['fact_count']) is int and 1<=packet['fact_count']<=128,'invalid_specialist_analysis_count')
    for key in ('generated_at','as_of'):
        require(timestamp(packet[key]) is not None,'invalid_specialist_analysis_time')
    refs=packet['references']
    require(type(refs) is list and 2<=len(refs)<=34,'invalid_specialist_analysis_references')
    seen=set()
    cases=0
    for row in refs:
        require(type(row) is dict and row.get('kind') in {'case_record','evidence_metadata'},'invalid_specialist_analysis_reference')
        uid(row.get('record_id'))
        kind=row['kind']
        prefix='case/' if kind=='case_record' else 'evidence/'
        fields={'ref','kind','record_id'} | ({'digest','source_verified','content_integrity'} if kind=='evidence_metadata' else set())
        require(set(row)==fields and row['ref']==prefix+row['record_id'] and row['ref'] not in seen,'invalid_specialist_analysis_reference')
        seen.add(row['ref'])
        if kind=='case_record':
            cases+=1
            require(row['record_id']==packet['case_id'],'specialist_case_mismatch')
        else:
            require(row['source_verified'] is False and row['content_integrity']=='verified'
                    and type(row['digest']) is str and re.fullmatch('[a-f0-9]{64}',row['digest']) is not None,'invalid_specialist_analysis_reference')
    require(cases==1 and any(r['record_id']==packet['input_evidence_id'] and r.get('digest')==packet['input_digest']
                            for r in refs if r['kind']=='evidence_metadata'),'specialist_input_binding_failed')
    require(len(canonical(packet))<=65536,'specialist_packet_limit')
    return packet


def validate_result(packet,result):
    validate_packet(packet)
    keys={'schema_version','purpose','contract_version','role','observations','hypotheses','alternatives','contradictions',
          'uncertainty','next_steps','coverage','incident_assessment','attack_status','urgency','confidence',
          'external_actions_authorized','execution'}
    require(type(result) is dict and set(result)==keys and type(result['schema_version']) is int and result['schema_version']==2
            and result['purpose']=='specialist-result-v2' and result['contract_version']==CONTRACT and result['role']==packet['role']
            and result['coverage']=='partial' and result['incident_assessment'] in {'bounded_rule_review','abstained'}
            and result['attack_status']=='unknown' and result['urgency'] in {'review','urgent_review','visibility_gap'}
            and result['confidence']=='unqualified' and result['external_actions_authorized'] is False,'invalid_specialist_analysis_result')
    admitted={r['ref'] for r in packet['references'] if r['kind']=='evidence_metadata'}
    for key in ('observations','hypotheses','alternatives','contradictions'):
        rows=result[key]
        require(type(rows) is list and len(rows)<=32 and (key not in {'observations','alternatives'} or len(rows)>0),'invalid_specialist_analysis_claims')
        for row in rows:
            require(type(row) is dict and set(row)=={'statement','references','source_verified'} and row['source_verified'] is False
                    and type(row['statement']) is str and 1<=len(row['statement'])<=512
                    and all(ord(c)>=32 and ord(c)!=127 for c in row['statement'])
                    and type(row['references']) is list and 1<=len(row['references'])<=32
                    and all(type(ref) is str and ref in admitted for ref in row['references'])
                    and len(set(row['references']))==len(row['references']),'unsupported_specialist_analysis_claim')
    require(type(result['uncertainty']) is list and 1<=len(result['uncertainty'])<=16
            and all(type(item) is str and 1<=len(item)<=512 and all(ord(c)>=32 and ord(c)!=127 for c in item)
                    for item in result['uncertainty'])
            and result['next_steps']==NEXT_STEPS[packet['role']],'invalid_specialist_analysis_limits')
    execution=result['execution']
    require(type(execution) is dict and set(execution)=={'engine','provider','model','prompt_version','playbook_version','tools','model_cost_usd','elapsed_ms'}
            and execution['engine']==VERSION and execution['playbook_version']==VERSION
            and all(execution[key] is None for key in ('provider','model','prompt_version'))
            and execution['tools']==[dict(name='typed_fact_rules',version=VERSION)] and execution['model_cost_usd']=='0'
            and type(execution['elapsed_ms']) is int and 0<=execution['elapsed_ms']<=120000,'invalid_specialist_analysis_execution')
    require(len(canonical(result))<=65536,'specialist_result_limit')
    return result


def verified_input(service,conn,p,case,input_evidence_id):
    def source(eid):
        row=service._evidence(conn,p,eid)
        if row['case_id']!=case['id']:
            raise AccessDenied('specialist_source_case_mismatch')
        if row['source_kind']=='model_generated_text' or conn.execute('''SELECT 1 FROM gabriel_identity.model_answer_intents
            WHERE organization_id=%s AND ingestion_id=%s''',(p.organization_id,row['ingestion_id'])).fetchone():
            raise AccessDenied('model_answer_is_not_specialist_source')
        body=service._verify(conn,row)
        service._custody(conn,p,row,'accessed')
        return row,body
    original,body=source(input_evidence_id)
    try:
        document=decode(body.decode('utf-8'))
    except (ValueError,UnicodeError,RecursionError):
        raise InvalidIdentityInput('invalid_specialist_facts') from None
    validate_document(document,case['id'])
    expected={}
    for fact in document['facts']:
        eid=identifier(fact['evidence_id'])
        if eid==input_evidence_id or eid in expected and expected[eid]!=fact['evidence_digest']:
            raise AccessDenied('specialist_source_binding_mismatch')
        expected[eid]=fact['evidence_digest']
    refs=[dict(ref='case/'+str(case['id']),kind='case_record',record_id=str(case['id']))]
    rows=[original]
    for eid,expected_digest in sorted(expected.items(),key=lambda item:str(item[0])):
        row,_=source(eid)
        if row['digest']!=expected_digest:
            raise AccessDenied('specialist_source_binding_mismatch')
        rows.append(row)
    refs.extend(dict(ref='evidence/'+str(row['id']),kind='evidence_metadata',record_id=str(row['id']),
                     digest=row['digest'],source_verified=False,content_integrity='verified') for row in rows)
    return original,document,refs


def run(service,token,case_id,request_id,role,input_evidence_id,*,_admission=None):
    role=role_name(role)
    request_id,input_evidence_id=identifier(request_id),identifier(input_evidence_id)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        if _admission is not None: _admission(conn)
        return run_in_connection(service,conn,p,case,request_id,role,input_evidence_id)


def run_in_connection(service,conn,p,case,request_id,role,input_evidence_id):
    from gabriel.identity.specialists import _replay, public_run
    role=role_name(role)
    request_id,input_evidence_id=identifier(request_id),identifier(input_evidence_id)
    started=time.monotonic()
    old=_replay(conn,p,case,request_id,role)
    if old:
        if old['packet'].get('input_evidence_id')!=str(input_evidence_id):
            raise AccessDenied('specialist_request_conflict')
        _audit(conn,'specialist.run_replayed',p,old['id'])
        return public_run(old)
    n=conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE organization_id=%s AND case_id=%s',
                   (p.organization_id,case['id'])).fetchone()['n']
    if n>=128:
        raise AccessDenied('case_specialist_run_limit')
    original,document,refs=verified_input(service,conn,p,case,input_evidence_id)
    packet=dict(schema_version=2,purpose='specialist-input-v2',contract_version=CONTRACT,role=role,
        organization_id=str(p.organization_id),case_id=str(case['id']),
        generated_at=iso(conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']),references=refs,
        input_evidence_id=str(input_evidence_id),input_digest=original['digest'],facts_digest=digest(document['facts']),
        fact_count=len(document['facts']),as_of=document['as_of'],coverage='partial',evidence_bodies_included=False,
        source_authenticity='unverified',normalization_status='unverified_user_supplied')
    result=analyze(role,document,'evidence/'+str(input_evidence_id))
    result['execution']['elapsed_ms']=int((time.monotonic()-started)*1000)
    validate_result(packet,result)
    row=conn.execute('''INSERT INTO gabriel_identity.specialist_runs
        (organization_id,id,case_id,request_id,requested_by,role,engine_version,packet,result,packet_digest,result_digest)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
        (p.organization_id,uuid4(),case['id'],request_id,p.user_id,role,VERSION,Jsonb(packet),Jsonb(result),digest(packet),digest(result))).fetchone()
    _audit(conn,'specialist.run_completed',p,row['id'])
    return public_run(row)
