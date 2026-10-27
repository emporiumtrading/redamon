"""Bounded typed historical references; no free-text memory is sent to models."""
from gabriel.identity import memory
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,identifier
from gabriel.identity.specialist_analysis import ROLE_TYPES,at,validate_document
from gabriel.identity.specialist_analysis_runs import verified_input

VERSION='reviewed-typed-reference-v1'
MAX_RECORDS=4
MAX_FACTS=6


def build(service,conn,p,case,document,role,*,snapshot=None):
    if case['purpose']=='performance_test':
        if snapshot:raise AccessDenied('performance_test_memory_excluded')
        return dict(result=dict(version=VERSION,state='disabled_for_performance_test',historical_assertions=[],
            source_authenticity='unverified',independent_corroboration=False,grants_authority=False,
            model_training_performed=False,contents_exported=False),records=[],lineage={})
    epoch=memory._epoch(conn,p)
    now=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
    if snapshot is None:
        candidates=conn.execute('''SELECT id FROM gabriel_identity.memory_records
            WHERE organization_id=%s AND epoch=%s AND (scope='organization' OR case_id=%s)
            ORDER BY created_at DESC,id DESC LIMIT 129''',(p.organization_id,epoch,case['id'])).fetchall()
        if len(candidates)>128:raise AccessDenied('memory_retrieval_limit')
        candidates=[str(r['id']) for r in candidates]
    else:
        if type(snapshot) is not list or len(snapshot)>MAX_RECORDS or any(type(v) is not str for v in snapshot) or len(set(snapshot))!=len(snapshot):
            raise AccessDenied('invalid_memory_snapshot')
        candidates=[str(identifier(r)) for r in snapshot]
    current_entities=sorted({f['entity_id'] for f in document['facts']
        if f['entity_id'] and (f['type'] in ROLE_TYPES[role] or f['type']=='coverage')})
    aliases={value:'e'+str(i+1) for i,value in enumerate(current_entities)}
    assertions=[];records=[];lineage={};seen=set()
    for mid in candidates:
        row=memory._record(conn,p,mid)
        eligible=(row['kind']=='fact' and row['sensitivity']!='restricted' and (row['scope']=='organization' or row['case_id']==case['id'])
            and memory._status(service,conn,p,row,epoch,now)=='eligible_pending_content_check')
        if not eligible:
            if snapshot is not None:raise AccessDenied('reviewed_memory_no_longer_eligible')
            continue
        raw=memory._read_source(service,conn,p,row)
        try:
            historical=validate_document(decode(raw),row['case_id'])
        except (InvalidIdentityInput,ValueError,TypeError,KeyError,UnicodeError,RecursionError):
            if snapshot is not None:raise AccessDenied('reviewed_memory_schema_changed') from None
            continue
        source_case=service._case(conn,p,row['case_id'])
        _,historical,_=verified_input(service,conn,p,source_case,row['evidence_id'])
        selected=[f for f in historical['facts'] if f['type'] in ROLE_TYPES[role]
            and f['entity_id'] in aliases and at(f['event_time'])<=at(document['as_of'])]
        before=len(assertions)
        for fact in selected:
            signature=canonical([fact['evidence_id'],fact['evidence_digest'],fact['entity_id'],fact['type'],fact['event_time'],fact['data']])
            if signature in seen:continue
            if len(assertions)>=MAX_FACTS:break
            seen.add(signature);ref='h'+str(len(assertions)+1)
            assertions.append(dict(id=ref,type=fact['type'],event_time=fact['event_time'],
                entity=aliases[fact['entity_id']],data=fact['data']))
            lineage[ref]=dict(record_id=fact['id'],evidence_id=fact['evidence_id'],
                evidence_digest=fact['evidence_digest'],historical_reviewed_memory=True)
        if len(assertions)>before:records.append(str(row['id']))
        elif snapshot is not None:raise AccessDenied('reviewed_memory_binding_changed')
        if len(records)>=MAX_RECORDS or len(assertions)>=MAX_FACTS:break
    if snapshot is not None and records!=snapshot:raise AccessDenied('reviewed_memory_binding_changed')
    # Use the completion time too; an expiring reference cannot survive a slow read.
    cutoff=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
    for mid in records:
        row=memory._record(conn,p,mid)
        if memory._status(service,conn,p,row,epoch,cutoff)!='eligible_pending_content_check':
            raise AccessDenied('reviewed_memory_no_longer_eligible')
    return dict(result=dict(version=VERSION,state='historical_references' if assertions else 'no_supported_references',
        historical_assertions=assertions,coverage='bounded_partial_references',source_authenticity='unverified',independent_corroboration=False,
        entity_binding='matching_supplied_identifier_unverified',grants_authority=False,
        model_training_performed=False,contents_exported=bool(assertions),free_text_exported=False),
        records=records,lineage=lineage)


def verify(service,conn,p,case,document,role,tool_result):
    private=tool_result.get('_reviewed_memory')
    if type(private) is not dict or set(private)!={'records','lineage'}:
        raise AccessDenied('reviewed_memory_snapshot_required')
    current=build(service,conn,p,case,document,role,snapshot=private['records'])
    if current['result']!=tool_result['result'] or current['lineage']!=private['lineage']:
        raise AccessDenied('reviewed_memory_binding_changed')
