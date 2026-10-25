"""Generated-console normalization and bounded cross-capture candidate review, without model dispatch."""
from uuid import uuid5

from psycopg.types.json import Jsonb

from gabriel.identity.attack_patterns import FIELDS,normalized
from gabriel.identity.attack_pattern_runs import GAPS,run as review
from gabriel.identity.cases import timestamp
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier
from gabriel.identity.specialist_analysis import at,require,uid
from gabriel.identity.specialist_contracts import digest

VERSION='generated-browser-events-v1'
RAW_FIELDS=(FIELDS-{'evidence_id','evidence_digest','authorization'})|{'reported_authority'}


def document(raw,artifact,case_id):
    require(type(raw) is dict and set(raw)=={'version','as_of','missing_sources','events'} and raw['version']==VERSION,
        'unsupported_browser_event_snapshot')
    require(type(raw['events']) is list and 1<=len(raw['events'])<=128,'browser_event_count_limit')
    events=[]
    for original in raw['events']:
        require(type(original) is dict and set(original)==RAW_FIELDS,'invalid_browser_event_fields')
        row=dict(original)
        row['authorization']=row.pop('reported_authority')
        events.append(dict(row,evidence_id=str(artifact['id']),evidence_digest=artifact['digest']))
    value=dict(version='security-events-v1',case_id=str(case_id),as_of=raw['as_of'],missing_sources=raw['missing_sources'],events=events)
    normalized(value,case_id)
    return value


def admitted(service,conn,human,peer,context):
    p,lease,_=service._observer(conn,human,peer,context)
    grant,_=service._grant(conn,p,lease)
    if grant['contract_version']!='generated-console-v1': raise AccessDenied('browser_event_adapter_not_admitted')
    if conn.execute("SELECT 1 FROM gabriel_identity.browser_observations WHERE organization_id=%s AND lease_id=%s AND state='prepared'",
                    (p.organization_id,lease['id'])).fetchone(): raise AccessDenied('browser_capture_outcome_unresolved')
    return p,lease


def process(service,human,peer,context,observation_id):
    observation_id=identifier(observation_id)
    def bound(conn): return admitted(service,conn,human,peer,context)
    with connection(service._dsn) as conn:
        p,lease=bound(conn)
        target=service._observation(conn,p,observation_id)
        if target['lease_id']!=lease['id'] or target['state']!='captured': raise AccessDenied('browser_event_capture_required')
        target_receipt=service._receipt(conn,p,target)
        old=conn.execute('SELECT * FROM gabriel_identity.browser_event_snapshots WHERE organization_id=%s AND observation_id=%s',
            (p.organization_id,observation_id)).fetchone()
        if old and (old['case_id']!=lease['case_id'] or old['created_by']!=p.user_id or old['normalizer_version']!=VERSION
                or old['source_digest']!=digest(old['source_refs'])): raise AccessDenied('browser_event_snapshot_integrity_failed')
        if old:
            refs=old['source_refs'];omitted=old['omitted_observations'];received=old['capture_received_at']
        else:
            candidates=conn.execute('''SELECT o.* FROM gabriel_identity.browser_observations o
                JOIN gabriel_identity.browser_leases l ON (l.organization_id,l.id)=(o.organization_id,o.lease_id)
                JOIN gabriel_identity.browser_navigation_grants g ON (g.organization_id,g.lease_id)=(l.organization_id,l.id)
                JOIN gabriel_identity.browser_observation_receipts r ON (r.organization_id,r.observation_id)=(o.organization_id,o.id)
                WHERE o.organization_id=%s AND l.case_id=%s AND o.state='captured' AND g.contract_version='generated-console-v1'
                    AND (r.created_at,o.id)<=(%s,%s) ORDER BY r.created_at DESC,o.id DESC LIMIT 33''',
                (p.organization_id,lease['case_id'],target_receipt['created_at'],observation_id)).fetchall()
            if len(candidates)>32: raise AccessDenied('browser_event_source_limit_requires_narrower_case')
            refs=[dict(observation_id=str(item['id']),evidence_id=str(item['evidence_id']),digest=item['content_digest']) for item in candidates]
            omitted=0;received=target_receipt['created_at']
        require(type(refs) is list and 1<=len(refs)<=32,'invalid_browser_event_sources')
        for ref in refs:
            require(type(ref) is dict and set(ref)=={'observation_id','evidence_id','digest'},'invalid_browser_event_source')
            uid(ref['observation_id']);uid(ref['evidence_id'])
        values=[];verified_refs=[]
        for ref in refs:
            row=service._observation(conn,p,ref['observation_id'])
            if row['state']!='captured' or str(row['evidence_id'])!=ref['evidence_id'] or row['content_digest']!=ref['digest']:
                raise AccessDenied('browser_event_source_binding_mismatch')
            artifact=service._captured_artifact(conn,p,row,lease)
            if artifact['source_kind']=='model_generated_text': raise AccessDenied('model_answer_is_not_browser_event_source')
            raw_bytes=service._verify(conn,artifact)
            service._custody(conn,p,artifact,'accessed')
            try: raw=decode(raw_bytes.decode('utf-8'))
            except (ValueError,UnicodeError,RecursionError): raw=None
            if not isinstance(raw,dict) or raw.get('version')!=VERSION:
                if row['id']==observation_id or old: raise InvalidIdentityInput('unsupported_browser_event_snapshot')
                omitted+=1;continue
            values.append(document(raw,artifact,lease['case_id']));verified_refs.append(ref)
        require(values and any(ref['observation_id']==str(observation_id) for ref in verified_refs),'browser_event_target_missing')
        combined=dict(version='security-events-v1',case_id=str(lease['case_id']),as_of=max((value['as_of'] for value in values),key=at),
            missing_sources=sorted(set().union(*(set(value['missing_sources']) for value in values),GAPS if omitted else set())),
            events=[event for value in values for event in value['events']])
        normalized(combined,lease['case_id'])
        if old:
            if verified_refs!=old['source_refs']: raise AccessDenied('browser_event_snapshot_integrity_failed')
        else:
            conn.execute('''INSERT INTO gabriel_identity.browser_event_snapshots
                (organization_id,observation_id,case_id,created_by,normalizer_version,source_refs,source_digest,omitted_observations,capture_received_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (p.organization_id,observation_id,lease['case_id'],p.user_id,VERSION,Jsonb(verified_refs),digest(verified_refs),omitted,received))
            _audit(conn,'browser.event_snapshot_prepared',p,observation_id)
        case_id=lease['case_id'];parent_id=target['evidence_id']
    with connection(service._dsn) as conn: bound(conn)
    holder=service.acquire(human,case_id,uuid5(observation_id,VERSION),canonical(combined).decode('utf-8'),
        'Generated browser event normalization',approved=True,parent_id=parent_id,redaction_state='user_declared_redacted')
    result=review(service,human,case_id,uuid5(observation_id,VERSION+'/review'),holder['id'],_admission=bound)
    elapsed=(timestamp(result['created_at'])-received).total_seconds()
    return dict(review_id=result['id'],case_id=str(case_id),normalized_evidence_id=str(holder['id']),
        candidate_count=len(result['result']['findings']),families=sorted({item['family'] for item in result['result']['findings']}),
        source_count=len(verified_refs),omitted_observations=omitted,unique_event_count=result['result']['unique_event_count'],
        capture_to_review_ms=int(elapsed*1000) if elapsed>=0 else None,time_basis='server_capture_receipt_to_review',
        source_verified=False,quality_qualified=False,live_detection_accepted=False,model_cost_usd='0')
