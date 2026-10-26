"""Encrypted unreviewed answer receipts; recovery never sends another provider call."""
from uuid import uuid4

from gabriel.identity.evidence_store import EvidenceContent,MAX_BYTES,canonical
from gabriel.identity.model_budget import investigation,limits,reservation
from gabriel.identity.model_evaluation import digest,validate_run
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,_audit,connection,identifier

VERSION='encrypted-model-answer-v1'
LABEL='Unreviewed generated model answer'


def principal(worker,conn,token,*,write=False):
    return worker._answer_principal(conn,token,write=write)


def intent(worker,conn,p,reservation_id):
    row=conn.execute("""SELECT a.*,r.input_digest AS reserved_input,q.configuration_digest AS quoted_configuration,
        i.case_id AS investigated_case,c.claimed_by FROM gabriel_identity.model_answer_intents a
        JOIN gabriel_identity.model_reservations r ON (r.organization_id,r.id)=(a.organization_id,a.reservation_id)
        JOIN gabriel_identity.model_price_quotes q ON (q.organization_id,q.id)=(r.organization_id,r.quote_id)
        JOIN gabriel_identity.model_investigations i ON (i.organization_id,i.id)=(r.organization_id,r.investigation_id)
        JOIN gabriel_identity.model_dispatch_claims c ON (c.organization_id,c.reservation_id)=(a.organization_id,a.reservation_id)
        WHERE a.organization_id=%s AND a.reservation_id=%s""",(p.organization_id,identifier(reservation_id))).fetchone()
    if not row: raise AccessDenied('model_answer_not_staged')
    worker.cases._case(conn,p,row['case_id'])
    if (row['reserved_input']!=row['input_digest'] or row['quoted_configuration']!=row['configuration_digest']
            or row['investigated_case']!=row['case_id'] or row['claimed_by']!=row['created_by']):
        raise AccessDenied('model_answer_binding_invalid')
    return row


def verified(worker,conn,p,staged,row,*,ready=True):
    if (row['case_id']!=staged['case_id'] or row['ingestion_id']!=staged['ingestion_id']
            or row['parent_id']!=staged['normalized_evidence_id'] or row['acquired_by']!=staged['created_by']
            or row['source_label']!=LABEL or row['digest']!=staged['payload_digest']
            or row['source_kind']!='model_generated_text' or row['parser_version']!='model-json-v1'):
        raise AccessDenied('model_answer_evidence_binding_invalid')
    raw=worker.cases._verify(conn,row,ready=ready)
    payload=decode(raw)
    if (not isinstance(payload,dict) or set(payload)!={'version','result','local_manifest'}
            or payload['version']!=VERSION or digest(payload)!=staged['payload_digest']):
        raise AccessDenied('model_answer_payload_invalid')
    result=payload['result']
    if (not isinstance(result,dict) or result.get('input_sha256')!=staged['input_digest']
            or result.get('configuration_sha256')!=staged['configuration_digest']):
        raise AccessDenied('model_answer_result_binding_invalid')
    manifest=payload['local_manifest']
    if not isinstance(manifest,dict) or not isinstance(manifest.get('lineage'),dict):
        raise AccessDenied('model_answer_manifest_invalid')
    packet=dict(case_id='typed-assessment',input_sha256=staged['input_digest'],
                observations=[dict(id=ref) for ref in manifest['lineage']])
    validate_run(result,packet)
    worker._validate_actions(result['decision'])
    return raw,payload


def wrapped(staged,evidence_id,payload,*,historical):
    return EvidenceContent(dict(reservation_id=str(staged['reservation_id']),answer_evidence_id=str(evidence_id),
        provider_response_digest=staged['provider_response_digest'],result_persisted=True,
        historical=historical,review_status='unreviewed',coverage='partial',
        cost_reconciliation_required=True,quality_qualified=False,production_admission=False),
        canonical(dict(result=payload['result'],local_manifest=payload['local_manifest'])))


def get(worker,token,reservation_id):
    with connection(worker.cases._dsn) as conn:
        p=principal(worker,conn,token)
        staged=intent(worker,conn,p,reservation_id)
        receipt=conn.execute("""SELECT evidence_id FROM gabriel_identity.model_answer_receipts
            WHERE organization_id=%s AND reservation_id=%s""",(p.organization_id,staged['reservation_id'])).fetchone()
        if not receipt: raise AccessDenied('model_answer_not_completed')
        row=worker.cases._evidence(conn,p,receipt['evidence_id'])
        _,payload=verified(worker,conn,p,staged,row)
        worker._verify_sources(conn,p,staged['normalized_evidence_id'],dict(local_manifest=payload['local_manifest']))
        worker.cases._custody(conn,p,row,'accessed')
        _audit(conn,'model_answer.read',p,staged['reservation_id'])
        return wrapped(staged,row['id'],payload,historical=True)


def live(worker,conn,p,staged):
    held=reservation(conn,p,staged['reservation_id'])
    investigation(conn,p,held['investigation_id'],active=True)
    if not limits(conn,p.organization_id)['enabled']: raise AccessDenied('model_budget_paused')
    if held['outcome']=='not_sent': raise AccessDenied('model_answer_settlement_conflict')
    worker._scope(conn,p,staged['coordinator_run_id'],staged['case_id'],_exclude_ingestion=staged['ingestion_id'])


def recover(worker,token,reservation_id):
    # Recovery can publish a staged answer only while its original scope is live.
    # Completed receipts remain available as historical unreviewed evidence.
    with connection(worker.cases._dsn) as conn:
        p=principal(worker,conn,token,write=True)
        staged=intent(worker,conn,p,reservation_id)
        receipt=conn.execute("""SELECT evidence_id FROM gabriel_identity.model_answer_receipts
            WHERE organization_id=%s AND reservation_id=%s""",(p.organization_id,staged['reservation_id'])).fetchone()
        if receipt:
            row=worker.cases._evidence(conn,p,receipt['evidence_id'])
            _,payload=verified(worker,conn,p,staged,row)
            worker._verify_sources(conn,p,staged['normalized_evidence_id'],dict(local_manifest=payload['local_manifest']))
            worker.cases._custody(conn,p,row,'accessed')
            _audit(conn,'model_answer.replayed',p,staged['reservation_id'])
            return wrapped(staged,row['id'],payload,historical=True)
        live(worker,conn,p,staged)
        row=conn.execute("""SELECT * FROM gabriel_identity.evidence_objects
            WHERE organization_id=%s AND case_id=%s AND ingestion_id=%s""",
            (p.organization_id,staged['case_id'],staged['ingestion_id'])).fetchone()
        if not row: raise AccessDenied('model_answer_bytes_not_recoverable_no_resend')
        raw,payload=verified(worker,conn,p,staged,row,ready=False)
        worker._verify_sources(conn,p,staged['normalized_evidence_id'],dict(local_manifest=payload['local_manifest']))
    worker.cases._finish_acquisition(token,row['id'],raw)
    with connection(worker.cases._dsn) as conn:
        p=principal(worker,conn,token,write=True)
        staged=intent(worker,conn,p,reservation_id)
        live(worker,conn,p,staged)
        current=worker.cases._evidence(conn,p,row['id'])
        _,payload=verified(worker,conn,p,staged,current)
        worker._verify_sources(conn,p,staged['normalized_evidence_id'],dict(local_manifest=payload['local_manifest']))
        conn.execute("""INSERT INTO gabriel_identity.model_answer_receipts
            (organization_id,reservation_id,case_id,evidence_id,completed_by) VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (organization_id,reservation_id) DO NOTHING""",
            (p.organization_id,staged['reservation_id'],staged['case_id'],row['id'],p.user_id))
        _audit(conn,'model_answer.completed',p,staged['reservation_id'])
        return wrapped(staged,row['id'],payload,historical=False)


def persist(worker,token,run,evidence_id,held,prepared,result,reply,guard):
    payload=dict(version=VERSION,result=result,local_manifest=prepared['local_manifest'])
    raw=canonical(payload)
    if not 1<=len(raw)<=MAX_BYTES: raise AccessDenied('model_answer_storage_limit')
    with connection(worker.cases._dsn) as conn:
        p=principal(worker,conn,token,write=True)
        guard(conn,p)
        count=conn.execute('''SELECT count(*) AS n FROM gabriel_identity.model_answer_intents
            WHERE organization_id=%s AND case_id=%s''',(p.organization_id,run['case_id'])).fetchone()['n']
        if count>=128: raise AccessDenied('case_model_answer_limit')
        conn.execute("""INSERT INTO gabriel_identity.model_answer_intents
            (organization_id,reservation_id,case_id,coordinator_run_id,normalized_evidence_id,ingestion_id,created_by,
             input_digest,configuration_digest,payload_digest,provider_response_digest)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (p.organization_id,held['id'],run['case_id'],run['id'],identifier(evidence_id),uuid4(),p.user_id,
             held['input_digest'],result['configuration_sha256'],digest(payload),digest(reply)))
        staged=intent(worker,conn,p,held['id'])
        _audit(conn,'model_answer.staged',p,held['id'])
    worker.cases.acquire(token,run['case_id'],staged['ingestion_id'],raw.decode(),LABEL,
                         approved=True,parent_id=evidence_id,_model_generated=True)
    return recover(worker,token,held['id'])
