"""Receipt-bound browser AI triage; no raw page text or memory is sent to a provider."""
from hashlib import sha256
from uuid import uuid5

from gabriel.identity import coordinator,model_routes
from gabriel.identity.browser_text_review import RULES,candidate_passages
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest
from gabriel.identity.model_protocol import PROMPT_V2,decode
from gabriel.identity.model_worker import ModelWorker,configuration as worker_configuration
from gabriel.identity.service import AccessDenied,_audit,connection,identifier

VERSION='browser-candidate-ai-v1'
PROMPT=PROMPT_V2+'''
Browser signals are local lexical candidate reports, not authenticated events.
passage_count counts matched passages, never attack attempts or independent events.
The receipt time is collection time, not the underlying event time. No actor,
asset, event semantics, impact or independent corroboration is established.
Do not invent those facts. The scope is preliminary triage of these candidate
reports. Explain what additional evidence an analyst needs; no actions are allowed.
'''


def configuration(model):
    value=worker_configuration(model)
    return dict(value,version=VERSION,prompt_digest=sha256(PROMPT.encode()).hexdigest(),projection_version=VERSION,orchestration_version=coordinator.BROWSER_PLAN)


def require_model(model):
    if type(model) is not str or model not in model_routes.ROUTES:
        raise AccessDenied('browser_ai_model_not_supported')
    value=configuration(model)
    if digest(value) not in model_routes.PRODUCTION_CONFIGURATIONS:
        raise AccessDenied('browser_ai_configuration_not_production_admitted')
    return value


def project(content,observation_id,artifact,received):
    local=candidate_passages(content)
    counts={family:sum(row['family']==family for row in local['findings']) for family,_ in RULES}
    signals=[dict(id='o'+str(i),signal=family,passage_count=count)
        for i,(family,count) in enumerate(((f,n) for f,n in sorted(counts.items()) if n),1)]
    packet=dict(version=VERSION,signals=signals,observed_at=received.isoformat(),
        time_basis='server_capture_receipt_not_event_time',coverage='partial',source_authenticity='unverified',
        independent_corroboration='not_established',actions_authorized=False,
        gaps=['raw_context_excluded','identities_excluded','reviewed_memory_stays_local','event_semantics_unverified',
              'source_visibility_not_established'],omitted_matches=local['omitted_matches'])
    lineage={row['id']:dict(record_id=str(uuid5(observation_id,row['signal'])),evidence_id=str(artifact['id']),
        evidence_digest=artifact['digest']) for row in signals}
    return dict(packet=packet,local_manifest=dict(version=VERSION,lineage=lineage,
        observation_id=str(observation_id),wire_digest=digest(packet),identity_map={}))


class BrowserModelWorker(ModelWorker):
    def __init__(self,cases,vault,human,peer,context,observation_id):
        super().__init__(cases,vault)
        self._human_token,self._peer,self._context,self._observation_id=human,peer,dict(context),identifier(observation_id)

    def _configuration(self,model):
        return configuration(model)

    def _bound(self,conn):
        p,lease,_=self.cases._observer(conn,self._human_token,self._peer,self._context)
        if p.role not in {'owner','admin'} or not lease['scheduled_review_enabled'] or not lease['intake_enabled']:
            raise AccessDenied('browser_ai_owner_and_scheduled_consent_required')
        row=self.cases._observation(conn,p,self._observation_id)
        if row['lease_id']!=lease['id'] or row['state']!='captured':raise AccessDenied('browser_ai_capture_scope_mismatch')
        return p,lease,row

    def _scope(self,conn,p,run_id,case_id=None,*,_exclude_ingestion=None):
        current,lease,_=self._bound(conn)
        if current!=p:raise AccessDenied('browser_ai_original_operator_required')
        return super()._scope(conn,p,run_id,case_id or lease['case_id'],_exclude_ingestion=_exclude_ingestion)

    def _input(self,token,run_id,evidence_id,model):
        if token!=self._human_token:raise AccessDenied('browser_ai_original_operator_required')
        config=self._admission(model)
        with connection(self.cases._dsn) as conn:
            p,lease,observation=self._bound(conn)
            run,selected=self._scope(conn,p,run_id,lease['case_id'])
            expected={row['evidence_id']:row['digest'] for row in selected}
            row=self.cases._evidence(conn,p,evidence_id)
            if str(row['id']) not in expected:raise AccessDenied('browser_ai_input_not_in_plan')
            artifact=self.cases._captured_artifact(conn,p,observation,lease)
            content=self.cases._verify(conn,artifact).decode('utf-8')
            receipt=self.cases._receipt(conn,p,observation)
            prepared=project(content,self._observation_id,artifact,receipt['created_at'])
            if not prepared['packet']['signals']:raise AccessDenied('browser_ai_no_supported_signals')
            raw=self.cases._verify(conn,row)
            if raw!=canonical(dict(version=VERSION,prepared=prepared)) or row['parent_id']!=artifact['id']:
                raise AccessDenied('browser_ai_normalization_binding_mismatch')
            self._verify_sources(conn,p,identifier(evidence_id),prepared)
            body=dict(model=model,messages=[dict(role='system',content=PROMPT),
                dict(role='user',content=canonical(prepared['packet']).decode())],**config['parameters'])
            if len(canonical(body))>7000:raise AccessDenied('browser_ai_wire_limit')
            binding=digest([str(run['id']),str(row['id']),row['digest'],body])
            return config,run,prepared,body,binding


def account_completed(worker,human,reservation_id):
    """Count the full reserved ceiling as spent; this is never a billing attestation."""
    from gabriel.identity.model_budget import reservation
    with connection(worker.cases._dsn) as conn:
        p=worker.cases._admin(conn,human)
        held=reservation(conn,p,reservation_id)
        receipt=conn.execute('''SELECT a.payload_digest FROM gabriel_identity.model_answer_receipts r
            JOIN gabriel_identity.model_answer_intents a USING(organization_id,reservation_id)
            WHERE r.organization_id=%s AND r.reservation_id=%s''',(p.organization_id,held['id'])).fetchone()
        if not receipt:raise AccessDenied('browser_ai_completed_receipt_required')
        if held['outcome'] is None:
            conn.execute('''INSERT INTO gabriel_identity.model_settlements
                (organization_id,reservation_id,attested_by,outcome,actual_microusd,receipt_digest)
                VALUES (%s,%s,%s,'completed_upper_bound',%s,%s)
                ON CONFLICT (organization_id,reservation_id) DO NOTHING''',
                (p.organization_id,held['id'],p.user_id,held['reserved_microusd'],digest([VERSION,str(held['id']),receipt['payload_digest']])))
            _audit(conn,'browser_ai.reserved_ceiling_accounted',p,held['id'])


def result(answer):
    payload=decode(answer.reveal().decode())
    return dict(state='historical_model_answer' if answer.metadata['historical'] else 'model_answer_requires_review',
        historical=answer.metadata['historical'],model_used=True,disposition=payload['result']['decision']['disposition'],
        answer_evidence_id=answer.metadata['answer_evidence_id'],reservation_id=answer.metadata['reservation_id'],
        quality_qualified=False,incident_confirmed=False,review_status='unreviewed',
        cost_accounting='reserved_upper_bound_not_verified_billing')


def process(service,vault,human,peer,context,observation_id,model):
    worker=BrowserModelWorker(service,vault,human,peer,context,observation_id)
    observation_id=identifier(observation_id)
    request_id=uuid5(observation_id,VERSION+'/'+model)
    with connection(service._dsn) as conn:
        p,lease,row=worker._bound(conn)
        old=conn.execute('''SELECT r.id,r.input_digest,c.id AS claim_id FROM gabriel_identity.model_reservations r
            JOIN gabriel_identity.model_investigations i ON (i.organization_id,i.id)=(r.organization_id,r.investigation_id)
            LEFT JOIN gabriel_identity.model_dispatch_claims c ON (c.organization_id,c.reservation_id)=(r.organization_id,r.id)
            WHERE i.organization_id=%s AND i.request_id=%s AND r.request_id=%s''',(p.organization_id,request_id,request_id)).fetchone()
        if old and old['claim_id']:
            completed=conn.execute('SELECT 1 FROM gabriel_identity.model_answer_receipts WHERE organization_id=%s AND reservation_id=%s',
                (p.organization_id,old['id'])).fetchone()
            if not completed:raise AccessDenied('browser_ai_outcome_unresolved_no_resend')
        artifact=service._captured_artifact(conn,p,row,lease)
        prepared=project(service._verify(conn,artifact).decode(),observation_id,artifact,service._receipt(conn,p,row)['created_at'])
        case_id=lease['case_id'];parent_id=artifact['id']
    if old and old['claim_id']:
        answer=worker.get_answer(human,old['id']);account_completed(worker,human,old['id'])
        return result(answer)
    require_model(model)
    if not prepared['packet']['signals']:
        return dict(state='abstained_no_supported_signals',model_used=False,quality_qualified=False,incident_confirmed=False)
    holder=service.acquire(human,case_id,uuid5(observation_id,VERSION),canonical(dict(version=VERSION,prepared=prepared)).decode(),
        'Browser minimized AI input',approved=True,parent_id=parent_id,redaction_state='user_declared_redacted')
    plan=service.begin_coordinator(human,case_id,request_id,input_evidence_id=holder['id'],_browser_model=True)
    if plan['completed_steps']<plan['max_steps']:service.complete_coordinator(human,plan['id'])
    try:
        held=worker.reserve(human,plan['id'],holder['id'],request_id,model)
    except AccessDenied as error:
        if str(error)!='model_concurrency_or_unknown_limit':raise
        return dict(state='deferred_budget_slot',model_used=False,dispatch_performed=False,
            quality_qualified=False,incident_confirmed=False)
    answer=worker.dispatch(human,plan['id'],holder['id'],held['reservation_id'])
    account_completed(worker,human,held['reservation_id'])
    return result(answer)
