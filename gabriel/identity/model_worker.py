"""Admission-bound single-attempt worker kernel; no route is production admitted.

Validated results use encrypted evidence receipts. A crash after a claim never
authorizes resend; reservations stay held for explicit operator reconciliation.
"""
import hmac
import time
from hashlib import sha256

from gabriel.identity import coordinator,model_routes
from gabriel.identity.cases import CaseService,admit_epoch
from gabriel.identity.evidence_store import EvidenceContent,canonical
from gabriel.identity.model_budget import ModelBudgetService,investigation,reservation
from gabriel.identity.model_evaluation import digest,validate_run
from gabriel.identity.model_input import prepare
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.model_protocol import PROMPT_V2 as PROMPT,ProbeError,budget_check,decode,money
from gabriel.identity.service import AccessDenied,_audit,connection,identifier
from gabriel.identity.vault import ProviderVault
from gabriel.identity.provider_onboarding import CustomerProviders,require_checked,dispatch_credit

QUESTION='Assess only the supplied partial typed observations. Disclose missing context and source uncertainty.'


def configuration(model):
    return dict(version='restricted-model-worker-v3',model=model,
                route_registry_version=model_routes.VERSION,expected_provider=model_routes.ROUTES[model][0],
                prompt_digest=sha256(PROMPT.encode()).hexdigest(),
                projection_version='typed-telemetry-minimization-v1',
                parameters=model_routes.parameters(model))


class ModelWorker:
    def __init__(self,cases,vault):
        if not isinstance(cases,CaseService) or not isinstance(vault,ProviderVault) or cases._dsn!=vault._dsn:
            raise ValueError('same_backend_case_service_and_vault_required')
        self.cases,self.vault=cases,vault
        self.budget=ModelBudgetService(cases._dsn)

    def __repr__(self): return '<ModelWorker private_backend>'

    def _admission(self,model):
        config=configuration(model)
        if digest(config) not in model_routes.PRODUCTION_CONFIGURATIONS:
            raise AccessDenied('model_configuration_not_production_admitted')
        return config

    def _scope(self,conn,p,run_id,case_id=None,*,_exclude_ingestion=None):
        run=coordinator.load(conn,p,run_id)
        selected=coordinator.active(self.cases,conn,p,run,_exclude_ingestion=_exclude_ingestion)
        if case_id is not None and run['case_id']!=case_id:
            raise AccessDenied('model_worker_case_mismatch')
        if coordinator.snapshot(conn,run)['completed_steps']!=run['max_steps']:
            raise AccessDenied('complete_local_plan_required')
        admit_epoch(conn,p.organization_id,self.cases.store.keys)
        return run,selected

    def _verify_sources(self,conn,p,evidence_id,prepared):
        ids={evidence_id}|{identifier(ref['evidence_id']) for ref in prepared['local_manifest']['lineage'].values()}
        for source_id in sorted(ids,key=str):
            source=self.cases._evidence(conn,p,source_id)
            derived=conn.execute('''SELECT 1 FROM gabriel_identity.model_answer_intents
                WHERE organization_id=%s AND ingestion_id=%s''',(p.organization_id,source['ingestion_id'])).fetchone()
            if derived or source['source_kind']=='model_generated_text':
                raise AccessDenied('unreviewed_model_answer_is_not_source_evidence')
            self.cases._verify(conn,source)
            self.cases._custody(conn,p,source,'accessed')
        _audit(conn,'model_worker.sources_verified',p,evidence_id)

    def _input(self,token,run_id,evidence_id,model):
        config=self._admission(model)
        evidence_id=identifier(evidence_id)
        with connection(self.cases._dsn) as conn:
            p=self.cases._admin(conn,token)
            run,selected=self._scope(conn,p,run_id)
            expected={row['evidence_id']:row['digest'] for row in selected}
            if str(evidence_id) not in expected: raise AccessDenied('model_input_not_in_plan')
            row=self.cases._evidence(conn,p,evidence_id)
            document=decode(self.cases._verify(conn,row).decode('utf-8'))
            self.cases._custody(conn,p,row,'accessed')
            _audit(conn,'model_worker.input_prepared',p,row['id'])
            if not isinstance(document,dict) or set(document)!={'version','records'} or document['version']!='normalized-telemetry-v1':
                raise AccessDenied('normalized_telemetry_required')
            key=hmac.digest(self.cases.store.keys._key(self.cases.store.keys.active),b'gabriel-model-projection-v1','sha256')
            prepared=prepare(document['records'],organization_id=str(p.organization_id),case_id=str(run['case_id']),pseudonym_key=key,max_wire_bytes=4096)
            for ref in prepared['local_manifest']['lineage'].values():
                if expected.get(ref['evidence_id'])!=ref['evidence_digest']:
                    raise AccessDenied('normalized_source_binding_mismatch')
            self._verify_sources(conn,p,evidence_id,prepared)
            body=dict(model=model,messages=[dict(role='system',content=PROMPT),
                      dict(role='user',content=canonical(dict(question=QUESTION,observations=prepared['packet'])).decode())],**config['parameters'])
            if len(canonical(body))>7000: raise AccessDenied('model_input_requires_narrower_scope')
            binding=digest([str(run['id']),str(evidence_id),expected[str(evidence_id)],body])
            return config,run,prepared,body,binding

    def reserve(self,token,run_id,evidence_id,request_id,model):
        config,run,_,_,binding=self._input(token,run_id,evidence_id,model)
        job=self.budget.begin(token,run['case_id'],request_id)
        with connection(self.cases._dsn) as conn:
            p=self.cases._admin(conn,token)
            old=conn.execute('''SELECT quote_id FROM gabriel_identity.model_reservations
                WHERE organization_id=%s AND investigation_id=%s AND request_id=%s''',
                (p.organization_id,job['id'],identifier(request_id))).fetchone()
        quote_id=old['quote_id'] if old else self.budget.quote(token,'openrouter',model,digest(config),500000,3000000)['id']
        row=self.budget.reserve(token,job['id'],request_id,quote_id,binding,max_input_tokens=8000,max_output_tokens=768)
        return dict(reservation_id=str(row['id']),investigation_id=str(job['id']),reserved_microusd=row['reserved_microusd'],
                    production_admission=False,dispatch_performed=False)

    def dispatch(self,token,run_id,evidence_id,reservation_id):
        with connection(self.cases._dsn) as conn:
            p=self.cases._admin(conn,token)
            held=reservation(conn,p,reservation_id)
            if held['claim_id']: raise AccessDenied('model_worker_already_claimed_no_resend')
            quote=conn.execute('''SELECT * FROM gabriel_identity.model_price_quotes WHERE organization_id=%s AND id=%s''',
                               (p.organization_id,held['quote_id'])).fetchone()
            if quote['provider']!='openrouter': raise AccessDenied('model_worker_provider_denied')
        config,run,prepared,body,binding=self._input(token,run_id,evidence_id,quote['model'])
        if (held['input_digest']!=binding or quote['configuration_digest']!=digest(config)
                or held['max_input_tokens']!=8000 or held['max_output_tokens']!=768
                or held['reserved_microusd']!=6304
                or quote['input_microusd_per_million']!=500000
                or quote['output_microusd_per_million']!=3000000):
            raise AccessDenied('model_worker_reservation_binding_mismatch')
        credential,credential_binding=CustomerProviders(self.vault).resolve(token,'openrouter')
        client=OpenRouterTransport(credential)
        model_routes.eligible(client.request('GET','/api/v1/endpoints/zdr'),quote['model'])
        budget_check(client.request('GET','/api/v1/key').get('data'))
        dispatch_credit(client.request('GET','/api/v1/credits'),held['reserved_microusd'])
        def guard(conn,p):
            require_checked(conn,p,'openrouter',expected=credential_binding)
            job=investigation(conn,p,held['investigation_id'],active=True)
            self._scope(conn,p,run_id,job['case_id'])
            self._verify_sources(conn,p,identifier(evidence_id),prepared)
        claimed=self.budget.claim(token,reservation_id,_guard=guard)
        if not claimed['new_claim']: raise AccessDenied('model_worker_already_claimed_no_resend')
        started=time.monotonic()
        reply=client.request('POST','/api/v1/chat/completions',body)
        elapsed=int((time.monotonic()-started)*1000)
        if not isinstance(reply,dict) or reply.get('model')!=quote['model'] or reply.get('provider')!=model_routes.ROUTES[quote['model']][0]:
            raise ProbeError('unexpected_model_or_provider')
        usage=reply.get('usage',{})
        if (type(usage.get('prompt_tokens')) is not int or not 0<=usage['prompt_tokens']<=8000
                or type(usage.get('completion_tokens')) is not int or not 0<=usage['completion_tokens']<=768
                or money(usage.get('cost'))*1000000>held['reserved_microusd']):
            raise ProbeError('worker_usage_or_cost_unresolved')
        choices=reply.get('choices')
        if not isinstance(choices,list) or len(choices)!=1 or choices[0].get('finish_reason')!='stop':
            raise ProbeError('incomplete_provider_answer')
        message=choices[0].get('message',{})
        if message.get('tool_calls') or not isinstance(message.get('content'),str): raise ProbeError('invalid_provider_answer')
        decision=decode(message['content'])
        packet=dict(case_id='typed-assessment',input_sha256=binding,
                    observations=[dict(id=ref) for ref in prepared['local_manifest']['lineage']])
        result=dict(case_id=packet['case_id'],input_sha256=binding,configuration_sha256=digest(config),origin='live_provider',
                    generation_id=reply.get('id'),latency_ms=elapsed,cost_usd=float(money(usage['cost'])),
                    input_tokens=usage['prompt_tokens'],output_tokens=usage['completion_tokens'],decision=decision)
        validate_run(result,packet)
        if decision['requested_actions']: raise ProbeError('external_action_requested')
        with connection(self.cases._dsn) as conn:
            p=self.cases._admin(conn,token)
            guard(conn,p)
        from gabriel.identity.model_answers import persist
        return persist(self,token,run,evidence_id,held,prepared,result,reply,guard)

    def get_answer(self,token,reservation_id):
        from gabriel.identity.model_answers import get
        return get(self,token,reservation_id)

    def recover_answer(self,token,reservation_id):
        from gabriel.identity.model_answers import recover
        return recover(self,token,reservation_id)
