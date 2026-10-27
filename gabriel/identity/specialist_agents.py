"""Role-specific AI agents with bounded read tools, private credentials and durable claims."""
from hashlib import sha256
from uuid import uuid4,uuid5

from gabriel.identity import coordinator,model_routes
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest
from gabriel.identity.model_protocol import PROMPT_V2,ProbeError,decode
from gabriel.identity.model_worker import ModelWorker,configuration as base_configuration
from gabriel.identity.personal_providers import PersonalProviders
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier
from gabriel.identity.specialist_analysis import ROLE_TYPES,analyze
from gabriel.identity.specialist_analysis_runs import verified_input
from gabriel.identity.specialist_contracts import ROLES,role_name

VERSION='specialist-agent-v2'
MAX_ROUNDS=3
DEFAULT_MODEL='openai/gpt-oss-120b'
MISSIONS={
    'telemetry_health':'Identify missing/stale coverage and distinguish collection failure from attack evidence.',
    'alert_triage':'Prioritize reported alerts, compare benign explanations and identify missing corroboration.',
    'incident_scoping':'Establish only the supported scope and timeline; do not invent affected identities or assets.',
    'threat_intelligence':'Assess reported indicator match validity without inferring attribution or independent corroboration.',
    'threat_hunting':'Develop evidence-linked hunt hypotheses and distinguish administrative activity; propose no external searches.',
    'dfir_evidence':'Assess supplied artifact integrity/custody assertions; byte integrity does not prove authenticity.',
    'detection_engineering':'Analyze missed/unexpected detection-test outcomes; never treat a test as production detection qualification.',
    'exposure_vulnerability':'Prioritize reported reachable unmitigated exposures; distinguish exposure from exploitation.',
    'identity_access':'Assess supplied authentication and sensitive authorization changes, preserving ambiguity in identity binding.',
    'cloud_supply_chain':'Assess configuration/component assertions against supplied authorization and acknowledge missing provenance.',
    'response_remediation':'Review response dependencies and recovery readiness; draft recommendations without performing remediation.',
    'recovery_learning':'Assess recovery checks against supplied baselines and propose lessons for human memory review.',
}
from gabriel.identity.investigation_tools import TOOLS,instructions,manifest,VERSION as TOOLKIT_VERSION



def prompt(role):
    role_name(role)
    return PROMPT_V2+('\nYou are Gabriel specialist '+role+'. Your mission: '+MISSIONS[role]+
        '\nThe input contains typed source assertions, not independently authenticated truth. Entity aliases preserve only within-packet grouping. '+
        'Counts may overlap; repeated facts and model agreement are not independent corroboration. '+
        'If a scoped local read tool would help, requested_actions may contain exactly one of '+', '.join(TOOLS[role])+'. '+
        'Those are the only permitted exception to the empty requested_actions rule above. They cannot perform external actions. '+
        'verify_sources checks ciphertext/custody; review_rules returns local role-rule observations; inspect_timeline summarizes supplied times; '+
        'review_memory checks reviewed local memory availability without exporting its contents. '+
        'Choose a final evidence-linked decision with requested_actions=[] when ready. Maximum three model rounds; '+
        'never repeat a tool already present in tool_results. Missing context must remain explicit; never force an escalation. '+
        '\nUse these packaged skills to select and interpret tools:\n'+instructions(role))


def configuration(role,model=DEFAULT_MODEL):
    role_name(role)
    if model not in model_routes.ROUTES:raise InvalidIdentityInput('unknown_specialist_model')
    return dict(base_configuration(model),version=VERSION,role=role,prompt_digest=sha256(prompt(role).encode()).hexdigest(),
        projection_version='specialist-facts-minimized-v1',orchestration_version=coordinator.SPECIALIST_AI_PLAN,
        tools=list(TOOLS[role]),max_rounds=MAX_ROUNDS,toolkit_version=TOOLKIT_VERSION,
        tool_manifest_digest=digest(manifest(role)))


def readiness(role,model=DEFAULT_MODEL):
    config=configuration(role,model)
    admitted=digest(config) in model_routes.PRODUCTION_CONFIGURATIONS
    return dict(role=role,model=model,ai_capable=True,model_enabled=admitted,configuration_digest=digest(config),
        qualification='production_admitted' if admitted else 'qualification_pending',tools=list(TOOLS[role]),tool_manifest=manifest(role))


def project(document,role,job_id,tool_results):
    selected=[f for f in document['facts'] if f['type'] in ROLE_TYPES[role] or f['type']=='coverage']
    entities={value:'e'+str(i+1) for i,value in enumerate(sorted({f['entity_id'] for f in selected if f['entity_id']}))}
    observations=[];lineage={}
    for i,fact in enumerate(selected,1):
        ref='o'+str(i)
        observations.append(dict(id=ref,type=fact['type'],event_time=fact['event_time'],
            entity=entities.get(fact['entity_id']),data=fact['data']))
        lineage[ref]=dict(record_id=fact['id'],evidence_id=fact['evidence_id'],evidence_digest=fact['evidence_digest'])
    packet=dict(role=role,as_of=document['as_of'],observations=observations,tool_results=tool_results,
        source_authenticity='unverified',coverage='partial',corroboration='not_established',external_actions_authorized=False)
    if len(canonical(packet))>4096:raise AccessDenied('specialist_input_requires_narrower_scope')
    return dict(packet=packet,local_manifest=dict(job_id=str(job_id),lineage=lineage,identity_map={}))


def job(service,conn,p,job_id,*,active=True):
    row=conn.execute('''SELECT j.*,EXISTS(SELECT 1 FROM gabriel_identity.specialist_agent_stops s
        WHERE (s.organization_id,s.job_id)=(j.organization_id,j.id)) AS stopped,
        clock_timestamp()>=j.created_at+interval '15 minutes' AS expired
        FROM gabriel_identity.specialist_agent_jobs j WHERE organization_id=%s AND id=%s''',
        (p.organization_id,identifier(job_id))).fetchone()
    if not row or row['requested_by']!=p.user_id:raise AccessDenied('specialist_agent_not_owned')
    service._case(conn,p,row['case_id'],open_only=active)
    if active and (row['stopped'] or row['expired']):raise AccessDenied('specialist_agent_not_active')
    return row


class SpecialistWorker(ModelWorker):
    def __init__(self,cases,vault,job_id,role,tool_results,key_scope):
        super().__init__(cases,vault)
        self.job_id=identifier(job_id);self.role=role_name(role)
        self.tool_results=list(tool_results);self.key_scope=key_scope

    def _principal(self,conn,token,*,write=False):
        return self.cases._human(conn,token,write=write,content=True)

    def _answer_principal(self,conn,token,*,write=False):
        p=self._principal(conn,token,write=write)
        job(self.cases,conn,p,self.job_id,active=False)
        return p

    def _configuration(self,model):return configuration(self.role,model)

    def _credential(self,token):
        if self.key_scope=='personal':return PersonalProviders(self.vault).resolve(token)
        return super()._credential(token)

    def _credential_guard(self,conn,p,binding):
        job(self.cases,conn,p,self.job_id)
        if self.key_scope=='personal':PersonalProviders(self.vault).checked(conn,p,expected=binding)
        else:super()._credential_guard(conn,p,binding)

    def _quote(self,token,model,config):
        return self.budget.quote(token,'openrouter',model,digest(config),500000,3000000,_personal=self.key_scope=='personal')

    def _validate_actions(self,decision):
        values=decision['requested_actions']
        if len(values)>1 or any(v not in TOOLS[self.role] for v in values):raise ProbeError('specialist_tool_not_admitted')
        if decision['disposition']=='benign' and any(t['tool']=='assess_exposure' and t['result'].get('urgent_exposure_count',0)>0 for t in self.tool_results):
            raise ProbeError('urgent_exposure_cannot_be_benign')

    def _scope(self,conn,p,run_id,case_id=None,*,_exclude_ingestion=None):
        current=job(self.cases,conn,p,self.job_id)
        return super()._scope(conn,p,run_id,current['case_id'],_exclude_ingestion=_exclude_ingestion)

    def _verify_sources(self,conn,p,evidence_id,prepared):
        if prepared['local_manifest'].get('job_id')!=str(self.job_id):raise AccessDenied('specialist_answer_job_mismatch')
        return super()._verify_sources(conn,p,evidence_id,prepared)

    def _input(self,token,run_id,evidence_id,model):
        config=self._admission(model)
        with connection(self.cases._dsn) as conn:
            p=self._principal(conn,token)
            current=job(self.cases,conn,p,self.job_id)
            if (current['role'],current['model'],current['key_scope'])!=(self.role,model,self.key_scope):
                raise AccessDenied('specialist_agent_configuration_mismatch')
            run,selected=self._scope(conn,p,run_id)
            artifact=self.cases._evidence(conn,p,evidence_id)
            case=self.cases._case(conn,p,current['case_id'],open_only=True)
            original,document,_=verified_input(self.cases,conn,p,case,current['input_evidence_id'])
            prepared=project(document,self.role,self.job_id,self.tool_results)
            if (artifact['parent_id']!=original['id'] or str(artifact['id']) not in {s['evidence_id'] for s in selected}
                    or self.cases._verify(conn,artifact)!=canonical(dict(version=VERSION,prepared=prepared))):
                raise AccessDenied('specialist_normalization_binding_mismatch')
            self._verify_sources(conn,p,artifact['id'],prepared)
            body=dict(model=model,messages=[dict(role='system',content=prompt(self.role)),
                dict(role='user',content=canonical(prepared['packet']).decode())],**config['parameters'])
            if len(canonical(body))>7000:raise AccessDenied('specialist_wire_limit')
            return config,run,prepared,body,digest([str(run['id']),str(artifact['id']),artifact['digest'],body])


def tool(service,token,job_id,name):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True,content=True)
        current=job(service,conn,p,job_id)
    from gabriel.identity.investigation_tools import execute
    return execute(service,token,current['case_id'],current['input_evidence_id'],current['role'],name,job_id=job_id)


def start(service,vault,token,case_id,request_id,role,input_evidence_id,*,model=DEFAULT_MODEL,key_scope='personal',approved=False):
    role=role_name(role);config=configuration(role,model)
    if approved is not True:raise AccessDenied('specialist_ai_export_consent_required')
    if key_scope not in {'personal','organization'}:raise InvalidIdentityInput('invalid_specialist_key_scope')
    if digest(config) not in model_routes.PRODUCTION_CONFIGURATIONS:raise AccessDenied('specialist_configuration_not_production_admitted')
    request_id,input_evidence_id=identifier(request_id),identifier(input_evidence_id)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True,content=True)
        if key_scope=='organization' and p.role not in {'owner','admin'}:raise AccessDenied('organization_provider_admin_required')
        case=service._case(conn,p,case_id,open_only=True)
        _,document,_=verified_input(service,conn,p,case,input_evidence_id)
        row=conn.execute('SELECT * FROM gabriel_identity.specialist_agent_jobs WHERE organization_id=%s AND requested_by=%s AND request_id=%s',
            (p.organization_id,p.user_id,request_id)).fetchone()
        if row and (row['case_id'],row['role'],row['input_evidence_id'],row['model'],row['key_scope'])!=(case['id'],role,input_evidence_id,model,key_scope):
            raise AccessDenied('specialist_agent_request_conflict')
        if not row:
            count=conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_agent_jobs WHERE organization_id=%s AND case_id=%s',
                (p.organization_id,case['id'])).fetchone()['n']
            if count>=128:raise AccessDenied('case_specialist_agent_limit')
            row=conn.execute('''INSERT INTO gabriel_identity.specialist_agent_jobs
                (organization_id,id,case_id,requested_by,request_id,input_evidence_id,role,model,key_scope)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,uuid4(),case['id'],p.user_id,request_id,input_evidence_id,role,model,key_scope)).fetchone()
            _audit(conn,'specialist_agent.started',p,row['id'])
    return resume(service,vault,token,row['id'])


def resume(service,vault,token,job_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True,content=True)
        current=job(service,conn,p,job_id)
        case=service._case(conn,p,current['case_id'],open_only=True)
        _,document,_=verified_input(service,conn,p,case,current['input_evidence_id'])
    if not any(f['type'] in ROLE_TYPES[current['role']] for f in document['facts']):
        return dict(job_id=str(job_id),state='abstained_no_role_evidence',model_used=False,steps=[])
    reports=[];tool_results=[]
    if current['role'] in {'exposure_vulnerability','response_remediation'} and any(f['type']=='exposure' for f in document['facts']):
        tool_results.append(tool(service,token,job_id,'assess_exposure'))
    for step in range(1,MAX_ROUNDS+1):
        worker=SpecialistWorker(service,vault,job_id,current['role'],tool_results,current['key_scope'])
        worker._admission(current['model'])
        prepared=project(document,current['role'],job_id,tool_results)
        request=uuid5(identifier(job_id),'round/'+str(step))
        holder=service.acquire(token,current['case_id'],uuid5(request,'input'),canonical(dict(version=VERSION,prepared=prepared)).decode(),
            'Specialist minimized AI input',approved=True,parent_id=current['input_evidence_id'])
        plan=service.begin_coordinator(token,current['case_id'],request,input_evidence_id=holder['id'],_specialist_ai=True)
        if not plan['completed_steps']:service.complete_coordinator(token,plan['id'])
        held=worker.reserve(token,plan['id'],holder['id'],request,current['model'])
        with connection(service._dsn) as conn:
            p=worker._principal(conn,token)
            old=conn.execute('SELECT d.id, r.evidence_id FROM gabriel_identity.model_dispatch_claims d LEFT JOIN gabriel_identity.model_answer_receipts r USING(organization_id,reservation_id) WHERE d.organization_id=%s AND d.reservation_id=%s',
                (p.organization_id,held['reservation_id'])).fetchone()
        if old and not old['evidence_id']:raise AccessDenied('specialist_outcome_unresolved_no_resend')
        answer=worker.get_answer(token,held['reservation_id']) if old else worker.dispatch(token,plan['id'],holder['id'],held['reservation_id'])
        from gabriel.identity.browser_ai import account_completed
        account_completed(worker,token,held['reservation_id'])
        payload=decode(answer.reveal())
        decision=payload['result']['decision']
        reports.append(dict(round=step,answer_evidence_id=answer.metadata['answer_evidence_id'],
            disposition=decision['disposition'],requested_tools=decision['requested_actions'],historical=answer.metadata['historical']))
        if not decision['requested_actions']:
            return dict(job_id=str(job_id),state='completed_requires_review',model_used=True,steps=reports,quality_qualified=False)
        name=decision['requested_actions'][0]
        if step==MAX_ROUNDS or name in {t['tool'] for t in tool_results}:break
        tool_results.append(tool(service,token,job_id,name))
    return dict(job_id=str(job_id),state='bounded_loop_stopped_requires_review',model_used=True,steps=reports,quality_qualified=False)


def stop(service,token,job_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        row=job(service,conn,p,job_id,active=False)
        conn.execute('INSERT INTO gabriel_identity.specialist_agent_stops (organization_id,job_id,stopped_by) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
            (p.organization_id,row['id'],p.user_id))
        _audit(conn,'specialist_agent.stopped',p,row['id'])
    return dict(stopped=True)


def history(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,content=True)
        case=service._case(conn,p,case_id)
        rows=conn.execute('''SELECT id,role,model,key_scope,created_at FROM gabriel_identity.specialist_agent_jobs
            WHERE organization_id=%s AND case_id=%s AND requested_by=%s ORDER BY created_at DESC,id LIMIT 32''',
            (p.organization_id,case['id'],p.user_id)).fetchall()
        return [dict(row,id=str(row['id']),created_at=row['created_at'].isoformat()) for row in rows]


def orchestrate(service,vault,token,case_id,request_id,input_evidence_id,*,model=DEFAULT_MODEL,key_scope='personal',approved=False):
    """Delegate only relevant roles; a shared provider does not merge agent identities."""
    if approved is not True:raise AccessDenied('specialist_ai_export_consent_required')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,content=True)
        case=service._case(conn,p,case_id,open_only=True)
        _,document,_=verified_input(service,conn,p,case,identifier(input_evidence_id))
        kinds={f['type'] for f in document['facts']}
    selected=[role for role in ROLES if ROLE_TYPES[role]&kinds]
    results=[]
    for role in selected:
        result=start(service,vault,token,case_id,uuid5(identifier(request_id),role),role,input_evidence_id,
            model=model,key_scope=key_scope,approved=True)
        results.append(dict(role=role,result=result))
    return dict(state='coordinator_completed_requires_review',agents=results,delegated_roles=selected,external_actions_authorized=False,quality_qualified=False)
