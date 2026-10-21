"""Real database restart checkpoint; secret state never enters CI artifacts."""
import json
import base64
from hashlib import sha256
import os
from pathlib import Path
import secrets
import sys
from types import SimpleNamespace
from uuid import uuid4
from psycopg.conninfo import make_conninfo

from gabriel.identity.cli import read_secret
from gabriel.identity.service import IdentityService, AuthenticationDenied, provision_organization
from gabriel.identity.machine import ServiceIdentityService
from gabriel.identity.vault import ProviderKeyRing, ProviderVault
from gabriel.identity.service import AccessDenied, IdentityUnavailable, connection, migrate
from gabriel.identity.cases import CaseService
from gabriel.identity.actions import ActionService
from gabriel.identity.retention import RetentionService
from gabriel.identity.checkpoint_service import CheckpointService
from gabriel.identity.checkpoint_policy import CheckpointPolicyService
from gabriel.identity.evidence_keys import EvidenceKeyService
from gabriel.identity.browser_sessions import BrowserSessionService
from gabriel.identity.browser_observations import BrowserObservationService
from gabriel.identity.browser_navigation import BrowserNavigationService,CONTRACTS,pending_navigation
from gabriel.identity.checkpoints import canonical,fingerprint,new_keypair,public_fingerprint,read_document,seal,write_document
from gabriel.identity.cases import custody_hash
from datetime import datetime,timedelta,timezone
from gabriel.identity.evidence_store import EvidenceError,EvidenceKeys,LocalEvidenceStore
from gabriel.identity.model_budget import ModelBudgetService
from testing.gabriel_identity.test_retention_integration import historical_artifact

app_dsn = read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE'])
app_dsn = make_conninfo(app_dsn,dbname='gabriel_vault_restore' if sys.argv[1]=='restored' else 'gabriel_checkpoint')
service = ServiceIdentityService(app_dsn)
vault = ProviderVault(app_dsn,
    ProviderKeyRing.from_file(os.environ['GABRIEL_PROVIDER_KEYRING_FILE']))
evidence_key_file = os.environ['GABRIEL_EVIDENCE_KEYRING_FILE']
cases = CaseService(app_dsn,LocalEvidenceStore(os.environ['GABRIEL_EVIDENCE_ROOT'],EvidenceKeys.from_file(evidence_key_file)))
state = Path('/checkpoint/state.json')
actions = ActionService(app_dsn,cases.store)
retention = RetentionService(app_dsn,cases.store)
checkpoints = CheckpointPolicyService(app_dsn,cases.store)
browsers = BrowserSessionService(app_dsn,cases.store)
observations = BrowserObservationService(app_dsn,cases.store)
navigation = BrowserNavigationService(app_dsn,cases.store)
assert not CONTRACTS
CONTRACTS['generated-recovery-navigation-v1']={'/security','/traffic'}
budget = ModelBudgetService(app_dsn)


def counts():
    tables = ('organizations','users','memberships','sessions','service_grants','audit_events',
              'provider_onboarding_checks','provider_secrets','provider_key_registry','provider_key_state','investigation_tasks','task_executions',
              'cases','case_tasks','evidence_objects','custody_events','evidence_exports','evidence_key_registry',
              'action_policies','action_policy_state','action_requests','action_approvals','action_decisions','action_executions',
              'retention_policies','case_hold_versions','legal_holds','hold_releases','purge_requests','purge_approvals','purge_attempts','retention_events',
              'checkpoint_keys','checkpoint_key_revocations','checkpoint_policies','checkpoint_captures','checkpoint_receipts',
              'evidence_key_epochs','evidence_rewraps','evidence_rewrap_results','browser_leases',
              'browser_observations','browser_observation_receipts','case_assignments','case_questions','case_question_answers','specialist_runs',
              'browser_navigation_grants','browser_navigation_intents','browser_navigation_receipts',
              'browser_navigation_commits','browser_navigation_stops','attack_pattern_runs',
              'memory_records','memory_reviews','memory_invalidations','memory_resets',
              'model_budget_policies','model_price_quotes','model_investigations','model_reservations',
              'model_dispatch_claims','model_settlements','model_investigation_stops','model_answer_intents','model_answer_receipts',
              'coordinator_runs','coordinator_sources','coordinator_steps','coordinator_claims','coordinator_results','coordinator_stops','migrations')
    # Migrations are deliberately not readable by the runtime role.
    with connection(app_dsn) as conn:
        return {name:conn.execute(f'SELECT count(*) AS n FROM gabriel_identity.{name}').fetchone()['n']
                for name in tables if name != 'migrations'}


if sys.argv[1] == 'before':
    owner_dsn = make_conninfo(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),dbname='gabriel_checkpoint')
    migrate(owner_dsn)
    password = secrets.token_urlsafe(24)
    org, user = provision_organization(owner_dsn,
                                      'Restart fixture', 'restart-owner', password)
    token = service.login(org, 'restart-owner', password).token
    task = service.create_task(token,'restart task',['evidence.hash'],3600,5)['id']
    machine = service.issue_service(token,'restart worker',task,['evidence.hash'])
    request_id = uuid4()
    request = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'restart fixture'}}
    response = service.execute_service(machine.token,task,request,request_id)
    provider_value = 'restart-generated-fixture-' + secrets.token_urlsafe(32)
    vault.put(token,'model_restart',provider_value)
    case = cases.create_case(token,'Recovery checkpoint fixture')
    cases.link_task(token,case['id'],task)
    evidence = cases.acquire(token,case['id'],uuid4(),'approved recovery fixture','Recovery fixture',approved=True)
    actions.set_policy(token,distinct_approver=False,approval_ttl=900)
    action = actions.propose_close(token,case['id'],uuid4(),'Reviewed recovery closure',ttl=3600)
    actions.submit(token,action['id'])
    actions.approve(token,action['id'],action['digest'])
    completed_case = cases.create_case(token,'Completed recovery fixture')
    completed_artifact = cases.acquire(token,completed_case['id'],uuid4(),'completed recovery artifact','Recovery fixture',approved=True)
    completed_action = actions.propose_close(token,completed_case['id'],uuid4(),'Reviewed completed fixture',ttl=3600)
    actions.submit(token,completed_action['id'])
    actions.approve(token,completed_action['id'],completed_action['digest'])
    receipt = actions.execute(token,completed_action['id'])
    retention.set_retention(token,1)
    hold = retention.place_hold(token,case['id'],'Recovery preservation fixture')
    review_password = secrets.token_urlsafe(24)
    retention.create_member(token,'retention-reviewer',review_password,'admin')
    review_token = retention.login(org,'retention-reviewer',review_password).token
    purge_case = cases.create_case(token,'Historical disposition recovery fixture')
    historical = SimpleNamespace(org=org,db=SimpleNamespace(owner=owner_dsn,app=app_dsn))
    artifacts = [cases.acquire(token,purge_case['id'],uuid4(),'generated historical purge fixture','Recovery disposition fixture',approved=True) for _ in range(2)]
    for artifact in artifacts:
        historical_artifact(historical,cases.store,artifact)
    close = actions.propose_close(token,purge_case['id'],uuid4(),'Reviewed historical recovery case closure')
    actions.submit(token,close['id'])
    actions.approve(token,close['id'],close['digest'])
    actions.execute(token,close['id'])
    attempts = []
    for index,artifact in enumerate(artifacts):
        request = retention.propose_purge(token,artifact['id'],uuid4(),'Reviewed primary recovery disposition')
        retention.approve_purge(review_token,request['id'],request['digest'])
        attempt = retention.prepare_purge(token,request['id'])
        attempts.append(attempt['id'])
        if index==0:
            retention.execute_purge(token,attempt['id'])
        else:
            with connection(owner_dsn,runtime=False) as conn:
                conn.execute('REVOKE INSERT ON gabriel_identity.retention_events FROM gabriel_identity_app')
            try:
                try:
                    retention.execute_purge(token,attempt['id'])
                except IdentityUnavailable:
                    pass
                else:
                    raise AssertionError('receipt failure did not block success')
            finally:
                with connection(owner_dsn,runtime=False) as conn:
                    conn.execute('GRANT INSERT ON gabriel_identity.retention_events TO gabriel_identity_app')
    signing_key,public_key = new_keypair()
    pin = public_fingerprint(public_key)
    checkpoints.trust_checkpoint_key(token,public_key,pin)
    checkpoints.set_checkpoint_policy(token,pin,3600)
    _,retired_public = new_keypair()
    retired_pin = public_fingerprint(retired_public)
    checkpoints.trust_checkpoint_key(token,retired_public,retired_pin)
    checkpoints.revoke_checkpoint_key(token,retired_pin,'Generated recovery key retirement')
    write_document('/checkpoint/custody-public.json',public_key)
    checkpoint_digests = {}
    for label,target in [('active',case['id']),('purged',purge_case['id'])]:
        envelope = seal(checkpoints.capture_checkpoint(token,target),signing_key)
        write_document('/checkpoint/custody-'+label+'.json',envelope)
        checkpoint_digests[label] = fingerprint(canonical(envelope))
        checkpoints.accept_checkpoint(token,target,envelope,checkpoint_digests[label])
    del signing_key
    key_password = secrets.token_urlsafe(24)
    key_org,_ = provision_organization(owner_dsn,'Separate key rollover recovery fixture','key-owner',key_password)
    key_token = service.login(key_org,'key-owner',key_password).token
    key_case = cases.create_case(key_token,'Encryption rollover recovery fixture')
    key_artifacts = [cases.acquire(key_token,key_case['id'],uuid4(),'generated key recovery artifact','Key recovery fixture',approved=True) for _ in range(2)]
    old_ring = cases.store.keys
    target = 'k_'+uuid4().hex
    new_ring = EvidenceKeys(target,dict(old_ring._keys,**{target:secrets.token_bytes(32)}),old_ring.generation+1)
    rekeys = EvidenceKeyService(app_dsn,LocalEvidenceStore(cases.store.root,new_ring))
    rekeys.activate_evidence_key(key_token)
    completed_rewrap = rekeys.prepare_rewrap(key_token,key_artifacts[0]['id'])
    rekeys.execute_rewrap(key_token,completed_rewrap['id'])
    pending_rewrap = rekeys.prepare_rewrap(key_token,key_artifacts[1]['id'])
    with connection(owner_dsn,runtime=False) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.evidence_rewrap_results FROM gabriel_identity_app')
    try:
        try:
            rekeys.execute_rewrap(key_token,pending_rewrap['id'])
        except IdentityUnavailable:
            pass
        else:
            raise AssertionError('rewrap receipt failure did not block success')
    finally:
        with connection(owner_dsn,runtime=False) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.evidence_rewrap_results TO gabriel_identity_app')
    write_document('/checkpoint/evidence-rotated-keys.json',{'schema_version':1,'purpose':'evidence-v1',
        'generation':new_ring.generation,'active':new_ring.active,'keys':{k:base64.b64encode(v).decode() for k,v in new_ring._keys.items()}})
    browser_context = {'browser':'chrome','extension_version':'0.1.0','installation_id':str(uuid4()),'tab_id':3,
        'document_id':str(uuid4()),'page_url':'https://generated-recovery-console.invalid/security','account_label':'Generated recovery account'}
    browser_task = browsers.create_browser_task(token,'Generated recovery browser task',3600,10)
    browser_grant = browsers.issue_browser_lease(token,browser_task['id'],case['id'],browser_context)
    browsers.connect_browser(browser_grant.token,browser_context)
    observation_password = secrets.token_urlsafe(24)
    observation_org,_ = provision_organization(owner_dsn,'Separate browser observation recovery fixture','observation-owner',observation_password)
    observation_token = service.login(observation_org,'observation-owner',observation_password).token
    observation_case = observations.create_case(observation_token,'Browser content recovery fixture')
    observation_task = observations.create_browser_task(observation_token,'Generated observation recovery task',3600,10)
    observation_grant = observations.issue_browser_lease(observation_token,observation_task['id'],observation_case['id'],browser_context,share_observations=True)
    observations.connect_browser(observation_grant.token,browser_context)
    observation_payload = dict(schema_version=1,operation='browser.observe',request_id=str(uuid4()),sequence=1,
        context=browser_context,observed_at=datetime.now(timezone.utc).isoformat(),visibility='partial',
        client_minimized=True,content='Generated browser recovery evidence')
    observation_receipt = observations.observe_browser(observation_token,observation_grant.token,observation_payload)
    pending_payload = dict(observation_payload,request_id=str(uuid4()),sequence=2,content='Generated interrupted browser recovery evidence')
    with connection(owner_dsn,runtime=False) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.browser_observation_receipts FROM gabriel_identity_app')
    try:
        try:
            observations.observe_browser(observation_token,observation_grant.token,pending_payload)
        except IdentityUnavailable:
            pass
        else:
            raise AssertionError('browser receipt failure did not block success')
    finally:
        with connection(owner_dsn,runtime=False) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.browser_observation_receipts TO gabriel_identity_app')
    with connection(app_dsn) as conn:
        pending_observation = conn.execute("SELECT id FROM gabriel_identity.browser_observations WHERE organization_id=%s AND state='prepared'",(observation_org,)).fetchone()['id']
    assignment=cases.assign_case(token,case['id'],uuid4(),user)
    question=cases.add_question(token,case['id'],uuid4(),'Generated recovery investigation question')
    cases.answer_question(token,case['id'],question,evidence['id'],'Generated recovery analyst explanation')
    prior_memory=cases.propose_memory(token,case['id'],evidence['id'],uuid4(),'fact','case','recovery.old',ttl_seconds=3600)
    cases.review_memory(token,prior_memory['id'],'approved',prior_memory['source_digest'],True)
    assert cases.forget_memory(token,prior_memory['id'])['retrieval_removed']
    assert cases.reset_memory(token,0)['epoch']==1
    memory=cases.propose_memory(token,case['id'],evidence['id'],uuid4(),'fact','case','recovery.current',ttl_seconds=3600)
    cases.review_memory(token,memory['id'],'approved',memory['source_digest'],True)
    from testing.gabriel_identity.test_specialist_analysis import CASES as specialist_examples
    typed_case=cases.create_case(token,'Generated twelve-specialist recovery case')
    typed_source=cases.acquire(token,typed_case['id'],uuid4(),'Generated specialist source bytes','Generated specialist source',approved=True)
    facts=[dict(id=str(uuid4()),type=kind,evidence_id=str(typed_source['id']),evidence_digest=typed_source['digest'],
        entity_id=str(uuid4()),event_time='2026-10-20T11:00:00Z',data=data)
        for _,kind,data,_,_ in specialist_examples]
    typed=cases.acquire(token,typed_case['id'],uuid4(),json.dumps(dict(version='specialist-facts-v1',case_id=str(typed_case['id']),
        as_of='2026-10-20T12:00:00Z',facts=facts)),'Generated twelve-specialist recovery facts',approved=True)
    typed_specialists={}
    for role,_,_,_,_ in specialist_examples:
        run=cases.run_specialist(token,typed_case['id'],uuid4(),role,input_evidence_id=typed['id'])
        typed_specialists[role]=dict(id=run['id'],digest=run['result_digest'])
    report_snapshot = cases.case_report(token,case['id'])['snapshot']
    specialist=cases.run_specialist(token,case['id'],uuid4(),'telemetry_health')
    coordinated=cases.begin_coordinator(token,case['id'],uuid4())
    first_step=cases.advance_coordinator(token,coordinated['id'])
    with connection(owner_dsn,runtime=False) as conn:
        conn.execute('REVOKE INSERT ON gabriel_identity.coordinator_results FROM gabriel_identity_app')
    try:
        try:
            cases.advance_coordinator(token,coordinated['id'])
        except IdentityUnavailable:
            pass
        else:
            raise AssertionError('coordinator receipt failure did not block success')
    finally:
        with connection(owner_dsn,runtime=False) as conn:
            conn.execute('GRANT INSERT ON gabriel_identity.coordinator_results TO gabriel_identity_app')
    stopped_coordinator=cases.begin_coordinator(token,case['id'],uuid4())
    cases.stop_coordinator(token,stopped_coordinator['id'])
    budget.configure(token)
    price=budget.quote(token,'openrouter','google/gemini-2.5-flash-lite','a'*64,100000,400000,3600)
    model_job=budget.begin(token,case['id'],uuid4())
    claimed=budget.reserve(token,model_job['id'],uuid4(),price['id'],'b'*64)
    budget.claim(token,claimed['id'])
    budget.reserve(token,model_job['id'],uuid4(),price['id'],'c'*64)
    budget.stop(token,model_job['id'])
    assert budget.status(token)['usage']==dict(month_used=1400,day_used=1400,held_slots=1)
    # A separate generated tenant preserves the existing budget checkpoint's exact assertions.
    from gabriel.identity import model_routes,model_worker,provider_onboarding
    from gabriel.identity.model_worker import ModelWorker,configuration
    from gabriel.identity.model_evaluation import digest as model_digest
    from testing.gabriel_identity.test_model_lab import catalog,key_data
    answer_password=secrets.token_urlsafe(24)
    answer_org,_=provision_organization(owner_dsn,'Generated answer recovery','answer-owner',answer_password)
    answer_token=service.login(answer_org,'answer-owner',answer_password).token
    answer_secret='generated-answer-key-'+secrets.token_urlsafe(30)
    answer_case=cases.create_case(answer_token,'Generated durable answer case')
    answer_source=cases.acquire(answer_token,answer_case['id'],uuid4(),'Generated normalized source','Generated answer source',approved=True)
    record=dict(record_id=str(uuid4()),evidence_id=str(answer_source['id']),evidence_digest=answer_source['digest'],
        event_time='2026-10-20T12:00:00Z',kind='authentication',outcome='failure',actor='Generated private recovery actor',
        asset='Generated private recovery asset',address=None,count=2)
    answer_input=cases.acquire(answer_token,answer_case['id'],uuid4(),json.dumps(dict(version='normalized-telemetry-v1',records=[record])),
        'Generated answer input',approved=True)
    answer_plan=cases.begin_coordinator(answer_token,answer_case['id'],uuid4())
    cases.advance_coordinator(answer_token,answer_plan['id']);cases.advance_coordinator(answer_token,answer_plan['id'])
    model='openai/gpt-4.1-mini';answer_calls=[]
    class GeneratedTransport:
        def __init__(self,credential): assert credential.reveal()==answer_secret
        def request(self,method,path,payload=None):
            if path=='/api/v1/key': return dict(data=key_data())
            if path=='/api/v1/credits': return dict(data=dict(total_credits=20,total_usage=0))
            if path=='/api/v1/endpoints/zdr': return catalog()
            assert method=='POST';answer_calls.append(1)
            decision=dict(disposition='abstain',claims=[dict(id='claim-1',statement='Generated partial source.',references=['o1'])],
                alternatives=['Generated authorized explanation.'],contradictions=['No independent corroboration supplied.'],
                uncertainty=['Generated visibility limit.'],reported_gaps=['missing-context'],requested_actions=[])
            return dict(id='generated-recovery-answer',model=model,provider='Azure',
                choices=[dict(finish_reason='stop',message=dict(content=json.dumps(decision)))],
                usage=dict(prompt_tokens=300,completion_tokens=200,cost=0.0002))
    old_transport,old_admission=model_worker.OpenRouterTransport,model_routes.PRODUCTION_CONFIGURATIONS
    old_onboarding_transport=provider_onboarding.OpenRouterTransport
    try:
        model_worker.OpenRouterTransport=GeneratedTransport
        provider_onboarding.OpenRouterTransport=GeneratedTransport
        provider_onboarding.CustomerProviders(vault).configure(answer_token,'openrouter',answer_secret)
        model_routes.PRODUCTION_CONFIGURATIONS=frozenset({model_digest(configuration(model))})
        answer_worker=ModelWorker(cases,vault)
        answer_reservation=answer_worker.reserve(answer_token,answer_plan['id'],answer_input['id'],uuid4(),model)
        answer_result=answer_worker.dispatch(answer_token,answer_plan['id'],answer_input['id'],answer_reservation['reservation_id'])
        assert answer_result.metadata['result_persisted'] and len(answer_calls)==1
        pending_plan=cases.begin_coordinator(answer_token,answer_case['id'],uuid4())
        cases.advance_coordinator(answer_token,pending_plan['id']);cases.advance_coordinator(answer_token,pending_plan['id'])
        pending_answer=answer_worker.reserve(answer_token,pending_plan['id'],answer_input['id'],uuid4(),model)
        with connection(owner_dsn,runtime=False) as conn:
            conn.execute('REVOKE INSERT ON gabriel_identity.model_answer_receipts FROM gabriel_identity_app')
        try:
            try: answer_worker.dispatch(answer_token,pending_plan['id'],answer_input['id'],pending_answer['reservation_id'])
            except IdentityUnavailable: pass
            else: raise AssertionError('answer receipt failure did not block publication')
        finally:
            with connection(owner_dsn,runtime=False) as conn:
                conn.execute('GRANT INSERT ON gabriel_identity.model_answer_receipts TO gabriel_identity_app')
        assert len(answer_calls)==2
    finally:
        model_worker.OpenRouterTransport=old_transport;model_routes.PRODUCTION_CONFIGURATIONS=old_admission
        provider_onboarding.OpenRouterTransport=old_onboarding_transport
    navigation_case=navigation.create_case(observation_token,'Separate generated navigation recovery case')
    navigation_task=navigation.create_browser_task(observation_token,'Generated navigation recovery task',3600,10)
    navigation_lease=navigation.issue_browser_lease(observation_token,navigation_task['id'],navigation_case['id'],browser_context,share_observations=True)
    navigation.connect_browser(navigation_lease.token,browser_context)
    navigation.grant_navigation(observation_token,navigation_lease.token,uuid4(),'generated-recovery-navigation-v1',
        ['https://generated-recovery-console.invalid/traffic',browser_context['page_url']],max_moves=2)
    navigation_intent=navigation.prepare_navigation(observation_token,navigation_lease.token,uuid4(),'https://generated-recovery-console.invalid/traffic')
    navigation_context=dict(browser_context,page_url=navigation_intent['destination_url'],document_id=str(uuid4()))
    navigation.complete_navigation(observation_token,navigation_lease.token,navigation_intent['id'],navigation_context)
    navigation_pending=navigation.prepare_navigation(observation_token,navigation_lease.token,uuid4(),browser_context['page_url'])
    from testing.gabriel_identity.test_attack_pattern_runs_integration import event_document
    attack_case=cases.create_case(token,'Separate generated attack review recovery case')
    attack_source=cases.acquire(token,attack_case['id'],uuid4(),'Generated attack review recovery bytes','Generated attack review source',approved=True)
    attack_input=cases.acquire(token,attack_case['id'],uuid4(),json.dumps(event_document(attack_case['id'],attack_source)),
        'Generated attack review snapshot',approved=True)
    attack_review=cases.run_attack_review(token,attack_case['id'],uuid4(),attack_input['id'])
    state.write_text(json.dumps({'org':str(org),'user':str(user),'token':token,
        'attack_case_id':str(attack_case['id']),'attack_review_id':attack_review['id'],'attack_review_digest':attack_review['result_digest'],
        'navigation_peer':navigation_lease.token,'navigation_intent':navigation_intent['id'],
        'navigation_pending':navigation_pending['id'],'navigation_context':navigation_context,
        'answer_token':answer_token,'answer_reservation':answer_reservation['reservation_id'],
        'pending_answer_reservation':pending_answer['reservation_id'],
        'answer_run':answer_plan['id'],'answer_input':str(answer_input['id']),'answer_digest':sha256(answer_result.reveal()).hexdigest(),
        'report_evidence':report_snapshot['evidence'],'report_timeline':report_snapshot['timeline'],
        'workflow_assignment':assignment['id'],'workflow_question':question,
        'specialist_id':specialist['id'],'specialist_digest':specialist['result_digest'],'typed_specialists':typed_specialists,
        'typed_specialist_case':str(typed_case['id']),
        'coordinator_id':coordinated['id'],'coordinator_first_digest':first_step['steps'][0]['result_digest'],
        'stopped_coordinator_id':stopped_coordinator['id'],
        'memory_id':memory['id'],'memory_source_digest':memory['source_digest'],'old_memory_id':prior_memory['id'],
        'model_reservation_id':str(claimed['id']),'model_job_id':str(model_job['id']),
        'provenance_digest':cases.case_graph(token,case['id'])['digest'],
        'task':str(task),'service_token':machine.token,'grant_id':str(machine.id),
        'request_id':str(request_id),'response':response,
        'case_id':str(case['id']),'evidence_id':str(evidence['id']),
        'action_id':str(action['id']),'completed_action_id':str(completed_action['id']),'action_receipt':receipt,
        'hold_id':str(hold['id']),'purge_case_id':str(purge_case['id']),
        'completed_purge':str(attempts[0]),'pending_purge':str(attempts[1]),
        'purged_evidence':[str(artifact['id']) for artifact in artifacts],
        'checkpoint_digests':checkpoint_digests,'retired_checkpoint_key':retired_pin,
        'completed_rewrap':str(completed_rewrap['id']),'pending_rewrap':str(pending_rewrap['id']),
        'key_token':key_token,'key_artifact':str(key_artifacts[1]['id']),'old_evidence_key':old_ring.active,
        'browser_token':browser_grant.token,'browser_lease':str(browser_grant.id),'browser_context':browser_context,
        'observation_token':observation_token,'observation_peer':observation_grant.token,'observation_lease':str(observation_grant.id),
        'observation_payload':observation_payload,'observation_receipt':json.loads(json.dumps(observation_receipt,default=str)),'pending_observation':str(pending_observation),
        'provider_digest':sha256(provider_value.encode()).hexdigest(),'counts':counts()}))
    state.chmod(0o600)
    print('PASS: real database checkpoint created without logging credentials')
elif sys.argv[1] in {'after','restored'}:
    saved = json.loads(state.read_text())
    if sys.argv[1] == 'restored':
        assert counts()==saved['counts']
    from gabriel.identity.model_worker import ModelWorker
    answer_worker=ModelWorker(cases,vault)
    restored_answer=answer_worker.get_answer(saved['answer_token'],saved['answer_reservation'])
    assert sha256(restored_answer.reveal()).hexdigest()==saved['answer_digest']
    assert restored_answer.metadata['historical'] and restored_answer.metadata['cost_reconciliation_required']
    assert answer_worker.recover_answer(saved['answer_token'],saved['answer_reservation']).reveal()==restored_answer.reveal()
    try:
        answer_worker.dispatch(saved['answer_token'],saved['answer_run'],saved['answer_input'],saved['answer_reservation'])
    except AccessDenied as error:
        assert str(error)=='model_worker_already_claimed_no_resend'
    else: raise AssertionError('completed answer was sent again after recovery')
    pending_recovered=answer_worker.recover_answer(saved['answer_token'],saved['pending_answer_reservation'])
    assert pending_recovered.metadata['result_persisted']
    assert answer_worker.get_answer(saved['answer_token'],saved['pending_answer_reservation']).reveal()==pending_recovered.reveal()
    assert budget.status(saved['answer_token'])['usage']['held_slots']==2
    print('PASS: encrypted model answer/lineage and immutable receipt survived recovery without provider access or another charge claim')
    coordinated=cases.get_coordinator(saved['token'],saved['coordinator_id'])
    assert coordinated['completed_steps']==1 and coordinated['steps'][1]['claimed_at'] is not None
    assert coordinated['steps'][0]['result_digest']==saved['coordinator_first_digest']
    with connection(app_dsn) as conn:
        before=conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE case_id=%s',(saved['case_id'],)).fetchone()['n']
    finished=cases.advance_coordinator(saved['token'],saved['coordinator_id'])
    assert finished['status']=='local_plan_complete' and finished['completed_steps']==2
    with connection(app_dsn) as conn:
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE case_id=%s',(saved['case_id'],)).fetchone()['n']==before
    assert cases.get_coordinator(saved['token'],saved['stopped_coordinator_id'])['status']=='stopped'
    try:
        cases.advance_coordinator(saved['token'],saved['stopped_coordinator_id'])
    except AccessDenied:
        pass
    else:
        raise AssertionError('stopped coordinator became executable after recovery')
    print('PASS: coordinator claim, source binding, replay and Stop survived recovery without duplicate specialist work')
    assert budget.status(saved['token'])['usage']==dict(month_used=1400,day_used=1400,held_slots=1)
    try:
        budget.claim(saved['token'],saved['model_reservation_id'])
    except AccessDenied:
        pass
    else:
        raise AssertionError('stopped model dispatch became claimable after recovery')
    budget.settle(saved['token'],saved['model_reservation_id'],700,'d'*64)
    assert budget.status(saved['token'])['usage']==dict(month_used=700,day_used=700,held_slots=0)
    attack_review=cases.get_attack_review(saved['token'],saved['attack_case_id'],saved['attack_review_id'])
    assert attack_review['result_digest']==saved['attack_review_digest'] and attack_review['result']['findings'][0]['family']=='brute_force'
    assert not attack_review['grants_authority'] and not attack_review['result']['live_detection_accepted']
    for ref in attack_review['packet']['references']:
        assert sha256(cases.read_evidence(saved['token'],ref['record_id']).reveal()).hexdigest()==ref['digest']
    print('PASS: persisted attack candidate review and verified source bytes survived recovery without model access or response authority')
    replayed_navigation=navigation.complete_navigation(saved['observation_token'],saved['navigation_peer'],
        saved['navigation_intent'],saved['navigation_context'])
    assert replayed_navigation['replayed'] and replayed_navigation['current']
    with connection(app_dsn) as conn:
        principal,lease=navigation._browser(conn,saved['navigation_peer'])
        assert str(pending_navigation(conn,principal.organization_id,lease['id'])['id'])==saved['navigation_pending']
        assert conn.execute('SELECT count(*) AS n FROM gabriel_identity.browser_navigation_commits WHERE organization_id=%s',
                            (principal.organization_id,)).fetchone()['n']==1
    try:
        navigation.observe_browser(saved['observation_token'],saved['navigation_peer'],
            dict(saved['observation_payload'],request_id=str(uuid4()),context=saved['navigation_context']))
    except AccessDenied as exc:
        assert str(exc)=='browser_navigation_outcome_unresolved'
    else: raise AssertionError('unresolved navigation allowed evidence capture after recovery')
    navigation.stop_navigation(saved['observation_token'],saved['navigation_peer'])
    try: navigation.heartbeat_browser(saved['navigation_peer'],saved['navigation_context'])
    except AuthenticationDenied: pass
    else: raise AssertionError('navigation Stop failed after recovery')
    print('PASS: navigation receipt replay and unresolved move survived recovery without dispatch, rewind or evidence capture; Stop remained terminal')
    observations.heartbeat_browser(saved['observation_peer'],saved['browser_context'])
    replay = observations.observe_browser(saved['observation_token'],saved['observation_peer'],saved['observation_payload'])
    assert json.loads(json.dumps(replay,default=str))==saved['observation_receipt']
    observations.revoke_browser_lease(saved['observation_token'],saved['observation_lease'])
    recovered = observations.reconcile_browser_observation(saved['observation_token'],saved['pending_observation'])
    assert recovered['mode']=='engineer_reconciled'
    assert observations.read_evidence(saved['observation_token'],recovered['evidence_id']).reveal()==b'Generated interrupted browser recovery evidence'
    assert observations.get_browser_lease(saved['observation_token'],saved['observation_lease'])['captured_observations']==2
    try:
        observations.observe_browser(saved['observation_token'],saved['observation_peer'],saved['observation_payload'])
    except (AccessDenied,AuthenticationDenied):
        pass
    else:
        raise AssertionError('revoked browser observation delegation survived recovery')
    assert browsers.heartbeat_browser(saved['browser_token'],saved['browser_context'])['page_content_received'] is False
    assert browsers.get_browser_lease(saved['token'],saved['browser_lease'])['authorization_current']
    rotated_store = LocalEvidenceStore(cases.store.root,EvidenceKeys.from_file('/checkpoint/evidence-rotated-keys.json'))
    rekeys = EvidenceKeyService(app_dsn,rotated_store)
    assert rekeys.reconcile_rewrap(saved['key_token'],saved['completed_rewrap'])['state']=='completed'
    assert rekeys.reconcile_rewrap(saved['key_token'],saved['pending_rewrap'])['state']=='completed'
    active = rotated_store.keys.active
    minimal = EvidenceKeys(active,{active:rotated_store.keys._key(active)},rotated_store.keys.generation)
    reduced = EvidenceKeyService(app_dsn,LocalEvidenceStore(cases.store.root,minimal))
    assert reduced.read_evidence(saved['key_token'],saved['key_artifact']).reveal()==b'generated key recovery artifact'
    assert rekeys.key_retirement_check(saved['key_token'],saved['old_evidence_key'])['tenant_live_ready']
    trusted_key = read_document('/checkpoint/custody-public.json')
    for label,target in [('active',saved['case_id']),('purged',saved['purge_case_id'])]:
        assert checkpoints.check_checkpoint_policy(saved['token'],target,saved['checkpoint_digests'][label])['full_current_evidence_coverage']
        assert checkpoints.verify_checkpoint(saved['token'],target,read_document('/checkpoint/custody-'+label+'.json'),
            trusted_key,saved['checkpoint_digests'][label])['custody_prefixes_match']
    try:
        checkpoints.set_checkpoint_policy(saved['token'],saved['retired_checkpoint_key'],3600)
    except AccessDenied:
        pass
    else:
        raise AssertionError('retired checkpoint signer regained authority after recovery')
    principal = service.whoami(saved['token'])
    assert str(principal.organization_id) == saved['org']
    assert str(principal.user_id) == saved['user'] and principal.role == 'owner'
    assert retention.governance(saved['token'],saved['case_id'])['holds'][0]['state']=='active'
    assert retention.reconcile_purge(saved['token'],saved['completed_purge'])['outcome']=='removed'
    assert retention.reconcile_purge(saved['token'],saved['pending_purge'])['outcome']=='absence_confirmed'
    for evidence_id in saved['purged_evidence']:
        try:
            cases.read_evidence(saved['token'],evidence_id)
        except EvidenceError as exc:
            assert str(exc)=='evidence_purged'
        else:
            raise AssertionError('purged evidence became readable')
    assert cases.verify_case(saved['token'],saved['case_id'])['complete']
    assert cases.read_evidence(saved['token'],saved['evidence_id']).reveal()==b'approved recovery fixture'
    report_snapshot = cases.case_report(saved['token'],saved['case_id'])['snapshot']
    assert report_snapshot['evidence']==saved['report_evidence']
    assert all(event in report_snapshot['timeline'] for event in saved['report_timeline'])
    assert report_snapshot['assessment']=='not_performed' and report_snapshot['content_integrity']=='not_checked'
    assert cases.case_graph(saved['token'],saved['case_id'])['digest']==saved['provenance_digest']
    for role,expected in saved['typed_specialists'].items():
        run=cases.get_specialist_run(saved['token'],saved['typed_specialist_case'],expected['id'])
        assert run['role']==role and run['result_digest']==expected['digest']
        assert run['result']['attack_status']=='unknown' and not run['result']['external_actions_authorized']
        assert run['packet']['fact_count']==12 and not run['grants_authority']
    print('PASS: all twelve source-bound local specialist reviews survived recovery without external execution')
    specialist=cases.get_specialist_run(saved['token'],saved['case_id'],saved['specialist_id'])
    assert specialist['result_digest']==saved['specialist_digest'] and specialist['result']['attack_status']=='unknown'
    assert not specialist['grants_authority'] and specialist['result']['execution']['model'] is None
    memory,=cases.retrieve_memory(saved['token'],saved['case_id'])
    assert memory.metadata['id']==saved['memory_id'] and memory.metadata['source_digest']==saved['memory_source_digest']
    assert memory.reveal()==b'approved recovery fixture' and not memory.metadata['grants_authority']
    history=cases.list_memory(saved['token'],saved['case_id'])
    assert history['current_epoch']==1 and next(row for row in history['records'] if row['id']==saved['old_memory_id'])['status']=='reset'
    assert cases.forget_memory(saved['token'],saved['memory_id'])['retrieval_removed']
    assert not cases.retrieve_memory(saved['token'],saved['case_id'])
    assert cases.reset_memory(saved['token'],1)['epoch']==2
    workflow=cases.case_workflow(saved['token'],saved['case_id'])
    assert workflow['assignment']['id']==saved['workflow_assignment'] and workflow['assignment']['assignee_active']
    assert workflow['questions'][0]['id']==saved['workflow_question'] and workflow['questions'][0]['state']=='human_answer_supplied'
    assert not workflow['questions'][0]['source_verified'] and not workflow['assignment_grants_authority']
    assert service.get_task(saved['token'],saved['task'])['id'] in cases.get_case(saved['token'],saved['case_id'])['task_ids']
    assert actions.get_action(saved['token'],saved['action_id'])['state']=='approved'
    assert actions.execute(saved['token'],saved['completed_action_id'])==saved['action_receipt']
    actions.execute(saved['token'],saved['action_id'],checkpoint_digest=saved['checkpoint_digests']['active'])
    assert cases.get_case(saved['token'],saved['case_id'])['case']['state']=='closed'
    assert cases.case_report(saved['token'],saved['case_id'])['snapshot']['case']['state']=='closed'
    assert sha256(vault.resolve_for_backend(saved['token'],'model_restart').reveal().encode()).hexdigest()==saved['provider_digest']
    vault.revoke(saved['token'],'model_restart')
    try:
        vault.resolve_for_backend(saved['token'],'model_restart')
    except AccessDenied:
        pass
    else:
        raise AssertionError('revoked provider secret survived')
    request = {'schema_version':1,'operation':'evidence.hash','arguments':{'content':'restart fixture'}}
    result = service.execute_service(saved['service_token'],saved['task'],request,saved['request_id'])
    assert result['service_id'] == saved['grant_id'] and result['organization_id'] == saved['org']
    assert result==saved['response'] and service.get_task(saved['token'],saved['task'])['used_steps']==1
    service.end_task(saved['token'],saved['task'],'cancelled')
    assert service.get_task(saved['token'],saved['task'])['state']=='cancelled'
    service.revoke_service(saved['token'],saved['grant_id'])
    try:
        service.execute_service(saved['service_token'],saved['task'],request,saved['request_id'])
    except AuthenticationDenied:
        pass
    else:
        raise AssertionError('revoked service survived')
    if sys.argv[1]=='restored':
        envelope = read_document('/checkpoint/custody-active.json')
        anchored = envelope['body']['snapshot']['evidence'][0]
        owner_dsn = make_conninfo(read_secret(os.environ['GABRIEL_MIGRATION_DSN_FILE']),dbname='gabriel_vault_restore')
        with connection(owner_dsn,runtime=False) as conn:
            events = conn.execute('SELECT * FROM gabriel_identity.custody_events WHERE organization_id=%s AND evidence_id=%s ORDER BY sequence',
                (saved['org'],anchored['evidence_id'])).fetchall()
            previous = None
            for event in events:
                if event['sequence']<anchored['sequence']:
                    previous = event['event_hash']
                    continue
                instant = event['created_at']+timedelta(microseconds=1)
                head = custody_hash(saved['org'],anchored['evidence_id'],event['sequence'],event['actor_id'],event['event'],previous,instant)
                conn.execute('UPDATE gabriel_identity.custody_events SET previous_hash=%s,event_hash=%s,created_at=%s WHERE organization_id=%s AND evidence_id=%s AND sequence=%s',
                    (previous,head,instant,saved['org'],anchored['evidence_id'],event['sequence']))
                previous = head
        assert cases.custody(saved['token'],anchored['evidence_id'])[-1]['event_hash']==head
        try:
            checkpoints.verify_checkpoint(saved['token'],saved['case_id'],envelope,trusted_key,saved['checkpoint_digests']['active'])
        except EvidenceError as exc:
            assert str(exc)=='checkpoint_custody_changed'
        else:
            raise AssertionError('trusted checkpoint missed privileged restored history rewrite')
        print('PASS: independent signed checkpoint detected privileged valid rehash after restore')
    service.logout(saved['token'])
    try:
        browsers.heartbeat_browser(saved['browser_token'],saved['browser_context'])
    except (AccessDenied,AuthenticationDenied):
        pass
    else:
        raise AssertionError('browser delegation survived original human logout')
    try:
        service.whoami(saved['token'])
    except AuthenticationDenied:
        pass
    else:
        raise AssertionError('revoked session survived')
    print('PASS: identities, service grant and encrypted provider value survived PostgreSQL restart; all revocations enforced')
    print('PASS: durable task/receipt replay survived recovery without another step; task cancellation enforced')
    print('PASS: case linkage and encrypted evidence/custody survived recovery; integrity-checked closure enforced')
    print('PASS: metadata report reconstructed evidence and prior timeline after recovery without inventing source truth or content-integrity verification')
    print('PASS: case provenance graph rebuilt with identical checksum after actual database recovery')
    print('PASS: immutable telemetry specialist result survived recovery without inventing attacker or model conclusions')
    print('PASS: reviewed encrypted memory and forget/reset epochs survived recovery; stale records remained excluded')
    print('PASS: append-only case assignment and evidence-linked analyst answer survived recovery without granting authority or learned truth')
    print('PASS: exact policy/approval survived recovery; pending local closure executed and completed receipt replayed')
    print('PASS: legal hold and retention survived recovery; completed purge retained and interrupted unlink reconciled without another deletion')
    print('PASS: externally retained signed custody checkpoints matched active and purged evidence after recovery')
    print('PASS: checkpoint trust/policy/receipts and signer revocation survived recovery; pending closure required the retained external digest')
    print('PASS: encryption rollover and interrupted replacement survived recovery; target-only live ring read verified bytes with immutable custody')
    print('PASS: scoped browser pairing survived recovery with live human authority; original logout denied delegated heartbeat; no page content collected')
    print('PASS: approved generated browser text and interrupted receipt survived recovery; revoked peer stayed denied while human reconciled authenticated ciphertext')
    if sys.argv[1] == 'restored':
        print('PASS: real pg_dump/pg_restore recovered matching row counts and encrypted values with separately retained keys')
else:
    raise SystemExit(2)
