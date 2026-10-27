"""Role-bound tool catalog, packaged skills and checked local evidence execution."""
import base64
from datetime import datetime
from hashlib import sha256
import http.client
import json
import math
from pathlib import Path

from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest
from gabriel.identity.service import AccessDenied,_audit,connection,identifier
from gabriel.identity.specialist_analysis import ROLE_TYPES,analyze
from gabriel.identity.specialist_analysis_runs import verified_input
from gabriel.identity.specialist_contracts import ROLES,role_name

VERSION='gabriel-investigation-toolkit-v1'
SKILLS=Path(__file__).with_name('investigation_skills')
REMOTE={'scan_artifacts','inspect_packets','inspect_logs'}
EXTRA={
    'telemetry_health':('correlate_events','inspect_logs'),
    'alert_triage':('inspect_logs','correlate_events','scan_artifacts'),
    'incident_scoping':('correlate_events','inspect_logs','inspect_packets'),
    'threat_intelligence':('scan_artifacts','inspect_packets'),
    'threat_hunting':('inspect_logs','scan_artifacts','inspect_packets'),
    'dfir_evidence':('scan_artifacts','inspect_packets'),
    'detection_engineering':('scan_artifacts','inspect_logs'),
    'exposure_vulnerability':('assess_exposure',),
    'identity_access':('inspect_logs','correlate_events'),
    'cloud_supply_chain':('scan_artifacts','correlate_events'),
    'response_remediation':('assess_exposure','correlate_events'),
    'recovery_learning':('correlate_events',),
}
TOOLS={r:('verify_sources','review_rules','review_memory')+(() if r=='recovery_learning' else ('inspect_timeline',))+('inspect_toolkit',)+EXTRA[r] for r in ROLES}
CATALOG={
    'verify_sources':('Gabriel','MIT','Check stored evidence integrity; this does not authenticate its origin.'),
    'review_rules':('Gabriel','MIT','Apply role-specific rules when supplied facts need prioritization.'),
    'inspect_timeline':('Gabriel','MIT','Inspect supplied event times; never assume clocks are verified.'),
    'review_memory':('Gabriel','MIT','Compare approved typed historical assertions; free text and performance-test memory stay excluded.'),
    'inspect_toolkit':('Gabriel','MIT','Check installed tool versions and skills when a capability is missing.'),
    'correlate_events':('Gabriel','MIT','Group supplied facts by entity and outcome; overlapping counts are not unique events.'),
    'assess_exposure':('Gabriel','MIT','Prioritize reachable unmitigated high/critical exposures independently of exploitation.'),
    'scan_artifacts':('yara-python','Apache-2.0 AND BSD-3-Clause','Match three bundled behavioral text rules on source files; no match never proves clean.'),
    'inspect_packets':('dpkt','BSD-3-Clause','Summarize Ethernet PCAP/PCAPNG source envelopes; packet patterns are hypotheses.'),
    'inspect_logs':('Python','PSF-2.0','Correlate normalized JSONL source logs for failure bursts and later successes.'),
}


def manifest(role):
    role_name(role)
    return [dict(name=n,engine=CATALOG[n][0],license=CATALOG[n][1],selection=CATALOG[n][2],
        skill_sha256=sha256((SKILLS/n/'SKILL.md').read_bytes()).hexdigest(),
        input='job_bound_local_sources_no_model_arguments',version=VERSION,
        purpose=CATALOG[n][2],when_to_use=CATALOG[n][2],args_format='requested_actions=[tool_name]; runtime supplies job-bound evidence; no arbitrary arguments',
        description=(SKILLS/n/'SKILL.md').read_text().split('---',2)[-1].strip(),
        implementation_sha256=digest([sha256(p.read_bytes()).hexdigest() for p in (Path(__file__),Path(__file__).parents[1]/'toolbox'/'engine.py',Path(__file__).parents[1]/'toolbox'/'server.py',Path(__file__).with_name('reviewed_memory.py'),Path(__file__).with_name('memory.py'))])) for n in TOOLS[role]]


def instructions(role):
    # The actual packaged skill is model context, not a decorative documentation link.
    return '\n'.join((SKILLS/n/'SKILL.md').read_text().split('---',2)[-1].strip() for n in TOOLS[role])


def remote(name,data=None):
    client=http.client.HTTPConnection('investigation-tools',8450,timeout=7)
    try:
        if name=='inspect_toolkit':client.request('GET','/health')
        else:client.request('POST','/analyze',body=canonical(dict(tool=name,data=base64.b64encode(data).decode())),headers={'Content-Type':'application/json'})
        response=client.getresponse();raw=response.read(8193)
        if response.status!=200 or len(raw)>8192:raise ValueError
        result=json.loads(raw)
        if type(result) is not dict:raise ValueError
        if name=='inspect_toolkit':
            available=result.get('status')=='ready' and result.get('packages')=={'yara-python':'4.5.4','dpkt':'1.9.8'} and set(result.get('tools',[]))==REMOTE and result.get('engine_sha256')==sha256((Path(__file__).parents[1]/'toolbox'/'engine.py').read_bytes()).hexdigest()
            return dict(status='ready' if available else 'version_mismatch',packaged_tools_ready=available,
                expected_packages={'yara-python':'4.5.4','dpkt':'1.9.8'},automatic_installation=False)
        return minimized(name,result)
    except (OSError,http.client.HTTPException,ValueError,TypeError,KeyError):
        return dict(status='tool_unavailable',required_action='check_private_toolbox_service',automatic_installation=False)
    finally:client.close()


def minimized(name,row):
    """Accept only closed identifiers/counts across the parser boundary."""
    if row.get('status')!='analyzed':
        status=row.get('status')
        return dict(status=status if status in {'unsupported_format','unsupported_link_type','analysis_failed'} else 'analysis_failed')
    out=dict(status='analyzed',source_authenticity='unverified',attack_status='unknown')
    if name=='scan_artifacts':
        names=row['matched_rule_ids']
        if type(names) is not list or len(names)>3 or any(n not in {'powershell_encoded_command','windows_shadow_copy_deletion','credential_dump_reference'} for n in names):raise ValueError
        out.update(matched_rule_ids=names,rules_evaluated=3,coverage='three_text_patterns_only',maliciousness='unqualified')
    else:
        keys=('packet_count','unique_endpoints','directed_flow_count','malformed_packets') if name=='inspect_packets' else ('record_count','unique_entities','five_failures_in_300s_groups','failure_burst_then_success_groups')
        for key in keys:
            if type(row[key]) is not int or not 0<=row[key]<=20000:raise ValueError
            out[key]=row[key]
        field='protocol_counts' if name=='inspect_packets' else 'outcome_counts'
        allowed={'tcp','udp','other_ip','non_ip','tcp_syn_without_ack','tcp_reset'} if name=='inspect_packets' else {'failure','success','blocked','observed'}
        counts=row[field]
        if type(counts) is not dict or not set(counts)<=allowed or any(type(n) is not int or not 0<=n<=10000 for n in counts.values()):raise ValueError
        out[field]=counts
        if name=='inspect_packets':
            duration=row['supplied_duration_seconds']
            if type(duration) not in {int,float} or not math.isfinite(duration) or not 0<=duration<=1e12:raise ValueError
            out['supplied_duration_seconds']=duration
        else:out['duplicates_deduplicated']=False
    return out


def facts_for(document,role):
    return dict(document,facts=[f for f in document['facts'] if f['type'] in ROLE_TYPES[role] or f['type']=='coverage'])


def native(name,document,role,ref_count):
    facts=document['facts']
    if name=='verify_sources':return dict(verified_artifact_count=ref_count-1,source_authenticity='unverified')
    if name=='inspect_timeline':
        times=sorted((f['event_time'] for f in facts),key=lambda t:datetime.fromisoformat(t.replace('Z','+00:00')))
        return dict(earliest=times[0],latest=times[-1],reported_as_of=document['as_of'],source_clock_verified=False)
    if name=='review_rules':
        result=analyze(role,document,'local-input')
        return dict(urgency=result['urgency'],observations=[r['statement'] for r in result['observations']],hypotheses=[r['statement'] for r in result['hypotheses']],qualified=False)
    if name=='assess_exposure':
        exposures=[f['data'] for f in facts if f['type']=='exposure']
        urgent=sum(d['severity'] in {'critical','high'} and d['reachable']=='yes' and d['mitigated']=='no' for d in exposures)
        return dict(urgent_exposure_count=urgent,exposure_count=len(exposures),
            urgency='urgent_review' if urgent else 'review',exploitation='not_established',coverage='supplied_facts_only')
    if name=='correlate_events':
        entities={f['entity_id'] for f in facts if f['entity_id']}
        activities=[f['data'] for f in facts if f['type']=='activity']
        return dict(fact_count=len(facts),unique_entities=len(entities),
            failure_fact_count=sum(a['outcome']=='failure' for a in activities),
            success_fact_count=sum(a['outcome']=='success' for a in activities),
            counts_may_overlap=True,attack_status='unknown')
    raise AccessDenied('specialist_tool_not_admitted')


def execute(service,token,case_id,input_evidence_id,role,name,*,job_id=None):
    role_name(role)
    if name not in TOOLS[role]:raise AccessDenied('specialist_tool_not_admitted')
    def scope(conn):
        p=service._human(conn,token,write=True,content=True)
        case=service._case(conn,p,case_id,open_only=True)
        if job_id is not None:
            from gabriel.identity.specialist_agents import job
            current=job(service,conn,p,job_id)
            if current['case_id']!=case['id'] or current['input_evidence_id']!=identifier(input_evidence_id) or current['role']!=role:
                raise AccessDenied('specialist_tool_job_mismatch')
        original,document,refs=verified_input(service,conn,p,case,identifier(input_evidence_id))
        return p,original,facts_for(document,role),refs
    with connection(service._dsn) as conn:
        p,original,document,refs=scope(conn)
        if not document['facts']:raise AccessDenied('specialist_tool_requires_role_evidence')
        binding=digest(document)
        sources=[]
        if name in REMOTE:
            eids=sorted({f['evidence_id'] for f in document['facts']})
            if len(eids)>8:raise AccessDenied('tool_requires_narrower_source_scope')
            total=0
            for eid in eids:
                row=service._evidence(conn,p,identifier(eid));body=service._verify(conn,row)
                total+=len(body)
                if len(body)>1048576 or total>4194304:raise AccessDenied('tool_source_byte_limit')
                sources.append((body,['o'+str(i) for i,f in enumerate(document['facts'],1) if f['evidence_id']==eid]))
        _audit(conn,'specialist_tool.started',p,original['id'])
    if name=='inspect_toolkit':result=remote(name)
    elif name in REMOTE:
        readiness=remote('inspect_toolkit')
        if readiness.get('packaged_tools_ready'):
            outputs=[]
            for data,references in sources:
                with connection(service._dsn) as conn:
                    _,_,current,_=scope(conn)
                    if digest(current)!=binding:raise AccessDenied('tool_source_changed')
                outputs.append(dict(remote(name,data),references=references))
            result=dict(artifacts=outputs,coverage='selected_sources_only')
        else:result=readiness
    elif name=='review_memory':
        from gabriel.identity.reviewed_memory import build
        with connection(service._dsn) as conn:
            p,_,current,_=scope(conn)
            memory_context=build(service,conn,p,service._case(conn,p,case_id),current,role)
        result=memory_context['result']
    else:result=native(name,document,role,len(refs))
    with connection(service._dsn) as conn:
        p,original,current,_=scope(conn)
        if digest(current)!=binding:raise AccessDenied('tool_source_changed')
        if name=='review_memory':
            from gabriel.identity.reviewed_memory import verify
            verify(service,conn,p,service._case(conn,p,case_id),current,role,
                dict(result=result,_reviewed_memory=dict(records=memory_context['records'],lineage=memory_context['lineage'])))
        _audit(conn,'specialist_tool.completed',p,original['id'])
    value=dict(tool=name,result=result)
    if name=='review_memory':value['_reviewed_memory']=dict(records=memory_context['records'],lineage=memory_context['lineage'])
    return value


def inspect(service,token,case_id,input_evidence_id,role,name,request_id):
    result=execute(service,token,case_id,input_evidence_id,role,name)
    artifact=service.acquire(token,case_id,request_id,canonical(dict(version=VERSION,role=role,
        input_evidence_id=str(input_evidence_id),tool_result=result,requires_review=True)).decode(),
        'Local investigation tool report',approved=True,parent_id=input_evidence_id)
    return dict(state='local_tool_report_ready_requires_review',report_evidence_id=artifact['id'],model_used=False,result=result)
