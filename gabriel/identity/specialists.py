"""Persisted deterministic telemetry assessment; no model or external action dispatch."""
import time
from uuid import uuid4
from psycopg.types.json import Jsonb

from gabriel.identity.analyst_views import source_health
from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.specialist_contracts import CONTRACT_VERSION,catalog,digest,role_name,validate_result
from gabriel.identity.service import AccessDenied,_audit,connection,identifier


def public_run(row):
    if (digest(row['packet'])!=row['packet_digest'] or digest(row['result'])!=row['result_digest']
            or row['packet'].get('organization_id')!=str(row['organization_id'])
            or row['packet'].get('case_id')!=str(row['case_id']) or row['packet'].get('role')!=row['role']):
        raise AccessDenied('specialist_record_integrity_failed')
    validate_result(row['packet'],row['result'])
    if row['engine_version']!=row['result']['execution']['engine']:
        raise AccessDenied('specialist_record_integrity_failed')
    return dict(id=str(row['id']),case_id=str(row['case_id']),role=row['role'],requested_by=str(row['requested_by']),
        created_at=iso(row['created_at']),packet=row['packet'],result=row['result'],packet_digest=row['packet_digest'],
        result_digest=row['result_digest'],time_basis=('historical_typed_snapshot' if row['packet']['schema_version']==2 else 'historical_individual_samples'),grants_authority=False)


def get_run(service,token,case_id,run_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        case=service._case(conn,p,case_id)
        row=conn.execute('''SELECT * FROM gabriel_identity.specialist_runs
            WHERE organization_id=%s AND case_id=%s AND id=%s''',(p.organization_id,case['id'],identifier(run_id))).fetchone()
        if not row: raise AccessDenied('specialist_run_not_accessible')
        value=public_run(row)
        _audit(conn,'specialist.run_read',p,row['id'])
        return value


def list_runs(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        case=service._case(conn,p,case_id)
        rows=conn.execute('''SELECT id,role,engine_version,created_at FROM gabriel_identity.specialist_runs
            WHERE organization_id=%s AND case_id=%s ORDER BY created_at DESC,id DESC LIMIT 51''',(p.organization_id,case['id'])).fetchall()
        return dict(runs=[dict(id=str(row['id']),role=row['role'],engine_version=row['engine_version'],created_at=iso(row['created_at'])) for row in rows[:50]],
            truncated=len(rows)>50,limit=50,catalog=catalog())


def _replay(conn,p,case,request_id,role):
    row=conn.execute('''SELECT * FROM gabriel_identity.specialist_runs
        WHERE organization_id=%s AND case_id=%s AND request_id=%s''',(p.organization_id,case['id'],request_id)).fetchone()
    if row and (row['requested_by']!=p.user_id or row['role']!=role): raise AccessDenied('specialist_request_conflict')
    return row


def run_specialist(service,token,case_id,request_id,role,*,input_evidence_id=None):
    if input_evidence_id is not None:
        from gabriel.identity.specialist_analysis_runs import run
        return run(service,token,case_id,request_id,role,input_evidence_id)
    role,request_id=role_name(role),identifier(request_id)
    if role!='telemetry_health': raise AccessDenied('specialist_engine_not_enabled')
    started=time.monotonic()
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        existing=_replay(conn,p,case,request_id,role)
        if existing:
            _audit(conn,'specialist.run_replayed',p,existing['id'])
            return public_run(existing)
        _audit(conn,'specialist.sampling_started',p,case['id'])
    # Sampling calls lock the tenant independently; never nest them under a held tenant lock.
    health=source_health(service,token,case['id'])
    report=service.case_report(token,case['id'])['snapshot']
    refs=[dict(ref='case/'+str(case['id']),kind='case_record',record_id=str(case['id']))]
    refs.extend(dict(ref='evidence/'+row['id'],kind='evidence_metadata',record_id=row['id'],digest=row['digest'],
        source_verified=False,content_integrity='not_checked') for row in report['evidence'])
    refs.extend(dict(ref='browser_lease/'+row['id'],kind='browser_lease_sample',record_id=row['id'],sample=row) for row in health['sources'])
    packet=dict(schema_version=1,purpose='specialist-input-v1',contract_version=CONTRACT_VERSION,role=role,
        organization_id=report['organization_id'],case_id=str(case['id']),generated_at=report['generated_at'],
        references=refs,source_limit=health['limit'],sources_truncated=health['truncated'],coverage='partial',
        sampling='individual_live_checks',evidence_bodies_included=False)
    if len(canonical(packet))>131072:
        raise AccessDenied('specialist_packet_limit')
    observations=[dict(statement='Browser session sample: '+row['health']+'.',references=['browser_lease/'+row['id']],source_verified=False) for row in health['sources']]
    if not observations:
        observations=[dict(statement='No browser lease is recorded for this case in the sampled set.',references=['case/'+str(case['id'])],source_verified=False)]
    result=dict(schema_version=1,purpose='specialist-result-v1',contract_version=CONTRACT_VERSION,role=role,
        observations=observations,hypotheses=[],contradictions=[],
        alternatives=[dict(statement='Browser inactivity or session expiry can explain a coverage gap; it does not establish attacker activity.',
            references=['case/'+str(case['id'])],source_verified=False)],
        uncertainty=['Page visibility and source authenticity are unverified.',
            'Samples are historical, individually checked and partial; an attacker assessment was not performed.']+
            (['Older browser sessions were omitted from the bounded sample.'] if health['truncated'] else []),
        next_steps=['review_browser_scope','review_source_visibility'],coverage='partial',incident_assessment='not_performed',attack_status='unknown',
        execution=dict(engine='telemetry-health-v1',provider=None,model=None,prompt_version=None,playbook_version='telemetry-health-v1',
            tools=[dict(name='source_health',version='source-health-v1')],model_cost_usd='0',elapsed_ms=int((time.monotonic()-started)*1000)))
    validate_result(packet,result)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        existing=_replay(conn,p,case,request_id,role)
        if existing:
            _audit(conn,'specialist.run_replayed',p,existing['id'])
            return public_run(existing)
        count=conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE organization_id=%s AND case_id=%s',
            (p.organization_id,case['id'])).fetchone()['n']
        if count>=128: raise AccessDenied('case_specialist_run_limit')
        row=conn.execute('''INSERT INTO gabriel_identity.specialist_runs
            (organization_id,id,case_id,request_id,requested_by,role,engine_version,packet,result,packet_digest,result_digest)
            VALUES (%s,%s,%s,%s,%s,%s,'telemetry-health-v1',%s,%s,%s,%s) RETURNING *''',
            (p.organization_id,uuid4(),case['id'],request_id,p.user_id,role,Jsonb(packet),Jsonb(result),digest(packet),digest(result))).fetchone()
        _audit(conn,'specialist.run_completed',p,row['id'])
        return public_run(row)
