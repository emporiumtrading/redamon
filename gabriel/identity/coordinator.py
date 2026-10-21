"""Durable local-only coordination; no model/browser-navigation/response dispatch."""
from uuid import uuid4
from psycopg.types.json import Jsonb

from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.specialist_contracts import digest
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier

PLAN='local-coordinator-v1'
OPERATIONS=('evidence_inventory','telemetry_health')


def sources(service,conn,p,case_id,*,_exclude_ingestion=None):
    rows=conn.execute('''SELECT * FROM gabriel_identity.evidence_objects
        WHERE organization_id=%s AND case_id=%s
        AND (%s::uuid IS NULL OR ingestion_id<>%s::uuid) ORDER BY id LIMIT 65''',
        (p.organization_id,case_id,_exclude_ingestion,_exclude_ingestion)).fetchall()
    if len(rows)>64:
        raise AccessDenied('coordinator_source_limit')
    values=[]
    for row in rows:
        if row['state']!='ready' or service._disposition(conn,row):
            raise AccessDenied('coordinator_source_unavailable')
        values.append(dict(evidence_id=str(row['id']),digest=row['digest']))
    return values


def load(conn,p,run_id):
    row=conn.execute('''SELECT r.*,clock_timestamp()>=r.expires_at AS expired,
        (u.active AND m.active AND m.role IN ('owner','admin','analyst')) AS creator_current,
        EXISTS(SELECT 1 FROM gabriel_identity.coordinator_stops s
          WHERE (s.organization_id,s.run_id)=(r.organization_id,r.id)) AS stopped
        FROM gabriel_identity.coordinator_runs r
        JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(r.organization_id,r.requested_by)
        JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
        WHERE r.organization_id=%s AND r.id=%s''',(p.organization_id,identifier(run_id))).fetchone()
    if not row:
        raise AccessDenied('coordinator_not_accessible')
    return row


def control(p,row):
    if p.role not in {'owner','admin'} and not (p.role=='analyst' and p.user_id==row['requested_by']):
        raise AccessDenied('coordinator_control_denied')


def active(service,conn,p,row,*,_exclude_ingestion=None):
    control(p,row)
    service._case(conn,p,row['case_id'],open_only=True)
    at=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
    if row['stopped'] or not row['creator_current'] or row['expires_at']<=at:
        raise AccessDenied('coordinator_not_active')
    current=sources(service,conn,p,row['case_id'],_exclude_ingestion=_exclude_ingestion)
    recorded=conn.execute('''SELECT evidence_id,digest FROM gabriel_identity.coordinator_sources
        WHERE organization_id=%s AND run_id=%s ORDER BY evidence_id''',
        (p.organization_id,row['id'])).fetchall()
    expected=[dict(evidence_id=str(value['evidence_id']),digest=value['digest']) for value in recorded]
    if digest(current)!=row['source_digest'] or current!=expected:
        raise AccessDenied('coordinator_source_scope_changed')
    return current


def snapshot(conn,row):
    steps=conn.execute('''SELECT s.sequence,s.operation,c.created_at AS claimed_at,
        r.result,r.result_digest,r.created_at AS completed_at
        FROM gabriel_identity.coordinator_steps s
        LEFT JOIN gabriel_identity.coordinator_claims c USING(organization_id,run_id,sequence)
        LEFT JOIN gabriel_identity.coordinator_results r USING(organization_id,run_id,sequence)
        WHERE s.organization_id=%s AND s.run_id=%s ORDER BY s.sequence''',
        (row['organization_id'],row['id'])).fetchall()
    if [step['operation'] for step in steps]!=list(OPERATIONS[:row['max_steps']]):
        raise AccessDenied('coordinator_plan_integrity_failed')
    for step in steps:
        if step['result'] is not None and digest(step['result'])!=step['result_digest']:
            raise AccessDenied('coordinator_result_integrity_failed')
    completed=sum(step['completed_at'] is not None for step in steps)
    status=('stopped' if row['stopped'] else 'authority_lost' if not row['creator_current']
            else 'expired' if row['expired'] else 'local_plan_complete' if completed==row['max_steps'] else 'pending_local_steps')
    return dict(id=str(row['id']),case_id=str(row['case_id']),requested_by=str(row['requested_by']),plan_version=row['plan_version'],
        source_digest=row['source_digest'],created_at=iso(row['created_at']),expires_at=iso(row['expires_at']),
        status=status,max_steps=row['max_steps'],completed_steps=completed,
        steps=[dict(sequence=step['sequence'],operation=step['operation'],claimed_at=iso(step['claimed_at']),
            completed_at=iso(step['completed_at']),result_digest=step['result_digest'],result=step['result']) for step in steps],
        model_enabled=False,external_actions_enabled=False,incident_assessment='not_performed',
        coverage='partial',current_source_authority_checked=False)


def begin(service,token,case_id,request_id,*,max_steps=2,ttl_seconds=900):
    case_id,request_id=identifier(case_id),identifier(request_id)
    if type(max_steps) is not int or not 1<=max_steps<=2 or type(ttl_seconds) is not int or not 60<=ttl_seconds<=900:
        raise InvalidIdentityInput('invalid_coordinator_limits')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        old=conn.execute('''SELECT id,case_id,requested_by,max_steps,
            extract(epoch FROM expires_at-created_at)::integer AS ttl FROM gabriel_identity.coordinator_runs
            WHERE organization_id=%s AND request_id=%s''',(p.organization_id,request_id)).fetchone()
        if old:
            if (old['case_id'],old['requested_by'],old['max_steps'],old['ttl'])!=(case_id,p.user_id,max_steps,ttl_seconds):
                raise AccessDenied('coordinator_request_conflict')
            _audit(conn,'coordinator.plan_replayed',p,old['id'])
            return snapshot(conn,load(conn,p,old['id']))
        count=conn.execute('''SELECT count(*) AS n FROM gabriel_identity.coordinator_runs
            WHERE organization_id=%s AND case_id=%s''',(p.organization_id,case_id)).fetchone()['n']
        if count>=128:
            raise AccessDenied('coordinator_case_plan_limit')
        selected=sources(service,conn,p,case['id'])
        rid=uuid4()
        conn.execute('''INSERT INTO gabriel_identity.coordinator_runs
            (organization_id,id,case_id,request_id,requested_by,plan_version,source_digest,max_steps,created_at,expires_at)
            SELECT %s,%s,%s,%s,%s,%s,%s,%s,t,t+%s*interval '1 second'
            FROM (SELECT clock_timestamp() AS t) admitted''',
            (p.organization_id,rid,case_id,request_id,p.user_id,PLAN,digest(selected),max_steps,ttl_seconds))
        for source in selected:
            conn.execute('''INSERT INTO gabriel_identity.coordinator_sources VALUES (%s,%s,%s,%s,%s)''',
                (p.organization_id,rid,case_id,source['evidence_id'],source['digest']))
        for sequence,operation in enumerate(OPERATIONS[:max_steps],1):
            conn.execute('''INSERT INTO gabriel_identity.coordinator_steps VALUES (%s,%s,%s,%s,%s)''',
                (p.organization_id,rid,sequence,operation,uuid4()))
        _audit(conn,'coordinator.plan_created',p,rid)
        return snapshot(conn,load(conn,p,rid))


def get(service,token,run_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        row=load(conn,p,run_id)
        service._case(conn,p,row['case_id'])
        _audit(conn,'coordinator.plan_read',p,row['id'])
        return snapshot(conn,row)


def history(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        case=service._case(conn,p,case_id)
        rows=conn.execute('''SELECT id FROM gabriel_identity.coordinator_runs
            WHERE organization_id=%s AND case_id=%s ORDER BY created_at DESC,id LIMIT 33''',
            (p.organization_id,case['id'])).fetchall()
        summaries=[]
        for row in rows[:32]:
            value=snapshot(conn,load(conn,p,row['id']))
            summaries.append({k:v for k,v in value.items() if k!='steps'})
        _audit(conn,'coordinator.history_read',p,case['id'])
        return dict(runs=summaries,truncated=len(rows)>32)


def stop(service,token,run_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        row=load(conn,p,run_id)
        control(p,row)
        conn.execute('''INSERT INTO gabriel_identity.coordinator_stops VALUES (%s,%s,%s,clock_timestamp())
            ON CONFLICT (organization_id,run_id) DO NOTHING''',(p.organization_id,row['id'],p.user_id))
        _audit(conn,'coordinator.stopped',p,row['id'])
        return snapshot(conn,load(conn,p,row['id']))


def execute_local(service,token,row,step,selected):
    if step['operation']=='evidence_inventory':
        return dict(operation='evidence_inventory',sources=selected,content_integrity='not_checked',
                    source_authenticity='unverified',independent_corroboration='not_established')
    if step['operation']=='telemetry_health':
        result=service.run_specialist(token,row['case_id'],step['request_id'],'telemetry_health')
        return dict(operation='telemetry_health',specialist_id=result['id'],
                    specialist_result_digest=result['result_digest'],incident_assessment='not_performed')
    raise AccessDenied('coordinator_operation_not_enabled')


def advance(service,token,run_id,*,expected_sequence=None):
    if expected_sequence is not None and (type(expected_sequence) is not int or expected_sequence not in {1,2}):
        raise InvalidIdentityInput('invalid_coordinator_sequence')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        row=load(conn,p,run_id)
        selected=active(service,conn,p,row)
        snapshot(conn,row)
        step=conn.execute('''SELECT s.* FROM gabriel_identity.coordinator_steps s
            WHERE s.organization_id=%s AND s.run_id=%s AND NOT EXISTS
            (SELECT 1 FROM gabriel_identity.coordinator_results r
              WHERE (r.organization_id,r.run_id,r.sequence)=(s.organization_id,s.run_id,s.sequence))
            ORDER BY s.sequence LIMIT 1''',(p.organization_id,row['id'])).fetchone()
        if not step or (expected_sequence is not None and step['sequence']!=expected_sequence):
            return snapshot(conn,row)
        conn.execute('''INSERT INTO gabriel_identity.coordinator_claims
            (organization_id,run_id,sequence,claimed_by) VALUES (%s,%s,%s,%s)
            ON CONFLICT (organization_id,run_id,sequence) DO NOTHING''',
            (p.organization_id,row['id'],step['sequence'],p.user_id))
        _audit(conn,'coordinator.local_step_claimed',p,row['id'])
    # Only idempotent local operations are admitted. A crash can safely replay the
    # same specialist request, but this protocol must never wrap external effects.
    result=execute_local(service,token,row,step,selected)
    if len(canonical(result))>131072:
        raise AccessDenied('coordinator_result_limit')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        row=load(conn,p,run_id)
        current=active(service,conn,p,row)
        if step['operation']=='evidence_inventory':
            expected=dict(operation='evidence_inventory',sources=current,content_integrity='not_checked',
                source_authenticity='unverified',independent_corroboration='not_established')
            if result!=expected:
                raise AccessDenied('coordinator_result_binding_failed')
        else:
            specialist=conn.execute('''SELECT id,result_digest FROM gabriel_identity.specialist_runs
                WHERE organization_id=%s AND case_id=%s AND request_id=%s AND role='telemetry_health' ''',
                (p.organization_id,row['case_id'],step['request_id'])).fetchone()
            if not specialist or result!=dict(operation='telemetry_health',specialist_id=str(specialist['id']),
                    specialist_result_digest=specialist['result_digest'],incident_assessment='not_performed'):
                raise AccessDenied('coordinator_result_binding_failed')
        receipt=conn.execute('''SELECT 1 FROM gabriel_identity.coordinator_results
            WHERE organization_id=%s AND run_id=%s AND sequence=%s''',
            (p.organization_id,row['id'],step['sequence'])).fetchone()
        if not receipt:
            conn.execute('''INSERT INTO gabriel_identity.coordinator_results
                (organization_id,run_id,sequence,result,result_digest,completed_by) VALUES (%s,%s,%s,%s,%s,%s)''',
                (p.organization_id,row['id'],step['sequence'],Jsonb(result),digest(result),p.user_id))
            _audit(conn,'coordinator.local_step_completed',p,row['id'])
        return snapshot(conn,load(conn,p,row['id']))
