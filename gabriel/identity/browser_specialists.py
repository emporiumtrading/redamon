"""Project captured event assertions into twelve local reviews without provider dispatch."""
import time
from uuid import uuid5

from psycopg.types.json import Jsonb

from gabriel.identity import browser_events
from gabriel.identity.attack_patterns import normalized
from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,_audit,connection,identifier
from gabriel.identity.specialist_analysis import at,require,validate_document
from gabriel.identity.specialist_analysis_runs import run_in_connection,verified_input
from gabriel.identity.specialist_contracts import ROLES,digest

VERSION='browser-specialist-facts-v1'
ACTIVITY={'auth_failure':('authentication','failure'),'auth_success':('authentication','success'),
    'remote_execution':('process','observed'),'file_write':('file','observed'),'file_rename':('file','observed'),
    'ransom_note':('file','observed')}


def project(document,observation_id):
    observation_id=identifier(observation_id)
    events=normalized(document,document['case_id'])
    groups={};sources={row['evidence_id']:row['evidence_digest'] for row in document['events']};facts=[];unmapped=0
    def add(kind,eid,entity,when,data,key):
        facts.append(dict(id=str(uuid5(observation_id,VERSION+'/'+key)),type=kind,evidence_id=eid,
            evidence_digest=sources[eid],entity_id=entity,event_time=when,data=data))
    for row in events:
        row=dict(row,evidence_id=min(row['references']).removeprefix('evidence/'))
        if row['kind'] not in ACTIVITY:
            unmapped+=1;continue
        category,outcome=ACTIVITY[row['kind']]
        actor=row['actor_id'] if category=='authentication' else None
        key=(row['evidence_id'],category,outcome,actor,row['asset_id'])
        group=groups.setdefault(key,dict(count=0,when=row['event_time']))
        group['count']+=1
        if at(row['event_time'])>at(group['when']): group['when']=row['event_time']
    for index,(key,group) in enumerate(sorted(groups.items(),key=lambda item:canonical(item[0]))):
        eid,category,outcome,actor,asset=key
        add('activity',eid,asset,group['when'],dict(category=category,outcome=outcome,count=group['count']),'activity/'+str(index))
        if category=='authentication':
            # A page's approval assertion cannot establish action authorization.
            event='login_success' if outcome=='success' else 'login_failure'
            add('identity',eid,actor,group['when'],dict(event=event,authorized='unknown'),'identity/'+str(index))
    for eid in sorted(sources):
        add('artifact',eid,None,document['as_of'],dict(integrity='match',custody='unknown'),'artifact/'+eid)
    if document['missing_sources'] or unmapped:
        eid=min(sources)
        add('coverage',eid,None,document['as_of'],dict(state='missing'),'coverage')
    value=dict(version='specialist-facts-v1',case_id=document['case_id'],as_of=document['as_of'],facts=facts)
    validate_document(value,document['case_id'])
    return value,dict(unique_event_count=len(events),unmapped_event_count=unmapped,fact_count=len(facts))


def process(service,human,peer,context,observation_id):
    observation_id=identifier(observation_id)
    deadline=time.monotonic()+10
    def within_budget():
        if time.monotonic()>deadline: raise AccessDenied('browser_specialist_time_budget')
    # Replaying normalization still checks actual original ciphertext and custody.
    review=browser_events.process(service,human,peer,context,observation_id)
    def bound(conn): return browser_events.admitted(service,conn,human,peer,context)
    with connection(service._dsn) as conn:
        p,lease=bound(conn)
        observation=service._observation(conn,p,observation_id)
        if observation['lease_id']!=lease['id']: raise AccessDenied('browser_specialist_scope_changed')
        original=service._evidence(conn,p,review['normalized_evidence_id'])
        if original['case_id']!=lease['case_id']: raise AccessDenied('browser_specialist_scope_changed')
        document=decode(service._verify(conn,original).decode('utf-8'))
        service._custody(conn,p,original,'accessed')
        projected,counts=project(document,observation_id)
        snapshot=conn.execute('SELECT * FROM gabriel_identity.browser_event_snapshots WHERE organization_id=%s AND observation_id=%s',
            (p.organization_id,observation_id)).fetchone()
        if not snapshot or snapshot['case_id']!=lease['case_id']: raise AccessDenied('browser_specialist_snapshot_missing')
        source_digest=snapshot['source_digest'];case_id=lease['case_id'];normalized_id=original['id']
    within_budget()
    holder=service.acquire(human,case_id,uuid5(observation_id,VERSION),canonical(projected).decode('utf-8'),
        'Browser specialist fact projection',approved=True,parent_id=normalized_id,redaction_state='user_declared_redacted')
    with connection(service._dsn) as conn:
        within_budget()
        p,lease=bound(conn)
        case=service._case(conn,p,case_id,open_only=True)
        normalized_source=service._evidence(conn,p,normalized_id)
        repeated=decode(service._verify(conn,normalized_source).decode('utf-8'))
        if normalized_source['case_id']!=case_id or project(repeated,observation_id)!=(projected,counts):
            raise AccessDenied('browser_specialist_projection_mismatch')
        service._custody(conn,p,normalized_source,'accessed')
        original,current,_=verified_input(service,conn,p,case,identifier(holder['id']))
        if current!=projected or original['digest']!=digest(projected): raise AccessDenied('browser_specialist_projection_mismatch')
        old=conn.execute('SELECT * FROM gabriel_identity.browser_specialist_suites WHERE organization_id=%s AND observation_id=%s',
            (p.organization_id,observation_id)).fetchone()
        if old:
            if (old['case_id'],old['lease_id'],old['created_by'],old['normalized_evidence_id'],old['facts_evidence_id'],
                    old['source_digest'],old['facts_digest'],old['projector_version'])!=(case_id,lease['id'],p.user_id,normalized_id,
                    identifier(holder['id']),source_digest,digest(projected),VERSION) or digest(old['result'])!=old['result_digest']:
                raise AccessDenied('browser_specialist_receipt_mismatch')
            saved=old['result']
            if (set(saved.get('specialists',{}))!=set(ROLES) or saved.get('specialist_count')!=12
                    or any(saved.get(key) is not False for key in ('source_verified','quality_qualified','external_actions_authorized'))
                    or saved.get('model_cost_usd')!='0' or saved.get('facts_evidence_id')!=str(holder['id'])
                    or saved.get('attack_review_id')!=review['review_id']
                    or any(saved.get(key)!=value for key,value in counts.items())):
                raise AccessDenied('browser_specialist_receipt_mismatch')
            from gabriel.identity.specialists import public_run
            for role in ROLES:
                within_budget()
                expected=old['result']['specialists'][role]
                row=conn.execute('SELECT * FROM gabriel_identity.specialist_runs WHERE organization_id=%s AND id=%s',
                    (p.organization_id,identifier(expected['id']))).fetchone()
                if (not row or row['case_id']!=case_id or row['requested_by']!=p.user_id or row['role']!=role
                        or row['request_id']!=uuid5(observation_id,VERSION+'/'+role)
                        or row['packet'].get('input_evidence_id')!=str(holder['id'])
                        or row['result']['incident_assessment']!=expected['assessment']
                        or public_run(row)['result_digest']!=expected['result_digest']):
                    raise AccessDenied('browser_specialist_result_mismatch')
            if saved.get('abstained_count')!=sum(row['assessment']=='abstained' for row in saved['specialists'].values()):
                raise AccessDenied('browser_specialist_receipt_mismatch')
            within_budget();bound(conn)
            _audit(conn,'browser.specialist_suite_replayed',p,observation_id)
            return old['result']
        n=conn.execute('SELECT count(*) AS n FROM gabriel_identity.specialist_runs WHERE organization_id=%s AND case_id=%s',
            (p.organization_id,case_id)).fetchone()['n']
        if n+len(ROLES)>128: raise AccessDenied('case_specialist_run_limit')
        results={}
        for role in ROLES:
            within_budget()
            bound(conn)
            run=run_in_connection(service,conn,p,case,uuid5(observation_id,VERSION+'/'+role),role,holder['id'])
            results[role]=dict(id=run['id'],result_digest=run['result_digest'],assessment=run['result']['incident_assessment'])
        within_budget();bound(conn)
        result=dict(suite_id=str(uuid5(observation_id,VERSION+'/suite')),observation_id=str(observation_id),case_id=str(case_id),
            attack_review_id=review['review_id'],facts_evidence_id=str(holder['id']),projector_version=VERSION,
            specialists=results,specialist_count=len(results),abstained_count=sum(row['assessment']=='abstained' for row in results.values()),
            **counts,coverage='partial',source_verified=False,quality_qualified=False,external_actions_authorized=False,
            model_cost_usd='0',created_at=iso(conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']))
        conn.execute('''INSERT INTO gabriel_identity.browser_specialist_suites
            (organization_id,observation_id,case_id,lease_id,created_by,projector_version,normalized_evidence_id,facts_evidence_id,
             source_digest,facts_digest,result,result_digest) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (p.organization_id,observation_id,case_id,lease['id'],p.user_id,VERSION,normalized_id,holder['id'],
             source_digest,digest(projected),Jsonb(result),digest(result)))
        _audit(conn,'browser.specialist_suite_completed',p,observation_id)
        return result
