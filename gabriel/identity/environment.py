"""Bounded case environment views over reviewed, untrusted typed evidence."""
from gabriel.identity.attack_pattern_runs import GAPS,public
from gabriel.identity.attack_patterns import normalized
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,_audit,connection,identifier
from gabriel.identity.specialist_analysis import at,require
from gabriel.identity.specialist_contracts import digest

VERSION='case-environment-view-v1'


def view(service,token,case_id,*,include_identifiers=False):
    if type(include_identifiers) is not bool: raise AccessDenied('explicit_environment_content_scope_required')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,content=include_identifiers)
        case=service._case(conn,p,case_id)
        rows=conn.execute('''SELECT * FROM gabriel_identity.attack_pattern_runs WHERE organization_id=%s AND case_id=%s
            ORDER BY created_at DESC,id DESC LIMIT 2''',(p.organization_id,case['id'])).fetchall()
        result=dict(version=VERSION,case_id=str(case['id']),coverage='partial',source_authenticity='unverified',
            current_environment_verified=False,live_coverage_verified=False,security_effectiveness_validated=False,
            compliance_assessed=False,control_evidence_state='unknown_stale',ownership_state='unknown',
            recovery_dependencies_state='unknown',source_bytes_checked=False,identifiers_included=False,
            source_clock_ahead=None,window='latest_reviewed_snapshot',older_snapshots_omitted=len(rows)>1,controls=[],assets=[],identities=[],relationships=[])
        if not rows:
            result.update(status='no_supported_snapshot',snapshot=None,missing_sources=sorted(GAPS))
        else:
            review=public(rows[0]);packet=review['packet']
            result.update(status='metadata_only',snapshot=dict(review_id=review['id'],review_created_at=review['created_at'],
                supplied_as_of=packet['as_of'],input_evidence_id=packet['input_evidence_id'],input_digest=packet['input_digest'],
                unique_event_count=review['result']['unique_event_count'],forwarded_duplicate_count=review['result']['forwarded_duplicate_count']),
                missing_sources=review['result']['missing_sources'])
            result['source_clock_ahead']=at(packet['as_of'])>conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            if include_identifiers:
                sources={}
                for ref in packet['references']:
                    eid=identifier(ref['record_id']);row=service._evidence(conn,p,eid)
                    if row['case_id']!=case['id'] or row['digest']!=ref['digest']:
                        raise AccessDenied('environment_source_binding_mismatch')
                    if row['source_kind']=='model_generated_text' or conn.execute('''SELECT 1 FROM gabriel_identity.model_answer_intents
                            WHERE organization_id=%s AND ingestion_id=%s''',(p.organization_id,row['ingestion_id'])).fetchone():
                        raise AccessDenied('model_answer_is_not_environment_source')
                    body=service._verify(conn,row);service._custody(conn,p,row,'accessed')
                    sources[str(eid)]=(row,body)
                document=decode(sources[packet['input_evidence_id']][1].decode('utf-8'))
                events=normalized(document,case['id'])
                expected={event['evidence_id']:event['evidence_digest'] for event in document['events']}
                if (set(sources)!={packet['input_evidence_id']}|set(expected) or packet['input_evidence_id'] in expected
                        or digest(document['events'])!=packet['events_digest'] or document['as_of']!=packet['as_of']
                        or len(events)!=review['result']['unique_event_count'] or document['missing_sources']!=result['missing_sources']
                        or any(sources[eid][0]['digest']!=value for eid,value in expected.items())):
                    raise AccessDenied('environment_source_binding_mismatch')
                assets={};identities={};relationships={}
                def entity(target,key,event):
                    item=target.setdefault(key,dict(id=key,evidence_state='reported',owner=None,source_verified=False,
                        event_count=0,first_event_time=event['event_time'],last_event_time=event['event_time'],references=set()))
                    item['event_count']+=1;item['references'].update(event['references'])
                    if at(event['event_time'])<at(item['first_event_time']): item['first_event_time']=event['event_time']
                    if at(event['event_time'])>at(item['last_event_time']): item['last_event_time']=event['event_time']
                    return item
                for event in events:
                    for asset in {event['asset_id'],event['source_asset_id']}-{None}: entity(assets,asset,event)
                    if event['actor_id'] is not None: entity(identities,event['actor_id'],event)
                    if event['source_asset_id'] and event['source_asset_id']!=event['asset_id']:
                        key=(event['source_asset_id'],event['asset_id'])
                        link=relationships.setdefault(key,dict(source=key[0],target=key[1],kind='reported_event_path',
                            event_count=0,event_kinds=set(),references=set(),source_verified=False))
                        link['event_count']+=1;link['event_kinds'].add(event['kind']);link['references'].update(event['references'])
                require(len(assets)<=128 and len(identities)<=128 and len(relationships)<=128,'environment_scope_requires_narrower_snapshot')
                def records(values):
                    return [{key:sorted(value) if isinstance(value,set) else value for key,value in row.items()}
                            for _,row in sorted(values.items())]
                result.update(status='bounded_historical_snapshot',source_bytes_checked=True,identifiers_included=True,
                    assets=records(assets),identities=records(identities),relationships=records(relationships))
        require(len(canonical(result))<=262144,'environment_profile_limit')
        _audit(conn,'environment.profile_content_read' if include_identifiers else 'environment.profile_metadata_read',p,case['id'])
        return dict(profile=result,digest=digest(result))
