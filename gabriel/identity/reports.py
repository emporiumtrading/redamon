"""Audited metadata-only case snapshots; timelines do not establish source truth."""
from collections import defaultdict
from hashlib import sha256
from uuid import uuid4

from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import AccessDenied,_audit,connection

MAX_TIMELINE = 4096


def case_report(service,token,case_id):
    with connection(service._dsn) as conn:
        principal = service._human(conn,token)
        case = service._case(conn,principal,case_id)
        rows = conn.execute('''SELECT * FROM gabriel_identity.evidence_objects
            WHERE organization_id=%s AND case_id=%s ORDER BY observed_at,id LIMIT 65''',
            (principal.organization_id,case['id'])).fetchall()
        if len(rows)>64:
            raise AccessDenied('case_report_limit')
        entries,artifacts,duplicates = [],[],defaultdict(list)
        entries.append(dict(id='case/'+str(case['id']),kind='case_created',time=iso(case['created_at']),
            time_basis='server_recorded',evidence_id=None))
        for row in rows:
            evidence_id = str(row['id'])
            chain = service._chain(conn,row)
            if len(entries)+len(chain)+2>MAX_TIMELINE:
                raise AccessDenied('case_report_limit')
            disposition = service._disposition(conn,row)
            storage = 'active' if not disposition else 'purged' if disposition['state']=='completed' else 'disposition_pending'
            artifacts.append(dict(id=evidence_id,digest=row['digest'],byte_length=row['byte_length'],
                state=row['state'],storage_state=storage,source_kind=row['source_kind'],source_label=row['source_label'],
                parser_version=row['parser_version'],schema_version=row['schema_version'],redaction_state=row['redaction_state'],
                parent_id=str(row['parent_id']) if row['parent_id'] else None,source_verified=False,
                custody_chain='validated',content_integrity='not_checked',source_event_time=iso(row['source_event_time']),
                collected_at=iso(row['observed_at'])))
            duplicates[(row['digest'],row['byte_length'])].append(evidence_id)
            entries.append(dict(id='collection/'+evidence_id,kind='evidence_collected',time=iso(row['observed_at']),
                time_basis='server_recorded',evidence_id=evidence_id))
            if row['source_event_time']:
                entries.append(dict(id='source/'+evidence_id,kind='source_event_claim',time=iso(row['source_event_time']),
                    time_basis='unverified_supplied',evidence_id=evidence_id))
            for event in chain:
                entries.append(dict(id='custody/'+evidence_id+'/'+str(event['sequence']),kind='custody_'+event['event'],
                    time=iso(event['created_at']),time_basis='server_recorded',evidence_id=evidence_id,
                    sequence=event['sequence'],actor_id=str(event['actor_id']),event_hash=event['event_hash']))
        browser = conn.execute('''SELECT o.id,o.evidence_id,o.observed_at,o.created_at,o.visibility,o.state,
                l.id AS lease_id,l.browser,l.extension_version
            FROM gabriel_identity.browser_observations o JOIN gabriel_identity.browser_leases l
                ON l.organization_id=o.organization_id AND l.id=o.lease_id
            WHERE l.organization_id=%s AND l.case_id=%s ORDER BY o.created_at,o.id LIMIT 1001''',
            (principal.organization_id,case['id'])).fetchall()
        if len(browser)>1000 or len(entries)+len(browser)>MAX_TIMELINE:
            raise AccessDenied('case_report_limit')
        observations = []
        for row in browser:
            evidence_id = str(row['evidence_id']) if row['evidence_id'] else None
            observations.append(dict(id=str(row['id']),evidence_id=evidence_id,lease_id=str(row['lease_id']),
                browser=row['browser'],extension_version=row['extension_version'],state=row['state'],
                visibility=row['visibility'],coverage='partial',source_verified=False,
                client_observed_at=iso(row['observed_at']),server_received_at=iso(row['created_at'])))
            entries.append(dict(id='browser/'+str(row['id']),kind='browser_observation_claim',
                time=iso(row['observed_at']),time_basis='unverified_client_clock',evidence_id=evidence_id))
        tasks = conn.execute('''SELECT task_id FROM gabriel_identity.case_tasks
            WHERE organization_id=%s AND case_id=%s ORDER BY task_id LIMIT 1001''',
            (principal.organization_id,case['id'])).fetchall()
        if len(tasks)>1000:
            raise AccessDenied('case_report_limit')
        snapshot = dict(schema_version=1,purpose='case-metadata-report-v1',report_id=str(uuid4()),
            organization_id=str(principal.organization_id),generated_at=iso(conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']),
            case=dict(id=str(case['id']),title=case['title'],state=case['state'],purpose=case.get('purpose','investigation'),created_at=iso(case['created_at'])),
            evidence=artifacts,browser_observations=observations,task_ids=[str(row['task_id']) for row in tasks],
            timeline=sorted(entries,key=lambda event:(event['time'],event['id'])),
            identical_artifacts=[dict(digest=digest,byte_length=length,evidence_ids=ids,
                meaning='identical_bytes_not_independent_corroboration') for (digest,length),ids in sorted(duplicates.items()) if len(ids)>1],
            coverage='partial',assessment='not_performed',content_integrity='not_checked',
            limitations=['Metadata snapshot, not an incident conclusion or proof of attacker absence.',
                'Artifact equality does not establish that underlying events are identical or independent.',
                'Source times and browser observations are unverified; clock skew is not corrected.',
                'Custody hash validation does not authenticate the source or verify stored content bytes.',
                'No evidence bodies, credentials, object paths or encryption key identifiers are included.'])
        _audit(conn,'case.report_generated',principal,case['id'])
        return dict(snapshot=snapshot,digest=sha256(canonical(snapshot)).hexdigest(),digest_scope='canonical_snapshot_utf8')
