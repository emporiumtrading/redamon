"""Explicitly reviewed reference data over encrypted evidence; never executable authority."""
import re
from uuid import uuid4

from gabriel.identity.cases import iso,timestamp
from gabriel.identity.evidence_store import EvidenceContent
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier


def _epoch(conn,p):
    return conn.execute('SELECT coalesce(max(sequence),0) AS n FROM gabriel_identity.memory_resets WHERE organization_id=%s',
        (p.organization_id,)).fetchone()['n']


def _scope(p,scope):
    if scope not in {'case','organization'}: raise InvalidIdentityInput('invalid_memory_scope')
    if scope=='organization' and p.role not in {'owner','admin'}: raise AccessDenied('organization_memory_admin_required')


def _record(conn,p,memory_id):
    row=conn.execute('''SELECT m.*,r.decision,r.reviewed_by,r.created_at AS reviewed_at,
        r.source_digest AS review_digest,x.memory_id AS forgotten,
        EXISTS(SELECT 1 FROM gabriel_identity.memory_records c WHERE c.organization_id=m.organization_id AND c.supersedes=m.id) AS has_correction
        FROM gabriel_identity.memory_records m LEFT JOIN gabriel_identity.memory_reviews r
            ON (r.organization_id,r.memory_id)=(m.organization_id,m.id)
        LEFT JOIN gabriel_identity.memory_invalidations x ON (x.organization_id,x.memory_id)=(m.organization_id,m.id)
        WHERE m.organization_id=%s AND m.id=%s''',(p.organization_id,identifier(memory_id))).fetchone()
    if not row: raise AccessDenied('memory_not_accessible')
    return row


def _active(conn,p,user):
    return bool(user and conn.execute('''SELECT 1 FROM gabriel_identity.memberships m JOIN gabriel_identity.users u
        ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
        WHERE m.organization_id=%s AND m.user_id=%s AND m.active AND u.active AND m.role IN ('owner','admin','analyst')''',
        (p.organization_id,user)).fetchone())


def _status(service,conn,p,row,epoch,now):
    if service._case(conn,p,row['case_id'])['purpose']=='performance_test':return 'performance_test_excluded'
    if row['epoch']!=epoch: return 'reset'
    if row['forgotten']: return 'forgotten'
    if row['has_correction']: return 'superseded'
    if row['expires_at']<=now: return 'expired'
    if row['decision']=='rejected': return 'rejected'
    if not _active(conn,p,row['proposed_by']): return 'authority_unavailable'
    if row['decision'] is None: return 'proposed'
    if not _active(conn,p,row['reviewed_by']): return 'authority_unavailable'
    source=service._evidence(conn,p,row['evidence_id'])
    if (source['state']!='ready' or source['digest']!=row['source_digest'] or row['review_digest']!=row['source_digest']
            or not _active(conn,p,source['acquired_by']) or service._disposition(conn,source)):
        return 'source_unavailable'
    return 'eligible_pending_content_check'


def _metadata(row,status):
    return dict(id=str(row['id']),case_id=str(row['case_id']),evidence_id=str(row['evidence_id']),kind=row['kind'],scope=row['scope'],
        topic=row['topic'],sensitivity=row['sensitivity'],epoch=row['epoch'],source_digest=row['source_digest'],
        proposed_by=str(row['proposed_by']),reviewed_by=str(row['reviewed_by']) if row['reviewed_by'] else None,
        self_review=bool(row['reviewed_by'] and row['reviewed_by']==row['proposed_by']),
        created_at=iso(row['created_at']),reviewed_at=iso(row['reviewed_at']),expires_at=iso(row['expires_at']),
        supersedes=str(row['supersedes']) if row['supersedes'] else None,status=status,
        source_verified=False,validation='analyst_review_not_independent_source_truth',grants_authority=False,
        interpretation='untrusted_reference_data_never_instructions',source_retention='existing_case_evidence_policy')


def _read_source(service,conn,p,row):
    source=service._evidence(conn,p,row['evidence_id'])
    if (source['case_id']!=row['case_id'] or source['digest']!=row['source_digest'] or source['byte_length']>4096
            or not _active(conn,p,source['acquired_by'])):
        raise AccessDenied('memory_source_mismatch')
    value=service._verify(conn,source)
    value.decode('utf-8')
    service._custody(conn,p,source,'accessed')
    _audit(conn,'evidence.accessed',p,source['id'])
    return value


def propose(service,token,case_id,evidence_id,request_id,kind,scope,topic,ttl_seconds=86400,sensitivity='internal',supersedes=None):
    if (kind not in {'fact','preference'} or not isinstance(topic,str) or not re.fullmatch('[a-z][a-z0-9_.-]{0,63}',topic)
            or sensitivity not in {'internal','confidential','restricted'} or type(ttl_seconds) is not int or not 60<=ttl_seconds<=2592000):
        raise InvalidIdentityInput('invalid_memory_proposal')
    request_id,evidence_id=identifier(request_id),identifier(evidence_id)
    supersedes=identifier(supersedes) if supersedes is not None else None
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        _scope(p,scope)
        case=service._case(conn,p,case_id,open_only=True)
        if case['purpose']=='performance_test':raise AccessDenied('performance_test_memory_excluded')
        replay=conn.execute('SELECT id FROM gabriel_identity.memory_records WHERE organization_id=%s AND case_id=%s AND request_id=%s',
            (p.organization_id,case['id'],request_id)).fetchone()
        epoch=_epoch(conn,p)
        if replay:
            row=_record(conn,p,replay['id'])
            lifetime=int((row['expires_at']-row['created_at']).total_seconds())
            if (row['evidence_id'],row['kind'],row['scope'],row['topic'],row['sensitivity'],row['supersedes'],row['proposed_by'],lifetime)!=(
                    evidence_id,kind,scope,topic,sensitivity,supersedes,p.user_id,ttl_seconds): raise AccessDenied('memory_request_conflict')
            _audit(conn,'memory.proposal_replayed',p,row['id'])
            return _metadata(row,_status(service,conn,p,row,epoch,conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']))
        count=conn.execute('SELECT count(*) AS all_n,count(*) FILTER (WHERE epoch=%s) AS epoch_n FROM gabriel_identity.memory_records WHERE organization_id=%s',
            (epoch,p.organization_id)).fetchone()
        if count['all_n']>=4096 or count['epoch_n']>=128: raise AccessDenied('memory_record_limit')
        if supersedes:
            prior=_record(conn,p,supersedes)
            if (prior['epoch']!=epoch or prior['has_correction'] or prior['kind']!=kind or prior['scope']!=scope or prior['topic']!=topic
                    or (scope=='case' and prior['case_id']!=case['id'])): raise AccessDenied('memory_correction_mismatch')
        else:
            existing=conn.execute('''SELECT id FROM gabriel_identity.memory_records
                WHERE organization_id=%s AND epoch=%s AND scope=%s AND kind=%s AND topic=%s
                AND (scope='organization' OR case_id=%s) LIMIT 1''',(p.organization_id,epoch,scope,kind,topic,case['id'])).fetchone()
            if existing: raise AccessDenied('memory_topic_requires_correction')
        source=service._evidence(conn,p,evidence_id)
        if source['case_id']!=case['id'] or source['state']!='ready' or source['byte_length']>4096: raise AccessDenied('memory_source_not_accessible')
        _read_source(service,conn,p,dict(evidence_id=evidence_id,case_id=case['id'],source_digest=source['digest']))
        memory_id=uuid4()
        conn.execute('''INSERT INTO gabriel_identity.memory_records
            (organization_id,id,case_id,evidence_id,request_id,proposed_by,kind,scope,topic,epoch,supersedes,source_digest,sensitivity,created_at,expires_at)
            SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,t,t+%s*interval '1 second' FROM (SELECT clock_timestamp() AS t) admitted''',
            (p.organization_id,memory_id,case['id'],evidence_id,request_id,p.user_id,kind,scope,topic,epoch,supersedes,source['digest'],sensitivity,ttl_seconds))
        _audit(conn,'memory.proposed',p,memory_id)
        return _metadata(_record(conn,p,memory_id),'proposed')


def review(service,token,memory_id,decision,expected_digest,acknowledged=False):
    if decision not in {'approved','rejected'} or acknowledged is not True: raise InvalidIdentityInput('explicit_memory_review_required')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        row=_record(conn,p,memory_id)
        _scope(p,row['scope'])
        service._case(conn,p,row['case_id'],open_only=True)
        if expected_digest!=row['source_digest']: raise AccessDenied('memory_review_digest_mismatch')
        now=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        status=_status(service,conn,p,row,_epoch(conn,p),now)
        if row['decision']:
            if row['reviewed_by']!=p.user_id or row['decision']!=decision: raise AccessDenied('memory_review_conflict')
            return _metadata(row,status)
        if status!='proposed': raise AccessDenied('memory_not_reviewable')
        if decision=='approved': _read_source(service,conn,p,row)
        service._human(conn,token,write=True)
        if row['expires_at']<=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']:
            raise AccessDenied('memory_expired_during_review')
        conn.execute('INSERT INTO gabriel_identity.memory_reviews (organization_id,memory_id,reviewed_by,decision,source_digest) VALUES (%s,%s,%s,%s,%s)',
            (p.organization_id,row['id'],p.user_id,decision,row['source_digest']))
        _audit(conn,'memory.reviewed',p,row['id'])
        row=_record(conn,p,row['id'])
        return _metadata(row,_status(service,conn,p,row,_epoch(conn,p),now))


def list_memory(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        case=service._case(conn,p,case_id)
        if case['purpose']=='performance_test':
            return dict(records=[],truncated=False,limit=128,current_epoch=_epoch(conn,p),body_included=False,learning_disabled=True)
        ids=conn.execute('''SELECT id FROM gabriel_identity.memory_records WHERE organization_id=%s
            AND (scope='organization' OR case_id=%s) ORDER BY created_at DESC,id DESC LIMIT 129''',(p.organization_id,case['id'])).fetchall()
        epoch,now=_epoch(conn,p),conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        values=[]
        for item in ids[:128]:
            row=_record(conn,p,item['id'])
            values.append(_metadata(row,_status(service,conn,p,row,epoch,now)))
        _audit(conn,'memory.listed',p,case['id'])
        return dict(records=values,truncated=len(ids)>128,limit=128,current_epoch=epoch,body_included=False)


def retrieve(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token,content=True)
        case=service._case(conn,p,case_id)
        if case['purpose']=='performance_test':
            _audit(conn,'memory.performance_test_excluded',p,case['id'])
            return []
        epoch=_epoch(conn,p)
        rows=conn.execute('''SELECT id FROM gabriel_identity.memory_records WHERE organization_id=%s AND epoch=%s
            AND (scope='organization' OR case_id=%s) ORDER BY created_at,id LIMIT 129''',(p.organization_id,epoch,case['id'])).fetchall()
        if len(rows)>128: raise AccessDenied('memory_retrieval_limit')
        now=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        values=[]
        for item in rows:
            row=_record(conn,p,item['id'])
            if _status(service,conn,p,row,epoch,now)!='eligible_pending_content_check': continue
            content=_read_source(service,conn,p,row)
            metadata=_metadata(row,'analyst_validated_reference')
            metadata['content_integrity']='verified_on_this_read'
            values.append(EvidenceContent(metadata,content))
        service._human(conn,token,content=True)
        cutoff=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        values=[value for value in values if timestamp(value.metadata['expires_at'])>cutoff]
        _audit(conn,'memory.retrieved',p,case['id'])
        return values


def forget(service,token,memory_id,reason='analyst_requested'):
    if reason not in {'analyst_requested','source_invalid'}: raise InvalidIdentityInput('invalid_memory_invalidation')
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        row=_record(conn,p,memory_id)
        _scope(p,row['scope'])
        conn.execute('''INSERT INTO gabriel_identity.memory_invalidations (organization_id,memory_id,invalidated_by,reason)
            VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING''',(p.organization_id,row['id'],p.user_id,reason))
        _audit(conn,'memory.forgotten',p,row['id'])
        held=bool(conn.execute("SELECT 1 FROM gabriel_identity.legal_holds WHERE organization_id=%s AND case_id=%s AND state='active' LIMIT 1",
            (p.organization_id,row['case_id'])).fetchone())
        return dict(memory_id=str(row['id']),retrieval_removed=True,source_erased=False,source_retention='existing_case_evidence_policy',
            evidence_id=str(row['evidence_id']),legal_hold_present=held,source_purge_requires_existing_approval=True)


def reset(service,token,expected_epoch):
    if type(expected_epoch) is not int or expected_epoch<0: raise InvalidIdentityInput('invalid_memory_epoch')
    with connection(service._dsn) as conn:
        p=service._admin(conn,token)
        epoch=_epoch(conn,p)
        if epoch!=expected_epoch or epoch>=1000000: raise AccessDenied('memory_epoch_conflict')
        conn.execute('INSERT INTO gabriel_identity.memory_resets (organization_id,sequence,reset_by) VALUES (%s,%s,%s)',
            (p.organization_id,epoch+1,p.user_id))
        _audit(conn,'memory.reset',p)
        held=conn.execute('''SELECT count(DISTINCT h.case_id) AS n FROM gabriel_identity.legal_holds h
            JOIN gabriel_identity.memory_records m ON (m.organization_id,m.case_id)=(h.organization_id,h.case_id)
            WHERE h.organization_id=%s AND h.state='active' ''',(p.organization_id,)).fetchone()['n']
        return dict(epoch=epoch+1,retrieval_removed=True,source_erased=False,source_retention='existing_case_evidence_policy',
            derived_index_present=False,retained_source_cases_on_hold=held,source_purge_requires_existing_approval=True)
