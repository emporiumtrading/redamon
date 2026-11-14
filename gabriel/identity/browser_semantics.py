"""Local quoted page structure; never field meaning, incident facts or an egress grant."""
import re
from uuid import uuid5

from gabriel.identity.browser_sessions import approved_context
from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest
from gabriel.identity.model_protocol import decode
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier

VERSION='browser-visible-structure-v1'
DRAFT='browser-structure-draft-v1'
LABEL='Browser unreviewed historical structure draft'
GAPS=['partial_top_frame','unloaded_content_unverified','event_semantics_unverified',
    'hidden_covered_offscreen_fields_excluded']
LIMITATIONS=[
    'Immutable unreviewed historical draft; not a current source-health or publication receipt.',
    'Quoted labels and values are untrusted browser claims, not authenticated events or field meanings.',
    'Visible table rows are not event counts; documentation, aggregates and historical records may look alike.',
    'Missing headers and cells remain missing; adjacent visible fields do not establish a relationship.',
    'Console identity, event time, entity binding, independent corroboration and incident status remain unknown.',
    'No provider dispatch, model admission, navigation, learned memory or response action is authorized.']


def require(value,code):
    if not value:raise InvalidIdentityInput(code)


def fields(value,keys):
    require(type(value) is dict and set(value)==set(keys.split()),'invalid_browser_structure_fields')


def text(value,maximum=1024):
    require(type(value) is str and 1<=len(value)<=maximum and value==value.strip()
        and all(ord(c)>=32 and ord(c)!=127 or c in '\n\t' for c in value),'invalid_browser_structure_text')


def local_id(value,prefix,maximum):
    require(type(value) is str and re.fullmatch(re.escape(prefix)+r'[1-9][0-9]*',value) is not None,
        'invalid_browser_structure_reference')
    require(int(value[len(prefix):])<=maximum,'invalid_browser_structure_reference')


def block_list(value,maximum):
    require(type(value) is list and len(value)<=maximum,'browser_structure_limit')
    require(all(type(row) is dict and type(row.get('id')) is str for row in value),'invalid_browser_structure_reference')
    require(len({row['id'] for row in value})==len(value),'duplicate_browser_structure_reference')


def structure(value,account=None):
    fields(value,'version account headings tables pairs gaps')
    require(value['version']==VERSION and value['gaps']==GAPS,'unsupported_browser_structure')
    fields(value['account'],'id text')
    require(value['account']['id']=='a1','invalid_browser_structure_reference');text(value['account']['text'],64)
    if account is not None:require(value['account']['text']==account,'browser_structure_account_mismatch')
    block_list(value['headings'],12);block_list(value['tables'],8);block_list(value['pairs'],32)
    require(value['headings'] or value['tables'] or value['pairs'],'empty_browser_structure')
    for row in value['headings']:
        fields(row,'id level text');local_id(row['id'],'h',12);text(row['text'])
        require(type(row['level']) is int and 1<=row['level']<=6,'invalid_browser_heading_level')
    for table in value['tables']:
        fields(table,'id headers rows');local_id(table['id'],'t',8)
        block_list(table['headers'],16);block_list(table['rows'],32)
        require(table['headers'] or table['rows'],'empty_browser_table')
        for header in table['headers']:
            fields(header,'id text');local_id(header['id'],table['id']+'/h',16);text(header['text'])
        for row in table['rows']:
            fields(row,'id cells');local_id(row['id'],table['id']+'/r',2000);block_list(row['cells'],16)
            require(row['cells'],'empty_browser_table_row')
            for cell in row['cells']:
                fields(cell,'id text');local_id(cell['id'],row['id']+'/c',16);text(cell['text'])
    for pair in value['pairs']:
        fields(pair,'id label value');local_id(pair['id'],'p',32)
        for name in ('label','value'):
            fields(pair[name],'id text');require(pair[name]['id']==pair['id']+'/'+name,'invalid_browser_structure_reference')
            text(pair[name]['text'])
    require(len(canonical(value))<=65536,'browser_structure_limit')
    return value


def draft(document,source):
    structure(document)
    return dict(version=DRAFT,status='unreviewed_historical_structure',source=source,structure=document,
        counts=dict(headings=len(document['headings']),tables=len(document['tables']),
            visible_table_rows=sum(len(t['rows']) for t in document['tables']),label_value_pairs=len(document['pairs']),event_count='unknown'),
        field_meanings='unknown',console_identity='unverified',coverage='partial',source_verified=False,
        model_calls=0,incident_facts_admitted=False,limitations=LIMITATIONS)


def validate_draft(value):
    fields(value,'version status source structure counts field_meanings console_identity coverage source_verified model_calls incident_facts_admitted limitations')
    fields(value['source'],'observation_id evidence_id evidence_digest capture_received_at client_observed_at capture_request_digest receipt_sha256')
    source=value['source']
    for name in ('observation_id','evidence_id'):identifier(source[name])
    for name in ('evidence_digest','capture_request_digest','receipt_sha256'):
        require(type(source[name]) is str and re.fullmatch('[a-f0-9]{64}',source[name]),'invalid_browser_structure_source')
    from gabriel.identity.cases import timestamp
    for name in ('capture_received_at','client_observed_at'):require(timestamp(source[name]) is not None,'invalid_browser_structure_time')
    require(canonical(value)==canonical(draft(value['structure'],source)),'invalid_browser_structure_draft')
    return value


def process(service,human,peer,context,observation_id):
    observation_id=identifier(observation_id);context=approved_context(context)
    def bound(conn):
        p,lease,now=service._observer(conn,human,peer,context)
        service._case(conn,p,lease['case_id'],open_only=True)
        service._human(conn,human,content=True)
        latest=conn.execute('''SELECT * FROM gabriel_identity.browser_observations
            WHERE organization_id=%s AND lease_id=%s ORDER BY sequence DESC LIMIT 1''',(p.organization_id,lease['id'])).fetchone()
        if not latest or latest['id']!=observation_id or latest['state']!='captured':
            raise AccessDenied('browser_structure_latest_capture_required')
        from gabriel.identity.browser_navigation import context_of
        navigation=conn.execute('''SELECT c.created_at,r.context,r.context_digest
            FROM gabriel_identity.browser_navigation_commits c
            JOIN gabriel_identity.browser_navigation_receipts r USING(organization_id,intent_id)
            JOIN gabriel_identity.browser_navigation_intents i ON (i.organization_id,i.id)=(c.organization_id,c.intent_id)
            JOIN gabriel_identity.browser_navigation_grants g ON (g.organization_id,g.id)=(i.organization_id,i.grant_id)
            WHERE g.organization_id=%s AND g.lease_id=%s ORDER BY c.created_at DESC,c.intent_id DESC LIMIT 1''',
            (p.organization_id,lease['id'])).fetchone()
        if navigation and (latest['created_at']<=navigation['created_at'] or navigation['context']!=context_of(lease)
                or navigation['context_digest']!=digest(navigation['context'])):
            raise AccessDenied('browser_structure_post_navigation_capture_required')
        receipt=service._receipt(conn,p,latest)
        if not (-5<=(now-latest['observed_at']).total_seconds()<=120 and 0<=(now-receipt['created_at']).total_seconds()<=120):
            raise AccessDenied('browser_structure_fresh_capture_required')
        artifact=service._captured_artifact(conn,p,latest,lease)
        if artifact['id']!=latest['evidence_id']:raise AccessDenied('browser_structure_source_mismatch')
        raw=service._verify(conn,artifact)
        doc=structure(decode(raw.decode('utf-8')),context['account_label'])
        source=dict(observation_id=str(latest['id']),evidence_id=str(artifact['id']),evidence_digest=artifact['digest'],
            capture_received_at=iso(receipt['created_at']),client_observed_at=iso(latest['observed_at']),capture_request_digest=latest['request_digest'],
            receipt_sha256=digest({k:str(receipt[k]) for k in ('observation_id','evidence_id','completed_by','mode','created_at')}))
        return p,lease,artifact,draft(doc,source)
    with connection(service._dsn) as conn:
        p,lease,artifact,value=bound(conn)
        service._custody(conn,p,artifact,'accessed')
        case_id=lease['case_id'];parent_id=artifact['id']
    # The retained object is always historical/unreviewed, including interrupted work.
    holder=service.acquire(human,case_id,uuid5(observation_id,DRAFT),canonical(value).decode(),LABEL,
        approved=True,parent_id=parent_id,redaction_state='user_declared_redacted')
    with connection(service._dsn) as conn:
        p,_,_,repeated=bound(conn)
        if repeated!=value:raise AccessDenied('browser_structure_source_changed')
        stored=service._evidence(conn,p,holder['id'])
        if service._verify(conn,stored)!=canonical(value) or stored['parent_id']!=parent_id:
            raise AccessDenied('browser_structure_draft_binding_mismatch')
        _audit(conn,'browser.historical_structure_draft_recorded',p,observation_id)
    return dict(state='unreviewed_historical_structure',draft_evidence_id=str(holder['id']),
        source_evidence_id=str(parent_id),observation_id=str(observation_id),counts=value['counts'],
        coverage='partial',source_verified=False,model_calls=0,incident_facts_admitted=False,
        current_semantic_assessment=False)


def historical(service,token,evidence_id):
    """Validate stored transformation lineage without treating an old lease as current."""
    from gabriel.identity.browser_observations import BrowserObservationService
    browser=BrowserObservationService(service._dsn,service.store)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,content=True)
        saved=service._evidence(conn,p,evidence_id)
        value=validate_draft(decode(service._verify(conn,saved).decode('utf-8')))
        source=value['source'];observation=browser._observation(conn,p,source['observation_id'])
        lease=conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',
            (p.organization_id,observation['lease_id'])).fetchone()
        if not lease or observation['state']!='captured' or lease['case_id']!=saved['case_id']:
            raise AccessDenied('browser_structure_historical_binding_mismatch')
        artifact=browser._captured_artifact(conn,p,observation,lease)
        receipt=browser._receipt(conn,p,observation)
        expected_source=dict(observation_id=str(observation['id']),evidence_id=str(artifact['id']),evidence_digest=artifact['digest'],
            capture_received_at=iso(receipt['created_at']),client_observed_at=iso(observation['observed_at']),
            capture_request_digest=observation['request_digest'],
            receipt_sha256=digest({k:str(receipt[k]) for k in ('observation_id','evidence_id','completed_by','mode','created_at')}))
        original=structure(decode(service._verify(conn,artifact).decode('utf-8')))
        if (saved['source_label']!=LABEL or saved['parent_id']!=artifact['id'] or saved['acquired_by']!=lease['issued_by']
                or saved['ingestion_id']!=uuid5(observation['id'],DRAFT) or observation['evidence_id']!=artifact['id']
                or canonical(value)!=canonical(draft(original,expected_source))):
            raise AccessDenied('browser_structure_historical_binding_mismatch')
        service._custody(conn,p,artifact,'accessed')
        _audit(conn,'browser.historical_structure_draft_viewed',p,saved['id'])
        return value
