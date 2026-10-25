"""Rebuildable case provenance from authoritative records; no inferred attack relationships."""
from hashlib import sha256

from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import AccessDenied,_audit,connection

MAX_NODES=4096
MAX_EDGES=8192


def case_graph(service,token,case_id):
    source=service.case_report(token,case_id)
    snapshot=source['snapshot']
    organization,case=snapshot['organization_id'],snapshot['case']
    scope='organization/'+organization+'/case/'+case['id']+'/'
    nodes,edges={},{}

    def node(kind,identifier,properties):
        key=scope+kind+'/'+identifier
        candidate=dict(id=key,kind=kind,record_id=identifier,properties=properties)
        if key in nodes and nodes[key]!=candidate: raise AccessDenied('case_graph_conflict')
        nodes[key]=candidate
        if len(nodes)>MAX_NODES: raise AccessDenied('case_graph_limit')
        return key

    def edge(kind,start,end):
        if start not in nodes or end not in nodes: raise AccessDenied('case_graph_dangling_reference')
        key=sha256(canonical([kind,start,end])).hexdigest()
        edges[key]=dict(id=key,kind=kind,source=start,target=end,basis='stored_record_link',source_verified=False)
        if len(edges)>MAX_EDGES: raise AccessDenied('case_graph_limit')

    root=node('case',case['id'],case)
    artifacts={}
    for row in snapshot['evidence']:
        artifacts[row['id']]=node('evidence',row['id'],row)
        edge('contains_evidence',root,artifacts[row['id']])
    for row in snapshot['evidence']:
        if row['parent_id']:
            if row['parent_id'] not in artifacts: raise AccessDenied('case_graph_dangling_reference')
            edge('derived_from',artifacts[row['id']],artifacts[row['parent_id']])
    for identifier in snapshot['task_ids']:
        edge('linked_task',root,node('task',identifier,dict(authority='not_assessed')))
    for row in snapshot['browser_observations']:
        lease=node('browser_lease',row['lease_id'],dict(browser=row['browser'],extension_version=row['extension_version'],
            current_authority='not_assessed',coverage='partial'))
        observation=node('browser_observation',row['id'],row)
        edge('has_browser_lease',root,lease)
        edge('received_observation',lease,observation)
        if row['evidence_id']:
            if row['evidence_id'] not in artifacts: raise AccessDenied('case_graph_dangling_reference')
            edge('captured_as',observation,artifacts[row['evidence_id']])
    for row in snapshot['identical_artifacts']:
        group=node('identical_bytes',row['digest']+'/'+str(row['byte_length']),dict(digest=row['digest'],byte_length=row['byte_length'],
            meaning='identical_bytes_not_independent_corroboration'))
        for identifier in row['evidence_ids']:
            if identifier not in artifacts: raise AccessDenied('case_graph_dangling_reference')
            edge('has_identical_bytes',artifacts[identifier],group)
    projection=dict(schema_version=1,purpose='case-provenance-graph-v1',organization_id=organization,case_id=case['id'],
        nodes=sorted(nodes.values(),key=lambda row:row['id']),edges=sorted(edges.values(),key=lambda row:row['id']),
        coverage='partial',assessment='not_performed',content_integrity='not_checked',
        limitations=['Stored links are provenance, not causality, attacker attribution or independent corroboration.',
            'No asset/identity resolution, event deduplication, learned facts or attack inference is performed.',
            'Browser leases and tasks are historical associations, not current authority or visibility.',
            'Source clocks and authenticity remain unverified; evidence bodies are excluded.',
            'A projection is a point-in-time view; rebuild it after record or disposition changes.'])
    if len(canonical(projection))>2*1024*1024: raise AccessDenied('case_graph_limit')
    with connection(service._dsn) as conn:
        principal=service._human(conn,token)
        service._case(conn,principal,case['id'])
        _audit(conn,'case.graph_generated',principal,case['id'])
    return dict(projection=projection,digest=sha256(canonical(projection)).hexdigest(),digest_scope='canonical_projection_utf8',
        source_report_digest=source['digest'],generated_at=snapshot['generated_at'])
