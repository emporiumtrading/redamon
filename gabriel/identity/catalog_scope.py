"""Bounded case relationship reviews over source-bound typed assertions."""
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations

SKILLS = {name: 'incident_scoping' for name in (
    'correlate_system_events', 'map_asset_relationships',
    'review_process_parentage', 'reconstruct_reported_remote_paths')}
SCOPE_LINK_SCHEMA = {'relation': {'asset_service', 'network_segment', 'cloud_resource',
                                  'third_party', 'process_parent', 'remote_session'},
                     'target_entity': 'uuid', 'state': {'observed', 'absent', 'unknown'}}


def _at(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def evaluate(name, document, *, verified_refs=None):
    from gabriel.identity.specialist_analysis import validate_document
    if name not in SKILLS:
        raise ValueError('unknown_scope_skill')
    validate_document(document, document.get('case_id') if type(document) is dict else None)
    visible = [(f'o{i}', f) for i, f in enumerate(
        (f for f in document['facts'] if f['type'] in
         {'activity', 'alert', 'identity', 'cloud', 'timeline_event', 'scope_link', 'coverage'}), 1)]
    result = dict(skill=name, role='incident_scoping', source_authenticity='unverified',
                  entity_identity_verified=False, source_clocks_verified=False,
                  scope_complete=False, attack_status='unknown', confidence='unqualified',
                  external_actions_authorized=False, model_used=False, requires_analyst_review=True)
    if name == 'correlate_system_events':
        groups = defaultdict(list)
        for ref, row in visible:
            if row['type'] in {'activity', 'alert', 'identity', 'cloud'} and row['entity_id']:
                groups[row['entity_id']].append((ref, row))
        pairs = [(ra, rb) for group in groups.values() for (ra, a), (rb, b) in combinations(group, 2)
                 if a['evidence_id'] != b['evidence_id']
                 and abs((_at(a['event_time'])-_at(b['event_time'])).total_seconds()) <= 300]
        result.update(status='review_required' if groups else 'no_correlatable_facts',
                      reported_cross_source_five_minute_pair_count=len(pairs),
                      sample_pair_refs=[list(pair) for pair in pairs[:4]],
                      distinct_entity_alias_count=len(groups),
                      cross_system_event_identity_verified=False, causality_established=False,
                      event_counts_may_overlap=True)
        return result
    kind = {'review_process_parentage':'process_parent',
            'reconstruct_reported_remote_paths':'remote_session'}.get(name)
    links = [(ref, f) for ref, f in visible if f['type']=='scope_link' and
             (kind is None or f['data']['relation']==kind)]
    groups = defaultdict(lambda: defaultdict(list))
    for ref, f in links:
        key = (f['entity_id'], f['data']['target_entity'], f['data']['relation'])
        groups[key][f['data']['state']].append(ref)
    contradictions = [states for states in groups.values() if 'observed' in states and 'absent' in states]
    observed = {key for key, states in groups.items() if 'observed' in states and 'absent' not in states}
    result.update(status='review_required' if links else 'no_scope_link_facts',
                  reported_relationship_count=len(groups), reported_observed_pair_count=len(observed),
                  contradicting_pair_count=len(contradictions),
                  sample_conflict_refs=[states['observed'][:1]+states['absent'][:1]
                                        for states in contradictions[:4]],
                  relationship_provenance='reported_case_bound_assertion_only')
    if name == 'map_asset_relationships':
        degree = Counter(entity for source, target, _ in observed for entity in (source, target))
        result.update(reported_relationships_by_kind=dict(sorted(Counter(kind for _, _, kind in observed).items())),
                      connected_entity_alias_count=len(degree),
                      multi_relationship_entity_alias_count=sum(n > 1 for n in degree.values()),
                      enterprise_inventory_complete=False)
    elif name == 'review_process_parentage':
        result.update(reported_self_parent_count=sum(source==target for source,target,_ in observed),
                      reported_child_with_multiple_parents_count=sum(n > 1 for n in Counter(
                          target for source,target,_ in observed if source!=target).values()),
                      process_creation_sequence_verified=False, executable_identity_verified=False)
    else:
        edges = {(source,target) for source,target,_ in observed if source!=target}
        adjacent = defaultdict(set)
        for source,target in edges: adjacent[source].add(target)
        paths = Counter(); explored=0; truncated=False
        for source in sorted(adjacent):
            stack=[(source,(source,))]
            while stack:
                explored+=1
                if explored>4096:
                    truncated=True; break
                node, visited=stack.pop()
                if len(visited)>1: paths[len(visited)-1]+=1
                if len(visited)<5:
                    stack.extend((target,(*visited,target)) for target in sorted(adjacent[node])
                                 if target not in visited)
            if truncated: break
        result.update(reported_path_count_by_hops={str(n):paths[n] for n in range(1,5)},
                      path_enumeration_truncated=truncated,
                      movement_success_verified=False, chronological_path_verified=False)
    return result
