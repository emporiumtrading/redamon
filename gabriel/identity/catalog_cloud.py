"""Assess reported external cloud-storage access paths using case-bound evidence."""

from collections import Counter, defaultdict


VERSION = 'gabriel-cloud-storage-exposure-v1'
SKILLS = {'assess_cloud_storage_exposure': 'cloud_supply_chain'}
PATHS = {'resource_policy', 'object_acl', 'website', 'access_point', 'delegated_link', 'other'}
AUDIENCES = {'anonymous', 'any_authenticated', 'bearer_link'}
OPERATIONS = ('read', 'list', 'write')
CLOUD_STORAGE_ACCESS_SCHEMA = {
    'path_id': 'uuid',
    'path': PATHS,
    'audience': AUDIENCES,
    'network': {'public', 'restricted', 'unknown'},
    'guard': {'blocks_path', 'does_not_block', 'unknown'},
    **{operation: {'allow', 'deny', 'unknown'} for operation in OPERATIONS},
    'policy_digest': 'digest',
    'valid_until': 'time',
}
MAX_PATH_DETAILS = 4
PRIORITY = {
    'reported_write_exposure': 0,
    'reported_read_or_list_exposure': 1,
    'conflicting_configuration': 2,
    'source_verification_unavailable': 3,
    'stale_configuration': 4,
    'incomplete_configuration': 5,
    'no_exposure_reported_for_path': 6,
}


def validate_cloud_storage_access(fact):
    """Require a case-local resource alias and a finite observation interval."""
    from gabriel.identity.specialist_analysis import at, require

    require(fact['entity_id'] is not None, 'cloud_storage_resource_alias_required')
    require(at(fact['event_time']) < at(fact['data']['valid_until']), 'invalid_cloud_storage_observation_interval')


def _verified_digests(case_id, refs):
    case_refs = []
    sources = defaultdict(list)
    for ref in refs or ():
        if type(ref) is not dict:
            continue
        if ref.get('kind') == 'case_record':
            case_refs.append(ref)
        if ref.get('kind') == 'evidence_metadata' and type(ref.get('record_id')) is str:
            sources[ref['record_id']].append(ref)
    if len(case_refs) != 1 or case_refs[0].get('record_id') != case_id or case_refs[0].get('ref') != f'case/{case_id}':
        return {}
    return {evidence_id: entries[0].get('digest') for evidence_id, entries in sources.items()
            if len(entries) == 1 and entries[0].get('ref') == f'evidence/{evidence_id}'
            and entries[0].get('content_integrity') == 'verified'}


def _assess_path(reports, as_of):
    latest_time = max(observed for observed, _, _, _ in reports)
    latest = [report for report in reports if report[0] == latest_time]
    unverified = [ref for _, _, ref, verified in latest if not verified]
    if unverified:
        return 'source_verification_unavailable', unverified[:2], [], 'unknown'

    configurations = {}
    for _, (digest, expiry, path, network, guard, grants), ref, _ in latest:
        configurations.setdefault((digest, path, network, guard, grants), {}).setdefault(expiry, ref)
    if len(configurations) > 1:
        refs = [next(iter(expirations.values())) for expirations in configurations.values()]
        return 'conflicting_configuration', refs[:2], [], 'unknown'

    (_, path, network, guard, grants), expirations = next(iter(configurations.items()))
    expiry = min(expirations)
    ref = expirations[expiry]
    if expiry <= as_of:
        return 'stale_configuration', [ref], [], path

    allowed = [name for name, grant in zip(OPERATIONS, grants) if grant == 'allow']
    if network == 'restricted' or guard == 'blocks_path' or all(grant == 'deny' for grant in grants):
        return 'no_exposure_reported_for_path', [ref], [], path
    if network == 'public' and guard == 'does_not_block' and allowed:
        status = 'reported_write_exposure' if 'write' in allowed else 'reported_read_or_list_exposure'
        return status, [ref], allowed, path
    return 'incomplete_configuration', [ref], [], path


def evaluate(name, document, *, verified_refs=None):
    """Return review findings for observed paths without a live cloud probe."""
    from gabriel.identity.specialist_analysis import ROLE_TYPES, at, validate_document

    if name not in SKILLS:
        raise ValueError('unknown_cloud_catalog_skill')
    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)
    as_of = at(document['as_of'])
    verified_digests = _verified_digests(case_id, verified_refs)
    visible_types = ROLE_TYPES[SKILLS[name]] | {'coverage'}
    visible_facts = (fact for fact in document['facts'] if fact['type'] in visible_types)
    paths = defaultdict(list)
    for index, fact in enumerate(visible_facts, 1):
        if fact['type'] != 'cloud_storage_access':
            continue
        data = fact['data']
        assertion = (data['policy_digest'], at(data['valid_until']), data['path'], data['network'], data['guard'],
                     tuple(data[operation] for operation in OPERATIONS))
        verified = verified_digests.get(fact['evidence_id']) == fact['evidence_digest']
        paths[(fact['entity_id'], data['path_id'], data['audience'])].append(
            (at(fact['event_time']), assertion, f'o{index}', verified))

    details = []
    for (_, _, audience), reports in paths.items():
        status, refs, operations, path = _assess_path(reports, as_of)
        details.append(dict(path=path, audience=audience, status=status, refs=refs, exposed_operations=operations))

    counts = Counter(detail['status'] for detail in details)
    details.sort(key=lambda detail: PRIORITY[detail['status']])
    status = 'no_storage_access_facts'
    if counts['source_verification_unavailable']:
        status = 'incomplete_local_verification'
    elif details:
        status = 'review_required'
    return dict(
        version=VERSION, status=status,
        reported_resource_alias_count=len({resource for resource, _, _ in paths}),
        reported_access_path_count=len(paths), path_status_counts=dict(sorted(counts.items())),
        access_paths=details[:MAX_PATH_DETAILS], omitted_path_count=max(0, len(details) - MAX_PATH_DETAILS),
        scope='supplied_paths_only', source_authenticity='unverified', confidence='unqualified',
        live_access_tested=False, storage_inventory_complete=False, external_actions_authorized=False,
        model_used=False, requires_analyst_review=True,
    )
