"""Validate local evidence provenance without inferring external authenticity."""

from collections import Counter, defaultdict

from gabriel.identity.specialist_analysis import ROLE_TYPES, validate_document

VERSION = 'gabriel-dfir-provenance-v1'
SKILLS = {'validate_evidence_provenance': 'dfir_evidence'}
MAX_SOURCE_DETAILS = 4
MAX_REFERENCES_PER_SOURCE = 4


def evaluate(name, document, *, verified_refs=None):
    """Compare artifact assertions with metadata produced by verified_input.

    The caller supplies case-authorized references after verifying stored bytes
    and the local custody chain. The input assertions cannot supply that proof.
    """
    if name not in SKILLS:
        raise ValueError('unknown_dfir_catalog_skill')
    case_id = document.get('case_id') if type(document) is dict else None
    validate_document(document, case_id)

    role = SKILLS[name]
    visible_types = ROLE_TYPES[role] | {'coverage'}
    visible_facts = (fact for fact in document['facts'] if fact['type'] in visible_types)
    artifacts = defaultdict(list)
    for index, fact in enumerate(visible_facts, 1):
        if fact['type'] == 'artifact':
            artifacts[fact['evidence_id']].append((f'o{index}', fact))

    result = dict(
        version=VERSION, skill=name, role=role,
        status='insufficient_artifact_facts',
        artifact_source_count=len(artifacts), local_provenance_verified_count=0,
        unresolved_source_count=len(artifacts), reported_discrepancy_source_count=0,
        conflicting_assertion_source_count=0, source_details=[], omitted_source_count=len(artifacts),
        source_authenticity='unverified', source_independence='unestablished',
        confidence='unqualified', incident_status='unknown',
        external_actions_authorized=False, model_used=False, requires_analyst_review=True,
    )
    if not artifacts:
        return result

    metadata = defaultdict(list)
    case_refs = []
    for ref in verified_refs or ():
        if type(ref) is not dict:
            continue
        if ref.get('kind') == 'case_record':
            case_refs.append(ref)
        if ref.get('kind') == 'evidence_metadata' and type(ref.get('record_id')) is str:
            metadata[ref['record_id']].append(ref)
    if len(case_refs) != 1 or case_refs[0].get('record_id') != case_id or case_refs[0].get('ref') != f'case/{case_id}':
        return dict(result, status='case_verification_unavailable')

    details = []
    for evidence_id, rows in artifacts.items():
        refs = metadata[evidence_id]
        digests = {fact['evidence_digest'] for _, fact in rows}
        integrity = {fact['data']['integrity'] for _, fact in rows}
        custody = {fact['data']['custody'] for _, fact in rows}
        conflict = ('match' in integrity and 'mismatch' in integrity) or ('complete' in custody and 'gap' in custody)
        discrepancy = 'mismatch' in integrity or 'gap' in custody

        if len(digests) != 1:
            local_status = 'conflicting_source_digests'
        elif len(refs) != 1 or refs[0].get('ref') != f'evidence/{evidence_id}' or refs[0].get('content_integrity') != 'verified':
            local_status = 'source_verification_unavailable'
        elif refs[0].get('digest') != next(iter(digests)):
            local_status = 'source_digest_mismatch'
        else:
            local_status = 'verified_local_bytes_and_custody'

        signatures = {}
        for alias, fact in rows:
            signature = (fact['evidence_digest'], fact['data']['integrity'], fact['data']['custody'])
            signatures.setdefault(signature, alias)
        details.append((discrepancy, conflict, dict(
            references=list(signatures.values())[:MAX_REFERENCES_PER_SOURCE],
            references_truncated=len(signatures) > MAX_REFERENCES_PER_SOURCE,
            local_status=local_status, reported_integrity=sorted(integrity), reported_custody=sorted(custody),
        )))

    statuses = Counter(detail['local_status'] for _, _, detail in details)
    verified = statuses['verified_local_bytes_and_custody']
    ordered = sorted(details, key=lambda row: (
        row[2]['local_status'] == 'verified_local_bytes_and_custody', not row[1], not row[0],
    ))
    result.update(
        status='review_required' if verified == len(details) else 'incomplete_local_verification',
        local_provenance_verified_count=verified, unresolved_source_count=len(details) - verified,
        reported_discrepancy_source_count=sum(discrepancy for discrepancy, _, _ in details),
        conflicting_assertion_source_count=sum(conflict for _, conflict, _ in details),
        source_details=[detail for _, _, detail in ordered[:MAX_SOURCE_DETAILS]],
        omitted_source_count=max(0, len(details) - MAX_SOURCE_DETAILS),
    )
    return result
