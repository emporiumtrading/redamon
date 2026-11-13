"""Auditable 240-skill implementation ledger; never an AI or tool permission source.

This catalog is an inventory of requirements, not 240 active tools. Runtime
tool admission remains controlled by the existing exact-role manifests.
"""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re

from gabriel.identity.specialist_analysis import ROLE_TYPES
from gabriel.identity.catalog_skills import SKILLS as IMPLEMENTED

VERSION = 'gabriel-skill-catalog-v1'
CATALOG = Path(__file__).with_name('skill_roadmap.json')
STATES = frozenset({'candidate_not_implemented', 'implemented_unqualified'})
SKILL_ID = re.compile(r'[a-z_]+\.(?:0[1-9]|1[0-9]|20)-[a-z0-9]+(?:-[a-z0-9]+)*\Z')


class InvalidSkillCatalog(ValueError):
    pass


def load():
    raw = CATALOG.read_bytes()
    if len(raw) > 200000:
        raise InvalidSkillCatalog('oversized_skill_catalog')
    doc = json.loads(raw)
    if type(doc) is not dict or set(doc) != {'schema_version', 'source_document', 'catalog_total', 'roles', 'skills'}:
        raise InvalidSkillCatalog('invalid_catalog_schema')
    if (doc['schema_version'] != VERSION or doc['catalog_total'] != 240 or doc['roles'] != 12
            or doc['source_document'] != 'docs/readmes/GABRIEL_SPECIALIST_SKILL_EXPANSION.md'):
        raise InvalidSkillCatalog('invalid_catalog_count')
    rows = doc['skills']
    if type(rows) is not list or len(rows) != 240:
        raise InvalidSkillCatalog('invalid_catalog_rows')
    ids = set()
    per_role = Counter()
    from gabriel.identity.investigation_tools import TOOLS
    registered = set()
    required = {'skill_id','owner_specialist','catalog_index','name','implementation_status',
                'qualification_status','accepted_implementation','evidence_contract','external_actions_allowed'}
    for row in rows:
        if type(row) is not dict or set(row) != required:
            raise InvalidSkillCatalog('invalid_skill_fields')
        role, n, skill_id = row['owner_specialist'], row['catalog_index'], row['skill_id']
        if role not in ROLE_TYPES or type(n) is not int or not 1 <= n <= 20:
            raise InvalidSkillCatalog('invalid_role_or_index')
        if type(skill_id) is not str or SKILL_ID.fullmatch(skill_id) is None or not skill_id.startswith(role+'.'+str(n).zfill(2)+'-'):
            raise InvalidSkillCatalog('invalid_skill_id')
        if skill_id in ids or (role, n) in per_role:
            raise InvalidSkillCatalog('duplicate_skill')
        ids.add(skill_id)
        per_role[(role, n)] += 1
        if type(row['name']) is not str or not 3 <= len(row['name']) <= 120:
            raise InvalidSkillCatalog('invalid_skill_name')
        if type(row['implementation_status']) is not str or row['implementation_status'] not in STATES or row['external_actions_allowed'] is not False:
            raise InvalidSkillCatalog('unsafe_skill_status')
        if row['qualification_status'] != 'not_evaluated':
            raise InvalidSkillCatalog('unsupported_qualification_claim')
        if row['implementation_status'] == 'candidate_not_implemented':
            if row['accepted_implementation'] is not None:
                raise InvalidSkillCatalog('unimplemented_claims_code')
        else:
            provenance = row['accepted_implementation']
            if type(provenance) is not str or not provenance.startswith('gabriel.identity.catalog_skills.evaluate:'):
                raise InvalidSkillCatalog('missing_implementation_provenance')
            implementation_name = provenance.rsplit(':', 1)[-1]
            if IMPLEMENTED.get(implementation_name) != role or implementation_name not in TOOLS[role]:
                raise InvalidSkillCatalog('unbound_skill_implementation')
            registered.add(implementation_name)
        if row['evidence_contract'] != 'case-bound typed source refs and digests required':
            raise InvalidSkillCatalog('unsupported_evidence_contract')
    if set(role for role, _ in per_role) != set(ROLE_TYPES) or len(per_role) != 240:
        raise InvalidSkillCatalog('incomplete_specialist_catalog')
    if registered != set(IMPLEMENTED):
        raise InvalidSkillCatalog('missing_or_unmapped_implementation')
    return doc


def status():
    doc = load()
    counts = Counter(row['implementation_status'] for row in doc['skills'])
    return dict(
        catalog_version=VERSION,
        candidate_skills=len(doc['skills']),
        candidates_not_implemented=counts['candidate_not_implemented'],
        implemented_unqualified=counts['implemented_unqualified'],
        qualified_for_review=counts['qualified_for_review'],
        production_admission=False,
        live_model_executions=0,
        external_actions_authorized=False,
        catalog_sha256=sha256(CATALOG.read_bytes()).hexdigest(),
    )
