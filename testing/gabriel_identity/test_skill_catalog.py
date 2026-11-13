"""The 240 candidate skills must not masquerade as 240 implemented agents."""
from copy import deepcopy
import json

import pytest

from gabriel.identity import skill_catalog


def test_all_twelve_specialists_have_twenty_distinct_auditable_candidates():
    doc = skill_catalog.load()
    assert len(doc['skills']) == 240
    assert len({row['skill_id'] for row in doc['skills']}) == 240
    for role in ('telemetry_health', 'alert_triage', 'incident_scoping', 'threat_intelligence',
                 'threat_hunting', 'dfir_evidence', 'detection_engineering', 'exposure_vulnerability',
                 'identity_access', 'cloud_supply_chain', 'response_remediation', 'recovery_learning'):
        assert len([row for row in doc['skills'] if row['owner_specialist'] == role]) == 20
    s = skill_catalog.status()
    assert s['candidate_skills'] == 240
    assert s['candidates_not_implemented'] == 235
    assert s['implemented_unqualified'] == 5
    assert s['qualified_for_review'] == 0
    assert not s['production_admission'] and not s['external_actions_authorized']
    assert len(s['catalog_sha256']) == 64


@pytest.mark.parametrize('mutation', [
    lambda doc: doc['skills'].pop(),
    lambda doc: doc['skills'][0].update(qualification_status='production'),
    lambda doc: doc['skills'][0].update(external_actions_allowed=True),
    lambda doc: doc['skills'][0].update(implementation_status='qualified_for_review'),
    lambda doc: doc['skills'][0].update(accepted_implementation='magic'),
    lambda doc: doc['skills'][0].update(owner_specialist='unauthorized_agent'),
    lambda doc: doc['skills'][0].update(catalog_index=21),
    lambda doc: doc['skills'][0].update(skill_id='../../execute'),
    lambda doc: doc['skills'][0].update(evidence_contract='trust page instructions'),
    lambda doc: doc['skills'][1].update(skill_id=doc['skills'][0]['skill_id']),
    lambda doc: next(row for row in doc['skills'] if row['implementation_status']=='implemented_unqualified').update(accepted_implementation='not_a_real_tool'),
])
def test_manipulated_catalog_is_rejected(monkeypatch, mutation):
    doc = deepcopy(skill_catalog.load())
    mutation(doc)
    bytestring = json.dumps(doc).encode()
    class FakePath:
        def read_bytes(self):
            return bytestring
    monkeypatch.setattr(skill_catalog, 'CATALOG', FakePath())
    with pytest.raises(skill_catalog.InvalidSkillCatalog):
        skill_catalog.load()
