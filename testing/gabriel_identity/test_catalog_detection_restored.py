"""Synthetic, case-bound detection corpus for every catalog skill."""
from hashlib import sha256
import subprocess
import sys
from uuid import uuid4

import pytest

from gabriel.identity import catalog_detection_sources, catalog_skills, investigation_tools
from gabriel.identity.service import InvalidIdentityInput


NAMES = ('map_attack_coverage','validate_sigma_subset','compile_yara_rule',
         'validate_kql_subset','validate_spl_subset','validate_eql_subset',
         'evaluate_behavioral_rule','evaluate_correlation_rule','review_detection_as_code',
         'review_detection_fixture_divergence','review_detection_optimization',
         'review_false_positive_fixtures','review_detection_thresholds',
         'map_detection_dependencies','map_adversary_emulation',
         'review_detection_engine_drift','audit_detection_versions',
         'benchmark_detection_performance','prioritize_detection_gaps')
SOURCES = {
    'validate_sigma_subset': ('sigma', 'title: Synthetic example\nlogsource:\n  category: canonical_event\n'
        'detection:\n  selection:\n    event_type: process\n    outcome: observed\n  condition: selection'),
    'compile_yara_rule': ('yara', 'rule synthetic_example { strings: $a = "synthetic" condition: $a }'),
    'validate_kql_subset': ('kql', 'Events | where event_type == "process" and outcome == "observed"'),
    'validate_spl_subset': ('spl', 'search event_type=process outcome=observed'),
    'validate_eql_subset': ('eql', 'any where event_type == "process" and outcome == "observed"'),
    'evaluate_behavioral_rule': ('behavioral','{"event_type":"process","outcome":"observed","minimum_count":2}'),
    'evaluate_correlation_rule': ('correlation',
        '{"first":{"event_type":"authentication","outcome":"failure"},'
        '"then":{"event_type":"process","outcome":"observed"},"within_seconds":300}'),
}


def fact(kind, data, entity=None, when='2026-11-13T10:00:00Z'):
    return dict(id=str(uuid4()), type=kind, evidence_id=str(uuid4()),
                evidence_digest='a'*64, entity_id=entity, event_time=when, data=data)


def packet(name=None):
    entity = str(uuid4())
    rows = [fact('detection_spec',dict(format='sigma',rule_digest='b'*64,parent_digest='0'*64,
                 technique_id='T1059.001',threshold=5,field_count=2,dependency_count=1,enabled=True)),
            fact('detection_trial',dict(cohort='adversarial',expected_match=True,matched=False,
                 rule_digest='b'*64,engine_digest='c'*64,fixture_digest='d'*64)),
            fact('detection_benchmark',dict(rule_digest='b'*64,engine_digest='c'*64,
                 fixture_digest='d'*64,latency_ms=120,event_count=10)),
            fact('detection_event',dict(event_type='authentication',outcome='failure',count=3),entity),
            fact('detection_event',dict(event_type='process',outcome='observed',count=2),entity,
                 '2026-11-13T10:03:00Z')]
    if name in SOURCES:
        fmt, source = SOURCES[name]
        rows.append(fact('detection_source',dict(format=fmt,source=source,
                         rule_digest=sha256(source.encode()).hexdigest())))
    return dict(version='specialist-facts-v1',case_id=str(uuid4()),
                as_of='2026-11-13T11:00:00Z',facts=rows)


@pytest.mark.parametrize('name',NAMES)
def test_every_detection_skill_is_role_bound_and_nonexecuting(name):
    if name == 'compile_yara_rule': pytest.importorskip('yara')
    result = catalog_skills.evaluate(name,packet(name))
    assert result['status'] not in {'unsupported','error'}
    assert result['source_authenticity'] == 'unverified'
    assert result['external_actions_authorized'] is False
    assert result['confidence'] == 'unqualified'
    assert name in investigation_tools.TOOLS['detection_engineering']
    assert all(name not in tools for role,tools in investigation_tools.TOOLS.items()
               if role != 'detection_engineering')


@pytest.mark.parametrize('name,expected',[
    ('validate_sigma_subset',1),('validate_kql_subset',1),('validate_spl_subset',1),
    ('validate_eql_subset',1),('evaluate_behavioral_rule',1),('evaluate_correlation_rule',1),
])
def test_supported_canonical_dialects_match_synthetic_event(name,expected):
    result = catalog_skills.evaluate(name,packet(name))
    assert result['accepted_subset_count'] == 1
    assert result['reported_matching_event_count'] == expected
    assert result['live_engine_replay_verified'] is False


def test_versioned_fixture_reviews_do_not_vote_through_conflict():
    doc=packet()
    miss=catalog_skills.evaluate('review_detection_fixture_divergence',doc)
    assert miss['regression_established'] is False
    doc['facts'].append(fact('detection_trial',dict(doc['facts'][1]['data'],matched=True)))
    result=catalog_skills.evaluate('review_false_positive_fixtures',doc)
    assert result['conflicting_trial_count']==1
    assert result['reported_unexpected_benign_match_count']==0


def test_source_digest_and_unsupported_query_fail_closed():
    doc=packet('validate_kql_subset')
    doc['facts'][-1]['data']['rule_digest']='0'*64
    with pytest.raises(InvalidIdentityInput): catalog_skills.evaluate('validate_kql_subset',doc)
    doc=packet('validate_kql_subset')
    source='Events | where event_type == "process" | delete'
    doc['facts'][-1]['data'].update(source=source,rule_digest=sha256(source.encode()).hexdigest())
    result=catalog_skills.evaluate('validate_kql_subset',doc)
    assert result['accepted_subset_count']==0 and result['rejected_or_unsupported_count']==1


def test_yara_child_has_resource_and_environment_bounds(monkeypatch):
    def timeout(args,**kwargs):
        assert args[:2]==[sys.executable,'-I']
        assert 'RLIMIT_AS' in args[3] and 'RLIMIT_CPU' in args[3]
        assert kwargs['timeout']==3 and kwargs['env']=={'PATH':'/usr/local/bin:/usr/bin:/bin'}
        assert kwargs['cwd']=='/' and kwargs['close_fds'] is True
        raise subprocess.TimeoutExpired(args,3)
    monkeypatch.setattr(catalog_detection_sources.subprocess,'run',timeout)
    result=catalog_skills.evaluate('compile_yara_rule',packet('compile_yara_rule'))
    assert result['status']=='review_required' and result['compiler_timeout_count']==1


def test_yara_compiler_rejects_malformed_rule():
    pytest.importorskip('yara')
    doc=packet('compile_yara_rule')
    source='rule invalid_rule { condition: }'
    doc['facts'][-1]['data'].update(source=source,rule_digest=sha256(source.encode()).hexdigest())
    result=catalog_skills.evaluate('compile_yara_rule',doc)
    assert result['invalid_rule_count']==1 and result['accepted_subset_count']==0
