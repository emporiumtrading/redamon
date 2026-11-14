"""Reported entity graph does not assert cross-source causality or movement."""
import unittest
from uuid import uuid4

from gabriel.identity.catalog_skills import evaluate
from gabriel.identity.investigation_tools import TOOLS
from gabriel.identity.service import InvalidIdentityInput


def u(): return str(uuid4())


def fact(kind, data, *, entity=None, source=None, time='2026-10-20T11:00:00Z'):
    return dict(id=u(), type=kind, evidence_id=source or u(), evidence_digest='a'*64,
                entity_id=entity or u(), event_time=time, data=data)


def doc(*facts):
    return dict(version='specialist-facts-v1', case_id=u(), as_of='2026-10-20T12:00:00Z', facts=list(facts))


class ScopeReviews(unittest.TestCase):
    def test_cross_source_pair_requires_same_entity_and_five_minutes(self):
        entity=u(); row=fact('activity',dict(category='network',outcome='observed',count=1),entity=entity)
        other=fact('activity',dict(category='network',outcome='observed',count=1),entity=entity,time='2026-10-20T11:04:59Z')
        result=evaluate('correlate_system_events',doc(row,other))
        self.assertEqual(result['reported_cross_source_five_minute_pair_count'],1)
        self.assertFalse(result['causality_established'])
        other['event_time']='2026-10-20T11:05:01Z'
        self.assertEqual(evaluate('correlate_system_events',doc(row,other))['reported_cross_source_five_minute_pair_count'],0)

    def test_conflicting_link_withheld_from_remote_paths(self):
        a,b=u(),u()
        one=fact('scope_link',dict(relation='remote_session',target_entity=b,state='observed'),entity=a)
        two=fact('scope_link',dict(relation='remote_session',target_entity=b,state='absent'),entity=a)
        result=evaluate('reconstruct_reported_remote_paths',doc(one,two))
        self.assertEqual(result['contradicting_pair_count'],1)
        self.assertEqual(result['reported_path_count_by_hops']['1'],0)
        self.assertFalse(result['movement_success_verified'])

    def test_process_parentage_and_role_bound(self):
        child=u();first=fact('scope_link',dict(relation='process_parent',target_entity=child,state='observed'))
        second=fact('scope_link',dict(relation='process_parent',target_entity=child,state='observed'))
        r=evaluate('review_process_parentage',doc(first,second))
        self.assertEqual(r['reported_child_with_multiple_parents_count'],1)
        self.assertFalse(r['executable_identity_verified'])
        for name in ('correlate_system_events','map_asset_relationships','review_process_parentage','reconstruct_reported_remote_paths'):
            self.assertIn(name,TOOLS['incident_scoping'])
            self.assertTrue(all(name not in names for role,names in TOOLS.items() if role!='incident_scoping'))

    def test_malformed_relationship_rejected(self):
        row=fact('scope_link',dict(relation='process_parent',target_entity='host.example',state='observed'))
        with self.assertRaises(InvalidIdentityInput): evaluate('review_process_parentage',doc(row))

if __name__=='__main__': unittest.main()
