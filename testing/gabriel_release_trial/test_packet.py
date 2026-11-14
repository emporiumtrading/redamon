"""Only container-run source/body review; this module cannot dispatch inference."""
from copy import deepcopy
from decimal import Decimal
import json
import unittest
from uuid import UUID

from packet import export,document,history
from gabriel.identity import catalog_skills,hermes_supervisor as hermes,specialist_agents as agents
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest


class ProposedPacket(unittest.TestCase):
    def test_complete_current_configurations_and_exact_bodies_without_authority(self):
        value=export()
        self.assertEqual(value,export())
        self.assertEqual(value['configuration_count'],14)
        self.assertEqual(value['request_count'],26)
        self.assertEqual(value['authorization'],'not_approved_for_dispatch')
        self.assertEqual(value['maximum_proposed_reservation_usd'],'0.163904')
        self.assertEqual(Decimal(value['per_request_reservation_usd'])*26,Decimal(value['maximum_proposed_reservation_usd']))
        self.assertEqual(value['network_calls'],0);self.assertEqual(value['live_calls_made'],0)
        self.assertFalse(value['production_admission']);self.assertFalse(value['quality_qualified'])
        self.assertEqual(value['request_set_sha256'],digest(value['requests']))
        for role in agents.ROLES:self.assertEqual(value['configurations'][role],agents.configuration(role))
        for stage in ('plan','report'):self.assertEqual(value['configurations']['hermes/'+stage],hermes.configuration(stage))
        self.assertEqual(len({r['name'] for r in value['requests']}),26)
        for row in value['requests']:
            self.assertEqual(row['body_sha256'],digest(row['body']))
            self.assertLessEqual(len(canonical(row['body'])),7000)
            self.assertEqual([m['role'] for m in row['body']['messages']],['system','user'])
    def test_catalog_followups_fit_existing_model_limit(self):
        for name, role in catalog_skills.SKILLS.items():
            index = agents.ROLES.index(role) + 1
            doc = document(index, role)
            fact = doc['facts'][0]
            if name == 'map_source_coverage':
                fact.update(type='source_coverage', data=dict(source_kind='network',
                            state='missing', window_start='2026-10-27T10:00:00Z'))
            if name == 'assess_cloud_storage_exposure':
                fact.update(type='cloud_storage_access', data=dict(path_id=str(UUID(int=60000)),
                            path='resource_policy', audience='anonymous', network='public',
                            guard='does_not_block', read='allow', list='deny', write='deny',
                            policy_digest='d'*64, valid_until='2026-10-28T10:00:00Z'))
            if name == 'review_intelligence_lifecycle':
                fact.update(type='intel_lifecycle', data=dict(feed_id=str(UUID(int=50000)),
                            feed_version=1, state='revoked', retrieved_at='2026-10-27T11:30:00Z',
                            valid_until='2026-10-27T10:00:00Z'))
            if name == 'review_vulnerability_sla':
                fact.update(type='vulnerability_sla', data=dict(first_seen='2026-10-10T10:00:00Z',
                            due_at='2026-10-27T10:00:00Z', state='open'))
            if name == 'review_powershell_activity':
                fact.update(type='powershell_execution', data=dict(process_instance_id=str(UUID(int=61000)),
                            indicator='encoded_command', approved='unknown'))
            if name == 'normalize_incident_timeline':
                fact.update(type='timeline_event', data=dict(offset_status='measured',
                            clock_offset_ms=4000, uncertainty_ms=1000))
            if name == 'analyze_false_negatives':
                fact.update(type='detection_trial', data=dict(fact['data'], rule_digest='a'*64,
                            engine_digest='b'*64, fixture_digest='c'*64))
            refs = [
                dict(kind='case_record', record_id=doc['case_id'], ref='case/'+doc['case_id']),
                dict(kind='evidence_metadata', record_id=fact['evidence_id'], ref='evidence/'+fact['evidence_id'],
                     digest=fact['evidence_digest'], content_integrity='verified'),
            ]
            result = catalog_skills.evaluate(name, doc, verified_refs=refs)
            self.assertEqual(result['status'], 'review_required', name)
            reviewed = history(index, doc)
            reviewed['result']['historical_assertions'][0]['data'] = agents.fact_data_for_model(fact)
            tools = [reviewed, dict(tool=name, result=result)]
            packet = agents.project(doc, role, UUID(int=index), tools)['packet']
            config = agents.configuration(role)
            body = dict(model=config['model'], messages=[dict(role='system', content=agents.prompt(role)),
                        dict(role='user', content=canonical(packet).decode())], **config['parameters'])
            wire = canonical(body)
            self.assertLessEqual(len(wire), 7000, name)
            for key in ('id', 'evidence_id', 'evidence_digest', 'entity_id'):
                self.assertNotIn(fact[key].encode(), wire, name)
            if fact['type'] == 'cloud_storage_access':
                for field in ('path_id','policy_digest'):
                    private = fact['data'][field].encode()
                    self.assertNotIn(private, wire)
                    self.assertNotIn(private, canonical(hermes.project(doc, 'plan')['packet']))
            if fact['type'] == 'powershell_execution':
                private = fact['data']['process_instance_id'].encode()
                self.assertNotIn(private, wire)
                self.assertNotIn(private, canonical(hermes.project(doc, 'plan')['packet']))
            if fact['type'] == 'intel_lifecycle':
                private = fact['data']['feed_id'].encode()
                self.assertNotIn(private, wire)
                self.assertNotIn(private, canonical(hermes.project(doc, 'plan')['packet']))
            if fact['type'] == 'detection_trial':
                for stage in ('plan','report'):
                    supervisor_wire = canonical(hermes.project(doc, stage)['packet'])
                    for field in ('rule_digest','engine_digest','fixture_digest'):
                        self.assertNotIn(fact['data'][field].encode(), supervisor_wire)
                        self.assertNotIn(fact['data'][field].encode(), wire)

    def test_history_is_separate_and_private_fixture_identifiers_do_not_cross_boundary(self):
        value=export();requests={r['name']:r for r in value['requests']}
        for index,role in enumerate(agents.ROLES,1):
            ordinary=json.loads(requests[role+'/current']['body']['messages'][1]['content'])
            historical=json.loads(requests[role+'/historical']['body']['messages'][1]['content'])
            self.assertEqual([t['tool'] for t in ordinary['tool_results']],['assess_exposure'] if role=='exposure_vulnerability' else [])
            self.assertEqual(ordinary['observations'],historical['observations'])
            reference=next(t['result'] for t in historical['tool_results'] if t['tool']=='review_memory')
            self.assertEqual(reference['historical_assertions'][0]['id'],'h1')
            self.assertFalse(reference['independent_corroboration'])
            wire=json.dumps(requests[role+'/historical']['body'])
            doc=document(index,role)
            for private in [doc['case_id'],doc['facts'][0]['id'],doc['facts'][0]['evidence_id'],doc['facts'][0]['entity_id']]:
                self.assertNotIn(private,wire)
            self.assertNotIn('_reviewed_memory',wire)
        altered=deepcopy(value['requests']);altered[0]['body']['model']='changed'
        self.assertNotEqual(digest(altered),value['request_set_sha256'])


if __name__=='__main__':unittest.main()
