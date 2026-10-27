"""Only container-run source/body review; this module cannot dispatch inference."""
from copy import deepcopy
from decimal import Decimal
import json
import unittest

from packet import export,document,SAMPLES
from gabriel.identity import specialist_agents as agents,hermes_supervisor as hermes
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
