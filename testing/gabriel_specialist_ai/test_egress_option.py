"""A provider-connectivity opt-in must not stick to a reused host controller."""
import unittest
from unittest.mock import Mock

from gabriel_install import Installation,COMPOSE,REPO


class EgressOption(unittest.TestCase):
    def app(self):
        app=Installation.__new__(Installation)
        app.config=dict(project='gabriel-install-generated',port=8444)
        app.command=[]
        app.start_db=Mock();app.compose=Mock();app.operator=Mock(return_value=dict(ticket='generated-ticket'))
        return app

    def test_opt_in_then_ordinary_open_restores_private_network(self):
        app=self.app()
        first=app.open('generated-test-password',ai_egress=True,username='generated-analyst')
        self.assertTrue(first['ai_egress'])
        self.assertIn(str(REPO/'compose.gabriel-specialist-ai.yml'),app.command)
        self.assertEqual(app.operator.call_args.args[1]['username'],'generated-analyst')
        second=app.open('generated-test-password')
        self.assertFalse(second['ai_egress'])
        self.assertEqual(app.command,['docker','compose','--project-name',app.config['project'],'--file',str(COMPOSE)])
        self.assertNotIn('username',app.operator.call_args.args[1])

    def test_non_boolean_cannot_enable_provider_network(self):
        app=self.app()
        with self.assertRaises(ValueError):app.open('generated-test-password',ai_egress='yes')
        app.compose.assert_not_called()


if __name__=='__main__':unittest.main()
