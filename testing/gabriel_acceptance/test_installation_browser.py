"""Offline lifecycle fault injection; run only inside the matching installation image."""
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch
from uuid import uuid4

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tooling/scripts'))
sys.path.insert(0,'/app')
import gabriel_install as installer
from gabriel.identity import installation
from gabriel.identity.service import IdentityUnavailable

assert Path(installation.__file__).resolve().is_relative_to(Path('/app/gabriel'))


class BrowserInstallation(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.app=installer.Installation.__new__(installer.Installation)
        self.app.root=self.root;self.app.env={};self.app.config={'port':8444,'project':'generated'}
        self.app.compose=MagicMock();self.app.start_db=MagicMock()
        self.app.browser_image_supported=MagicMock(return_value=True)
        self.app.operator=MagicMock(return_value={'revocation_confirmed':True})

    def configure_tls_renewal(self):
        self.app.config['image']='sha256:'+'a'*64
        self.app.browser_stop=MagicMock(return_value={'revocation_confirmed':True})
        self.app.check_network=MagicMock()
        (self.root/'tls').mkdir(mode=0o700)
        (self.root/'tls/ca.pem').write_bytes(b'generated-original-ca')
        def generate(directory,image):
            directory.mkdir(mode=0o700)
            (directory/'ca.pem').write_bytes(b'generated-replacement-ca')
        return generate

    def test_tls_renewal_closes_and_revokes_before_replacement(self):
        generate=self.configure_tls_renewal()
        events=[]
        self.app.compose.side_effect=lambda *a,**k:events.append(('compose',a))
        self.app.browser_stop.side_effect=lambda:events.append(('browser',)) or {'revocation_confirmed':True}
        self.app.start_db.side_effect=lambda:events.append(('database',))
        self.app.operator.side_effect=lambda *a:events.append(('operator',a)) or {}
        with patch.object(installer,'run',return_value=b'{"org.gabriel.tls-profile":"rfc5280-strict-v1"}'), \
                patch.object(installer,'prepare_tls',side_effect=generate):
            result=self.app.renew_tls()
        self.assertEqual(events[:3],[('compose',('stop','local-entry','workbench')),('browser',),('database',)])
        self.assertEqual(events[-1],('operator',('revoke',)))
        self.assertTrue(result['tls_renewed']);self.assertTrue(result['certificate_trust_requires_review'])
        self.assertTrue(result['requires_fresh_login']);self.assertFalse(result['production_admitted'])
        self.assertEqual((self.root/'tls/ca.pem').read_bytes(),b'generated-replacement-ca')
        retired=list(self.root.glob('tls-retired-*'))
        self.assertEqual(len(retired),1)
        self.assertEqual((retired[0]/'ca.pem').read_bytes(),b'generated-original-ca')
        self.assertNotEqual(result['previous_ca_file_sha256'],result['ca_file_sha256'])

    def test_tls_renewal_keeps_original_files_on_generation_failure(self):
        self.configure_tls_renewal()
        with patch.object(installer,'run',return_value=b'{"org.gabriel.tls-profile":"rfc5280-strict-v1"}'), \
                patch.object(installer,'prepare_tls',side_effect=ValueError('generation failed')):
            with self.assertRaisesRegex(ValueError,'generation failed'):self.app.renew_tls()
        self.assertEqual((self.root/'tls/ca.pem').read_bytes(),b'generated-original-ca')
        self.assertFalse(list(self.root.glob('tls-retired-*')))

    def test_tls_renewal_restores_original_directory_on_publication_failure(self):
        generate=self.configure_tls_renewal()
        rename=installer.os.rename
        def publish(source,target):
            if Path(source).name.startswith('tls-pending-'):raise OSError('publication failed')
            return rename(source,target)
        with patch.object(installer,'run',return_value=b'{"org.gabriel.tls-profile":"rfc5280-strict-v1"}'), \
                patch.object(installer,'prepare_tls',side_effect=generate),patch.object(installer.os,'rename',side_effect=publish):
            with self.assertRaisesRegex(OSError,'publication failed'):self.app.renew_tls()
        self.assertEqual((self.root/'tls/ca.pem').read_bytes(),b'generated-original-ca')
        self.assertEqual(len(list(self.root.glob('tls-pending-*'))),1)

    def test_tls_renewal_requires_capable_image_and_confirmed_browser_revocation(self):
        self.configure_tls_renewal()
        with patch.object(installer,'run',return_value=b'{}'):
            with self.assertRaisesRegex(ValueError,'rebuild_required'):self.app.renew_tls()
        self.app.compose.assert_not_called()
        self.app.browser_stop.return_value={'revocation_confirmed':False}
        with patch.object(installer,'run',return_value=b'{"org.gabriel.tls-profile":"rfc5280-strict-v1"}'):
            with self.assertRaisesRegex(ValueError,'revocation_unconfirmed'):self.app.renew_tls()
        self.app.start_db.assert_not_called();self.app.operator.assert_not_called()
        self.assertEqual((self.root/'tls/ca.pem').read_bytes(),b'generated-original-ca')

    def test_stop_closes_both_services_before_database_even_with_corrupt_metadata(self):
        (self.root/'browser.json').write_text('not-json')
        events=[]
        self.app.compose.side_effect=lambda *a,**k:events.append(('compose',a))
        self.app.start_db.side_effect=lambda:events.append(('database',))
        self.app.operator.side_effect=ValueError('unavailable')
        result=self.app.browser_stop()
        self.assertEqual(events[0],('compose',('rm','-sf','browser-entry','browser-gateway')))
        self.assertTrue(result['listener_stopped']);self.assertFalse(result['revocation_confirmed'])
        self.assertFalse((self.root/'browser.json').exists())

    def test_failed_listener_shutdown_never_touches_credentials_or_database(self):
        self.app.compose.side_effect=ValueError('shutdown failed')
        with self.assertRaisesRegex(ValueError,'shutdown failed'):self.app.browser_stop()
        self.app.start_db.assert_not_called();self.app.operator.assert_not_called()

    def test_legacy_image_never_initializes_browser_volume_or_runs_browser_operator(self):
        self.app.browser_image_supported.return_value=False
        result=self.app.browser_stop()
        self.assertTrue(result['listener_stopped']);self.assertFalse(result['revocation_confirmed'])
        self.app.start_db.assert_not_called();self.app.operator.assert_not_called()
        with self.assertRaisesRegex(ValueError,'rebuild_required'):
            self.app.browser_open(str(uuid4()),{},'chrome-extension://'+'a'*32)
        self.app.start_db.assert_not_called();self.app.operator.assert_not_called()

    def test_full_stop_closes_workbench_and_dependencies_when_database_is_unavailable(self):
        self.app.browser_stop=MagicMock(return_value={'listener_stopped':True,'revocation_confirmed':False})
        self.app.start_db.side_effect=ValueError('database unavailable')
        with self.assertRaises(ValueError):self.app.stop()
        self.assertEqual(self.app.compose.call_args_list[0].args,('stop','local-entry','workbench'))
        self.assertEqual(self.app.compose.call_args_list[-1].args,('stop','hermes','investigation-tools','identity-db'))
        self.app.operator.assert_not_called()

    def test_browser_open_passes_only_explicit_scope_and_does_not_publish_ticket_to_disk(self):
        case,task,lease=[str(uuid4()) for _ in range(3)]
        context={'generated':'native metadata fixture'}
        result=dict(case_id=case,task_id=task,lease_id=lease,endpoint='https://localhost:8443',
            expires_at=(datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat(),ticket='gbc1_generated_ticket')
        self.app.browser_stop=MagicMock(return_value={'listener_stopped':True,'revocation_confirmed':True})
        self.app.check_network=MagicMock();self.app.operator.return_value=result
        opened=self.app.browser_open(case,context,'chrome-extension://'+'a'*32,duration=60,max_steps=3,share_observations=True)
        self.app.operator.assert_called_once_with('browser-open',dict(case_id=case,context=context,extension_origin='chrome-extension://'+'a'*32,
            port=8443,duration=60,max_steps=3,share_observations=True))
        self.assertEqual(opened['ticket'],result['ticket'])
        self.assertNotIn('ticket',(self.root/'browser.json').read_text())
        self.app.compose.assert_called_once_with('up','-d','--wait','--force-recreate','browser-gateway','browser-entry')

    def test_publication_failure_after_grant_quiesces_and_revokes_without_losing_error(self):
        self.app.browser_stop=MagicMock(return_value={'revocation_confirmed':True});self.app.check_network=MagicMock()
        self.app.operator.return_value=dict(ticket='one-use',expires_at='generated')
        with patch.object(installer,'write',side_effect=OSError('publication failed')):
            with self.assertRaisesRegex(OSError,'publication failed'):
                self.app.browser_open(str(uuid4()),{},'chrome-extension://'+'a'*32)
        self.assertEqual(self.app.browser_stop.call_count,2)
        self.app.compose.assert_not_called()

    def test_new_enrollment_is_blocked_while_prior_revocation_is_unconfirmed(self):
        self.app.browser_stop=MagicMock(return_value={'listener_stopped':True,'revocation_confirmed':False})
        self.app.check_network=MagicMock()
        with self.assertRaisesRegex(ValueError,'browser_revocation_unconfirmed'):
            self.app.browser_open(str(uuid4()),{},'chrome-extension://'+'a'*32)
        self.app.operator.assert_not_called();self.app.check_network.assert_not_called()

    def test_uncertain_private_revocation_receipt_is_retained_and_retried(self):
        browser=self.root/'browser';browser.mkdir(mode=0o700)
        workbench=self.root/'workbench';workbench.mkdir(mode=0o700)
        session=str(uuid4());bootstrap=browser/session;bootstrap.mkdir(mode=0o700)
        human=workbench/session;human.mkdir(mode=0o700)
        for path,value in [(browser/'active.json',{'session':session}),(workbench/'active.json',{'session':session}),
                (bootstrap/'gateway.json',{'lease_id':str(uuid4())}),(bootstrap/'task.json',{'task_id':str(uuid4())}),
                (bootstrap/'human.json',{'token':'generated-human'}),(human/'human.json',{'token':'generated-human'})]:
            installation.write_document(path,value)
        backend=MagicMock();backend._dsn='generated'
        backend.revoke_browser_lease.side_effect=[IdentityUnavailable('offline'),None]
        tasks=MagicMock();tasks.end_task.side_effect=[IdentityUnavailable('offline'),None]
        with patch.object(installation,'ROOT',workbench),patch.object(installation,'BROWSER_ROOT',browser),patch.object(installation,'browser_service',return_value=backend),patch('gabriel.identity.tasks.TaskService',return_value=tasks):
            self.assertFalse(installation.stop_browser()['revocation_confirmed'])
            self.assertTrue((browser/'active.json').exists())
            self.assertTrue(installation.stop_browser()['revocation_confirmed'])
            self.assertFalse((browser/'active.json').exists())
        self.assertEqual(backend.revoke_browser_lease.call_count,2)
        self.assertEqual(tasks.end_task.call_count,2)

    def test_rebuild_quiesces_gateway_before_building_or_reading_credentials(self):
        self.app.browser_stop=MagicMock(side_effect=ValueError('cannot stop'))
        with patch.object(installer,'build_image') as build:
            with self.assertRaisesRegex(ValueError,'cannot stop'):self.app.rebuild(self.root/'backup')
        build.assert_not_called()

    def test_expired_naive_or_excessive_process_deadline_is_rejected(self):
        for value in (datetime.now(timezone.utc)-timedelta(seconds=1),datetime.now(timezone.utc)+timedelta(seconds=301),datetime.now()):
            with self.subTest(value=value),self.assertRaises(ValueError):installation.remaining_browser_seconds(value.isoformat())

    def test_gateway_process_group_is_terminated_at_original_deadline(self):
        child=MagicMock();child.pid=12345;child.poll.return_value=None
        child.wait.side_effect=[subprocess.TimeoutExpired('generated gateway',60),0]
        expiry=(datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat()
        with patch.object(installation,'browser_active',return_value=self.root),patch.object(installation,'read_document',return_value={'expires_at':expiry}),patch.object(installation.subprocess,'Popen',return_value=child) as launch,patch.object(installation.os,'killpg') as terminate:
            installation.serve_browser()
        self.assertTrue(launch.call_args.kwargs['start_new_session'])
        self.assertNotIn('token',' '.join(launch.call_args.args[0]))
        self.assertLessEqual(child.wait.call_args_list[0].kwargs['timeout'],60)
        terminate.assert_called_once_with(child.pid,installation.signal.SIGTERM)


if __name__=='__main__':unittest.main()

