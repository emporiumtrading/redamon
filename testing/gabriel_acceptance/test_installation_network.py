"""Installer network failures are bounded, credential-free and fail before enrollment."""
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tooling/scripts'))
import gabriel_install as installer


def report(dns=True,tcp=True):
    return dict(version='gabriel-install-network-v1',dns_resolves=dns,tcp_reachable=tcp)


class NetworkCheckTests(unittest.TestCase):
    def app(self):
        app=installer.Installation.__new__(installer.Installation)
        app.config={'project':'gabriel-install-'+'a'*16}
        app.compose=MagicMock(return_value=json.dumps(report()).encode())
        return app

    def probe(self,*,dns_error=None,tcp_error=None):
        output=io.StringIO()
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',5432))],side_effect=dns_error) as resolve,patch('socket.socket') as factory,contextlib.redirect_stdout(output):
            client=factory.return_value.__enter__.return_value
            client.connect.side_effect=tcp_error
            exec(installer.NETWORK_CHECK,{})
        return json.loads(output.getvalue()),resolve,client

    def test_probe_uses_fixed_destination_and_only_tcp_connect(self):
        result,resolve,client=self.probe()
        self.assertEqual(result,report())
        resolve.assert_called_once_with('identity-db',5432,socket.AF_INET,socket.SOCK_STREAM)
        client.settimeout.assert_called_once_with(3)
        client.connect.assert_called_once_with(('192.0.2.1',5432))
        client.send.assert_not_called()
        client.sendall.assert_not_called()

    def test_dns_failure_does_not_attempt_tcp_or_disclose_resolver_error(self):
        result,_,client=self.probe(dns_error=socket.gaierror('private-resolver-detail'))
        self.assertEqual(result,report(False,False))
        client.connect.assert_not_called()
        self.assertNotIn('private-resolver-detail',json.dumps(result))

    def test_blocked_and_refused_tcp_are_distinct_from_dns_failure(self):
        for error in (TimeoutError('private-detail'),ConnectionRefusedError('private-detail')):
            with self.subTest(error=type(error).__name__):
                result,_,_=self.probe(tcp_error=error)
                self.assertEqual(result,report(True,False))

    def test_successful_check_has_deadline_no_input_and_removes_own_container(self):
        app=self.app()
        self.assertEqual(app.check_network(),report())
        app.compose.assert_called_once_with('run','--rm','--no-deps','-T','--name',
            app.config['project']+'-network-check','network-check','-c',installer.NETWORK_CHECK,timeout=30)

    def test_failed_dns_and_tcp_remain_distinguishable(self):
        for value,phase in ((report(False,False),'database_dns'),(report(True,False),'database_tcp')):
            with self.subTest(phase=phase):
                app=self.app();app.compose.return_value=json.dumps(value).encode()
                with self.assertRaises(installer.InstallationNetworkError) as raised: app.check_network()
                self.assertEqual(raised.exception.phase,phase)

    def test_malformed_or_contradictory_result_never_passes(self):
        for value in (b'not-json',b'[]',b'null',json.dumps(report(False,True)).encode(),
                json.dumps(dict(report(),tcp_reachable=1)).encode(),json.dumps(dict(report(),extra='secret')).encode()):
            with self.subTest(value=value):
                app=self.app();app.compose.return_value=value
                with self.assertRaises(installer.InstallationNetworkError) as raised: app.check_network()
                self.assertEqual(raised.exception.phase,'invalid_probe_result')

    def test_timeout_removes_only_named_probe_and_redacts_subprocess_output(self):
        app=self.app()
        app.compose.side_effect=subprocess.TimeoutExpired(['private-command'],30,output=b'private-output')
        with patch.object(installer,'run') as run:
            with self.assertRaises(installer.InstallationNetworkError) as raised: app.check_network()
        self.assertEqual(raised.exception.phase,'probe_timeout')
        run.assert_called_once_with(['docker','rm','--force',app.config['project']+'-network-check'],timeout=10)
        self.assertNotIn('private',str(raised.exception))

    def test_probe_execution_failure_does_not_expose_docker_output(self):
        app=self.app()
        app.compose.side_effect=installer.DockerOperationError(subprocess.CompletedProcess([],1,b'private-output',b'private-error'))
        with self.assertRaises(installer.InstallationNetworkError) as raised: app.check_network()
        self.assertEqual(str(raised.exception),'installation_network_check_failed: probe_execution')

    def test_failed_initialize_network_does_not_read_or_submit_owner_password(self):
        with tempfile.TemporaryDirectory() as root,patch.object(installer,'Installation') as constructor,patch.object(installer,'password') as password,patch.object(sys,'argv',['install','initialize',root]),contextlib.redirect_stdout(io.StringIO()) as output:
            constructor.return_value.check_network.side_effect=installer.InstallationNetworkError('database_tcp')
            self.assertEqual(installer.main(),1)
            password.assert_not_called()
            constructor.return_value.operator.assert_not_called()
        value=json.loads(output.getvalue())
        self.assertEqual(value['code'],'installation_network_check_failed')
        self.assertEqual(value['phase'],'database_tcp')

    def test_open_does_not_submit_password_or_publish_new_session_on_network_failure(self):
        app=self.app();app.start_db=MagicMock();app.operator=MagicMock()
        app.config['project']='gabriel-install-'+'a'*16
        app.check_network=MagicMock(side_effect=installer.InstallationNetworkError('database_tcp'))
        with self.assertRaises(installer.InstallationNetworkError): app.open('generated-test-password')
        app.operator.assert_not_called()
        app.compose.assert_not_called()

    def test_later_login_failure_is_not_reclassified_as_network_failure(self):
        app=self.app();app.start_db=MagicMock();app.check_network=MagicMock(return_value=report())
        app.config['port']=8444
        app.operator=MagicMock(side_effect=ValueError('installation denied at authentication'))
        with self.assertRaisesRegex(ValueError,'installation denied at authentication') as raised: app.open('generated-test-password')
        self.assertNotIsInstance(raised.exception,installer.InstallationNetworkError)

    def test_stop_does_not_depend_on_new_connectivity_probe(self):
        app=self.app();app.start_db=MagicMock();app.operator=MagicMock()
        app.check_network=MagicMock(side_effect=AssertionError('must not block shutdown'))
        app.stop()
        app.compose.assert_any_call('stop','local-entry','workbench')
        app.operator.assert_called_once_with('revoke')
        app.check_network.assert_not_called()

    def test_migration_failure_after_network_success_is_not_a_network_denial(self):
        with tempfile.TemporaryDirectory() as root,patch.object(installer,'Installation') as constructor,patch.object(installer,'password',return_value='generated-test-password'),patch.object(sys,'argv',['install','initialize',root]),contextlib.redirect_stdout(io.StringIO()) as output:
            constructor.return_value.check_network.return_value=report()
            constructor.return_value.operator.side_effect=ValueError('installation denied at migration (IdentityUnavailable)')
            self.assertEqual(installer.main(),1)
            constructor.return_value.operator.assert_called_once_with('initialize',dict(organization='Gabriel private lab',username='owner',password='generated-test-password'))
        self.assertEqual(json.loads(output.getvalue())['code'],'installation_command_failed; existing state retained for inspection')
        self.assertNotIn('generated-test-password',output.getvalue())

    def test_nonfresh_restore_is_rejected_before_start_or_probe(self):
        app=self.app();app.config.update(image='sha256:'+'a'*64,source='a'*40)
        app.start_db=MagicMock();app.check_network=MagicMock()
        app.compose.return_value=b'existing-container'
        manifest=dict(schema_version=1,purpose='gabriel-quiesced-test-backup-v1',image=app.config['image'],source=app.config['source'],identity={},
            files={'database.dump':'digest','evidence.tar.gz':'digest'},key_fingerprints={'provider':'digest','evidence':'digest'})
        with tempfile.TemporaryDirectory() as directory,patch.object(installer,'private'),patch.object(installer,'read',return_value=manifest),patch.object(installer,'digest',return_value='digest'):
            backup=Path(directory)
            for name in manifest['files']: (backup/name).write_bytes(b'fixture')
            with self.assertRaisesRegex(ValueError,'fresh_restore_target_required'): app.restore(backup,backup)
        app.start_db.assert_not_called()
        app.check_network.assert_not_called()


if __name__=='__main__': unittest.main()
