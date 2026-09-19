import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from diagnostics import Diagnostics, ACTIVE_SETUP, sanitize
import bootstrap_windows
import common
import windows


def records(state):
    return [json.loads(line) for line in (state / 'verbose.jsonl').read_text().splitlines()]


class SetupDiagnosticsTests(unittest.TestCase):
    def test_build_stdout_stderr_exit_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            state = Path(tmp).resolve()
            diag = Diagnostics(state, True)
            with diag.setup(), self.assertRaises(subprocess.CalledProcessError):
                common.run([sys.executable, '-c',
                            "import sys; print('build started'); print('error CS1001', file=sys.stderr); "
                            "print('password=TOPSECRET'); print('https://user:URLSECRET@example.test/?key=QUERYSECRET'); sys.exit(7)"])
            data = records(state)
            text = (state / 'verbose.jsonl').read_text()
            self.assertIn('build started', text)
            self.assertIn('error CS1001', text)
            for secret in ('TOPSECRET', 'URLSECRET', 'QUERYSECRET'):
                self.assertNotIn(secret, text)
            self.assertEqual(next(r for r in data if r['event'] == 'tool_finished')['returncode'], 7)
            self.assertIsNone(ACTIVE_SETUP.get())

    def test_bootstrap_missing_dependency_is_logged(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            state = Path(tmp).resolve()
            with patch.object(sys, 'argv', ['bootstrap_windows.py', 'install', '--verbose', '--state', str(state)]), \
                 patch.object(bootstrap_windows, 'require_windows'), \
                 patch.object(bootstrap_windows.shutil, 'which', return_value=None):
                with self.assertRaisesRegex(RuntimeError, 'Install git first'):
                    bootstrap_windows.main()
            failure = records(state)[-1]
            self.assertEqual(failure['event'], 'failure')
            self.assertEqual(failure['phase'], 'prerequisites')
            self.assertIn('Install git first', failure['message'])
            self.assertTrue(failure['frames'])

    def test_bootstrap_and_child_keep_history_and_session(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            state = Path(tmp).resolve()
            python = state / 'venv/Scripts/python.exe'
            python.parent.mkdir(parents=True)
            python.touch()
            prior = Diagnostics(state, True)
            prior.emit('earlier_attempt')
            def child(argv, env):
                diag = Diagnostics(state, True, session=env['WOTLK_DIAGNOSTIC_SESSION'])
                diag.emit('child_failure')
                return 3
            with patch.object(sys, 'argv', ['bootstrap_windows.py', 'run', '--verbose', '--state', str(state)]), \
                 patch.object(bootstrap_windows, 'require_windows'), \
                 patch.object(bootstrap_windows.subprocess, 'call', side_effect=child):
                self.assertEqual(bootstrap_windows.main(), 3)
            data = records(state)
            self.assertIn('earlier_attempt', [r['event'] for r in data])
            parent = next(r for r in data if r['event'] == 'bootstrap_started')
            child_event = next(r for r in data if r['event'] == 'child_failure')
            self.assertEqual(parent['session'], child_event['session'])
            self.assertNotEqual(parent['session'], prior.session)
            self.assertEqual(data[-1]['returncode'], 3)

    def test_source_pin_failure_is_recorded_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            state = Path(tmp).resolve()
            diag = Diagnostics(state, True)
            args = argparse.Namespace(command='install', experimental=True, server='example.test',
                                      auth_port=3724, target=state / 'client')
            with patch.object(windows, 'game_closed'), \
                 patch.object(windows, 'build', side_effect=RuntimeError('Source pin changed for wow-patcher')), \
                 patch.object(windows, 'launch') as launch:
                with self.assertRaisesRegex(RuntimeError, 'Source pin changed'):
                    windows.dispatch(args, state, diag, argparse.ArgumentParser())
                launch.assert_not_called()
            failure = records(state)[-1]
            self.assertEqual(failure['phase'], 'build_tools')
            self.assertEqual(failure['message'], 'Source pin changed for wow-patcher')
            self.assertIsNone(ACTIVE_SETUP.get())
            self.assertFalse((state / 'installation.json').exists())

    def test_auth_commands_do_not_enable_tool_capture_or_record_error_body(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            diag = Diagnostics(Path(tmp), True)
            def execute(*_):
                self.assertIsNone(ACTIVE_SETUP.get())
                raise RuntimeError('TOPSECRET account response')
            with patch.object(windows, 'execute', side_effect=execute):
                with self.assertRaises(RuntimeError):
                    windows.dispatch(argparse.Namespace(command='remember-account'), Path(tmp), diag, None)
            self.assertNotIn('TOPSECRET', diag.path.read_text())

    def test_credentials_with_spaces_and_headers_are_redacted(self):
        for line in ('password="secret with spaces"', 'Authorization: Basic dXNlcjpwYXNz',
                     'Bearer hidden', 'login_ticket=HP-' + 'a' * 40,
                     '{"api_key": "secret"}', 'Cookie: secret'):
            self.assertEqual(sanitize(line), '[credential-bearing tool line redacted]')

    def test_proxy_pid_can_be_logged_alongside_supervisor_identity(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            state = Path(tmp).resolve()
            Diagnostics(state, True).emit('proxy_started', pid=123)
            self.assertEqual(records(state)[-1]['pid'], 123)
            self.assertEqual(records(state)[-1]['process_id'], os.getpid())

    def test_original_patch_stamp_remains_compatible(self):
        import build_tools
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            destination = state / 'src/wow-patcher'
            destination.mkdir(parents=True)
            # The branding change must not alter the pinned patch input again.
            stamp = {'commit': common.PINS['sources']['wow-patcher']['commit'],
                     'patch_sha256': '8e1dbdb8469009250649ce16023678919f524150ed005f6161dc82226d31fd63'}
            (destination / '.wrath-source.json').write_text(json.dumps(stamp))
            with patch.object(build_tools, 'run') as run:
                self.assertEqual(build_tools.source('wow-patcher', state), destination)
                run.assert_not_called()


class ClientConnectionTests(unittest.TestCase):
    def test_only_client_states_and_ports_are_retained(self):
        from diagnostics import parse_client_connections
        output = '''Active Connections
  TCP    127.0.0.1:50000     127.0.0.1:1119      ESTABLISHED     123
  TCP    [::1]:50001        [::1]:8081          SYN_SENT        123
  TCP    192.0.2.10:50002   198.51.100.20:443   SYN_SENT        123
  TCP    127.0.0.1:50003    127.0.0.1:9999      ESTABLISHED     456
  UDP    0.0.0.0:1234       *:*                                 123
'''
        result = parse_client_connections(output, 123)
        self.assertEqual(len(result), 3)
        self.assertEqual([r['remote_loopback'] for r in result], [True, True, False])
        self.assertEqual(result[0]['remote_port'], 1119)
        self.assertEqual(result[1]['state'], 'SYN_SENT')
        self.assertNotIn('198.51.100.20', json.dumps(result))
        self.assertNotIn('9999', json.dumps(result))

    def test_helper_pid_and_bnet_events_do_not_retain_raw_lines(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            diag = Diagnostics(Path(tmp), True)
            diag.consume(io.StringIO('WRATH_DIAG client_pid 123\n'), 'helper')
            self.assertEqual(diag.client_pid, 123)
            diag.consume(io.StringIO('Accepting connection from PRIVATE.\n'
                                     'Client requested service PRIVATE/m:7\n'), 'hermes')
            self.assertEqual(diag.counts['connection_accepted'], 1)
            self.assertEqual(diag.counts['bnet_service_request'], 1)
            self.assertNotIn('PRIVATE', diag.path.read_text())

    def test_verbose_network_profile_keeps_packet_and_file_logs_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            windows.configure(state / 'client', state, 'example.test', 3724, verbose=True)
            profile = json.loads((state / 'hermes.json').read_text())
            self.assertEqual(profile['LoggingOptions']['NetworkLevel'], 'Debug')
            self.assertFalse(profile['LoggingOptions']['ToFile'])
            self.assertFalse(profile['DiagnosticsOptions']['PacketsLog'])
            windows.configure(state / 'client', state, 'example.test', 3724)
            profile = json.loads((state / 'hermes.json').read_text())
            self.assertEqual(profile['LoggingOptions']['NetworkLevel'], 'Information')
