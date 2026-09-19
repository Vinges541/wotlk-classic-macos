import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client_diagnostics import ClientLogProbe, login_events
from diagnostics import Diagnostics


class ClientDiagnosticsTests(unittest.TestCase):
    def test_only_fixed_stages_endpoint_classes_and_numbers_survive(self):
        events = list(login_events('''
[GlueLogin] Starting login | launcherPortal=nullopt | loginPortal=127.0.0.1:1119
[IBN_Login] Attempting logon | host=private.example | port=1119 | token=SECRET
[IBN_Login] Front disconnected | code=ERROR_NETWORK_MODULE_FAILED_TO_DOWNLOAD_CERT_BUNDLE (1021) | debugMessage=SECRET
unknown line password=SECRET
Attempt to launcher login, but no WEB_TOKEN
'''))
        self.assertEqual(events, [
            {'stage': 'login_started', 'launcherPortal': 'absent', 'loginPortal': 'loopback'},
            {'stage': 'logon_attempt', 'host': 'non_loopback_or_unknown', 'port': 1119},
            {'stage': 'front_disconnected', 'error_code': 1021},
            {'stage': 'launcher_ticket_missing'},
        ])
        self.assertNotIn('SECRET', json.dumps(events))
        self.assertNotIn('private.example', json.dumps(events))

    def test_ipv6_local_endpoint(self):
        self.assertEqual(list(login_events('Starting login | loginPortal=[::1]:1119'))[0]['loginPortal'], 'loopback')

    def test_existing_log_is_not_replayed_and_appends_are_captured(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            root = Path(tmp)
            log = root / '_classic_/Logs/BattleNet.log'
            log.parent.mkdir(parents=True)
            log.write_text('Starting login\n')
            diag = Diagnostics(root, True)
            probe = ClientLogProbe(root, diag)
            with log.open('a') as stream:
                stream.write('Attempting logon | host=localhost | port=1119\n')
            probe.collect()
            result = diag.path.read_text()
            self.assertNotIn('login_started', result)
            self.assertIn('logon_attempt', result)

    def test_replaced_log_is_captured(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            root = Path(tmp)
            log = root / '_classic_/Logs/BattleNet.log'
            log.parent.mkdir(parents=True)
            log.write_text('stale contents\n' * 20)
            diag = Diagnostics(root, True)
            probe = ClientLogProbe(root, diag)
            log.write_text('Starting login\n')
            probe.collect()
            self.assertIn('login_started', diag.path.read_text())

    def test_missing_unchanged_and_bounded_logs(self):
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            root = Path(tmp)
            diag = Diagnostics(root, True)
            probe = ClientLogProbe(root, diag)
            probe.collect()
            self.assertIn('"status": "missing"', diag.path.read_text())
            probe.path.parent.mkdir(parents=True)
            probe.path.write_text('Starting login\n')
            ClientLogProbe(root, diag).collect()
            self.assertIn('"status": "unchanged"', diag.path.read_text())
            probe.limit = 100
            probe.path.write_text('SECRET' * 100 + '\nStarting login\n')
            probe.collect()
            text = diag.path.read_text()
            self.assertIn('"truncated": true', text)
            self.assertNotIn('SECRET', text)

    def test_disabled_probe_never_opens_game_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diag = Diagnostics(root, False)
            with patch.object(Path, 'open', side_effect=AssertionError('unexpected read')):
                ClientLogProbe(root, diag).collect()
