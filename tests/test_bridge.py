import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("WRATH_STATE", tempfile.gettempdir())
import bridge
from client import EXE_REL


class BridgeTests(unittest.TestCase):
    def run_launch(self, already_open, login_error=False):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            target = state / "client"
            wtf = target / "_classic_/WTF/Config.wtf"
            wtf.parent.mkdir(parents=True)
            original_settings = 'SET portal "EU"\nSET gxResolution "1728x1117"\n'
            wtf.write_text(original_settings)
            exe = str(target / EXE_REL)
            config = {"proxy": str(state / "HermesProxy")}
            first = [(42, exe)] if already_open else []
            proxy = Mock(pid=123)
            proxy.poll.return_value = None
            server = Mock()
            with (
                patch.object(bridge, "session_unlocked", return_value=True),
                patch.object(bridge, "verify", return_value=target),
                patch.object(bridge, "managed_bridge_ready", return_value=False),
                patch.object(bridge, "game_processes", side_effect=[first, first, [(42, exe)], []]),
                patch.object(bridge, "port_open", side_effect=[False] * 5 + [True] * 5) as ports,
                patch.object(bridge, "ThreadingHTTPServer", return_value=server),
                patch.object(bridge.threading, "Thread"),
                patch.object(bridge.signal, "signal"),
                patch.object(bridge.subprocess, "Popen", return_value=proxy) as start_proxy,
                patch.object(bridge.subprocess, "run") as open_client,
                patch.object(bridge.login, "prepare", return_value=["--args", "-launcherlogin"]) as prepare_login,
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                if login_error:
                    prepare_login.side_effect = RuntimeError("synthetic-secret-error-body")
                def opened(*args, **kwargs):
                    settings = wtf.read_text()
                    self.assertIn('SET gxResolution "1728x1117"', settings)
                    if already_open:
                        self.assertEqual(settings, original_settings)
                    else:
                        self.assertIn('SET portal "localhost."', settings)
                        self.assertNotIn('SET portal "EU"', settings)
                    start_proxy.assert_called_once()
                    self.assertEqual(ports.call_count, 10)
                    running = list(state.glob("running.json"))
                    self.assertEqual(running, [])
                    self.assertEqual("-launcherlogin" in args[0], not already_open and not login_error)

                open_client.side_effect = opened
                bridge.launch(state, config)
                open_client.assert_called_once()
                self.assertEqual(prepare_login.call_count, 0 if already_open else 1)
                self.assertNotIn("synthetic-secret-error-body", output.getvalue())
                if login_error:
                    self.assertIn("use the game's login form", output.getvalue())
                self.assertFalse((state / "running.json").exists())
                proxy.terminate.assert_called_once()
                server.shutdown.assert_called_once()
                server.server_close.assert_called_once()

    def test_new_client_waits_for_services_and_cleans_up_after_exit(self):
        self.run_launch(already_open=False)

    def test_directly_opened_client_gets_missing_bridge(self):
        self.run_launch(already_open=True)

    def test_failed_automatic_login_opens_manual_form_without_logging_error_body(self):
        self.run_launch(already_open=False, login_error=True)

    def test_proxy_start_failure_closes_metadata_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            server = Mock()
            with (
                patch.object(bridge, "session_unlocked", return_value=True),
                patch.object(bridge, "verify", return_value=state / "client"),
                patch.object(bridge, "game_processes", return_value=[]),
                patch.object(bridge, "port_open", return_value=False),
                patch.object(bridge, "ThreadingHTTPServer", return_value=server),
                patch.object(bridge.threading, "Thread"),
                patch.object(bridge.subprocess, "Popen", side_effect=OSError("cannot start")),
            ):
                with self.assertRaisesRegex(OSError, "cannot start"):
                    bridge.launch(state, {"proxy": str(state / "HermesProxy")})
                server.shutdown.assert_called_once()
                server.server_close.assert_called_once()

    def test_stale_proxy_pid_does_not_count_as_managed_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            (state / "running.json").write_text(json.dumps({
                "client_pid": 42, "proxy_pid": 43, "supervisor_pid": 44,
            }))
            with patch.object(bridge.subprocess, "run", return_value=Mock(
                stdout="43 /some/other/process\n44 /usr/bin/python3\n"
            )), patch.object(bridge, "port_open", return_value=True):
                self.assertFalse(bridge.managed_bridge_ready(
                    state, {"proxy": str(state / "HermesProxy")}, 42
                ))

    def test_connection_counters_reset_and_discard_raw_protocol_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / "connection-status.json").write_text('{"backend_auth_succeeded": 99}')
            bridge.counters(io.StringIO(
                "AuthClient Connecting to auth server...\n"
                "private synthetic payload: do-not-store\n"
                "AuthClient Authentication succeeded!\n"
            ), state)
            text = (state / "connection-status.json").read_text()
            self.assertNotIn("do-not-store", text)
            counts = json.loads(text)
            self.assertEqual(counts["backend_auth_attempts"], 1)
            self.assertEqual(counts["backend_auth_succeeded"], 1)


if __name__ == "__main__":
    unittest.main()
