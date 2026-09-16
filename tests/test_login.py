import contextlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from accounts import Keychain, service
import login

STATE = Path(os.environ.get("WRATH_STATE", str(ROOT / ".state")))
LIBRARY = STATE / "build/tls/release/libwrath_local_tls.dylib"
FRAME = b"HP-0123456789012345678901234567890123456789\nSYNTHETIC"


class AccountTests(unittest.TestCase):
    def test_keychain_scope_is_normalized_and_separate_for_each_server(self):
        def scope(host, port=3724):
            return service({"LegacyServerOptions": {"Address": host, "Port": port, "Build": "12340"}})
        self.assertEqual(scope("Example.invalid."), scope("example.invalid"))
        self.assertNotEqual(scope("a.invalid"), scope("b.invalid"))
        self.assertNotEqual(scope("a.invalid"), scope("a.invalid", 3725))

    def test_rejects_account_names_that_break_ipc_frame(self):
        for name in ("", " ", "a\nb", "a\rb", "a\x00b", "а" * 321):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                Keychain.validate(name, "synthetic")

    def test_no_saved_account_leaves_manual_login_available(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            state = Path(tmp)
            (state / "hermes.json").write_text(json.dumps({"LegacyServerOptions": {
                "Address": "example.invalid", "Port": 3724, "Build": "12340"}}))
            with patch.object(login, "Keychain") as keychain, patch.object(login, "authenticate") as auth:
                keychain.return_value.read.return_value = None
                self.assertEqual(login.prepare(state, {}, state / "client", stack), [])
                auth.assert_not_called()


@unittest.skipUnless(platform.system() == "Darwin" and LIBRARY.is_file(), "Requires built macOS helper")
class NativeLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = Path(cls.tmp.name).resolve() / "login-smoke"
        env = dict(os.environ)
        if Path("/Library/Developer/CommandLineTools").is_dir():
            env["DEVELOPER_DIR"] = "/Library/Developer/CommandLineTools"
        subprocess.run(["xcrun", "clang", "-Wno-deprecated-declarations", str(ROOT / "tests/login_smoke.c"),
                        "-framework", "Security", "-framework", "CoreFoundation", "-o", str(cls.exe)],
                       check=True, env=env, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def invoke(self, frame, reject=False):
        server = login.TicketServer(frame, self.exe)
        try:
            self.assertEqual(stat.S_IMODE(server.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(server.path.parent.stat().st_mode), 0o700)
            env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(LIBRARY), WRATH_LOGIN_SOCKET=str(server.path))
            env.pop("WRATH_NETWORK_LOG", None)
            result = subprocess.run([str(self.exe)] + (["reject"] if reject else []),
                                    env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(server.delivered.wait(1))
            server.thread.join(timeout=1)
            self.assertFalse(server.path.exists())
        finally:
            server.close()

    def test_ticket_reaches_native_preferences_and_only_own_crypto_marker(self):
        self.invoke(FRAME)

    def test_malformed_frames_never_fall_back_to_another_account(self):
        for frame in (b"", FRAME.replace(b"HP-", b"XX-"), FRAME + b"\nother", FRAME[:44], FRAME + b"x" * 700):
            with self.subTest(length=len(frame)):
                self.invoke(frame, reject=True)

    def test_other_executable_cannot_receive_ticket(self):
        server = login.TicketServer(FRAME, self.exe)
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(3)
                conn.connect(str(server.path))
                self.assertEqual(conn.recv(1024), b"")
            self.assertFalse(server.delivered.is_set())
        finally:
            server.close()

    def test_missing_socket_fails_closed(self):
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(LIBRARY), WRATH_LOGIN_SOCKET=str(self.exe) + ".missing")
        result = subprocess.run([str(self.exe), "reject"], env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
