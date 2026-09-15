"""Exercise real Security.framework policy; no system trust writes."""

import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
STATE = Path(os.environ.get("WRATH_STATE", str(ROOT / ".state")))
LIBRARY = STATE / "build/tls/release/libwrath_local_tls.dylib"


@unittest.skipUnless(
    platform.system() == "Darwin" and LIBRARY.is_file(),
    "Run prepare on macOS to build the TLS helper",
)
class TrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.exe = cls.root / "trust-smoke"
        env = dict(os.environ)
        if Path("/Library/Developer/CommandLineTools").is_dir():
            env["DEVELOPER_DIR"] = "/Library/Developer/CommandLineTools"
        subprocess.run(
            [
                "xcrun",
                "clang",
                str(ROOT / "tests/trust_smoke.c"),
                "-framework",
                "Security",
                "-framework",
                "CoreFoundation",
                "-o",
                str(cls.exe),
            ],
            check=True,
            env=env,
            capture_output=True,
        )
        config = cls.root / "openssl.cnf"
        config.write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:localhost.,IP:127.0.0.1\n"
        )
        for name in ("pinned", "unrelated"):
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-sha256",
                    "-config",
                    str(config),
                    "-keyout",
                    str(cls.root / (name + ".key")),
                    "-out",
                    str(cls.root / (name + ".crt")),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(cls.root / (name + ".crt")),
                    "-outform",
                    "DER",
                    "-out",
                    str(cls.root / (name + ".der")),
                ],
                check=True,
                capture_output=True,
            )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def evaluate(self, leaf, host, pin=True):
        env = dict(os.environ)
        env.pop("WRATH_NETWORK_LOG", None)
        env.pop("WRATH_TLS_LEAF_DER", None)
        env["DYLD_INSERT_LIBRARIES"] = str(LIBRARY)
        if pin:
            env["WRATH_TLS_LEAF_DER"] = str(self.root / "pinned.der")
        output = subprocess.check_output(
            [str(self.exe), str(self.root / (leaf + ".der")), host], env=env, text=True
        )
        self.assertIn("user_trust_settings_status=-25300 count=0", output)
        return output

    def test_matching_leaf_and_host(self):
        self.assertIn("trust_result=4", self.evaluate("pinned", "localhost."))

    def test_wrong_host_rejected(self):
        self.assertIn("trust_result=5", self.evaluate("pinned", "wrong.invalid"))

    def test_unrelated_leaf_rejected(self):
        self.assertIn("trust_result=5", self.evaluate("unrelated", "localhost."))

    def test_no_pin_rejected(self):
        self.assertIn(
            "trust_result=5", self.evaluate("pinned", "localhost.", pin=False)
        )
