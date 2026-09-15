import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("WRATH_STATE", tempfile.gettempdir())
from bootstrap import unpack
from client import update_wtf
from common import checked_path
from main import profile


class SetupTests(unittest.TestCase):
    def test_config_preserves_account_and_graphics_preferences(self):
        current = 'SET accountName "remembered"\nSET gxResolution "1728x1117"\nSET portal "old"\n'
        updated = update_wtf(current, {"portal": "localhost.", "gxApi": "MTL"})
        self.assertIn('SET accountName "remembered"', updated)
        self.assertIn('SET gxResolution "1728x1117"', updated)
        self.assertEqual(updated.count("SET portal "), 1)
        self.assertEqual(
            update_wtf(updated, {"portal": "localhost.", "gxApi": "MTL"}), updated
        )

    def test_managed_paths_reject_nested_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "real").mkdir()
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(ValueError):
                checked_path(root / "alias/new-file")

    def test_archive_escape_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "test.tar"
            with tarfile.open(archive, "w") as out:
                item = tarfile.TarInfo("../escape")
                item.size = 1
                out.addfile(item, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                unpack(archive, root / "output")
            self.assertFalse((root / "escape").exists())

    def test_archive_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "test.tar"
            with tarfile.open(archive, "w") as out:
                item = tarfile.TarInfo("link")
                item.type = tarfile.SYMTYPE
                item.linkname = "../../escape"
                out.addfile(item)
            with self.assertRaises(ValueError):
                unpack(archive, root / "output")

    def test_profile_uses_parameterized_backend_and_disables_packet_logs(self):
        config = profile("server.example", 3724, Path("/tmp/sample"))
        self.assertEqual(config["LegacyServerOptions"]["Address"], "server.example")
        self.assertEqual(config["ProxyNetworkOptions"]["ExternalAddress"], "127.0.0.1")
        self.assertFalse(config["LoggingOptions"]["ToFile"])
        self.assertFalse(config["DiagnosticsOptions"]["PacketsLog"])
        self.assertNotIn("password", json.dumps(config).lower())


if __name__ == "__main__":
    unittest.main()
