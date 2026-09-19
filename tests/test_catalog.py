import hashlib
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
os.environ.setdefault('WRATH_STATE', tempfile.gettempdir())
import catalog
import metadata_server

BASE = (b'# synthetic build\nroot = ' + b'1' * 32 + b'\nencoding = ' + b'2' * 32 + b' ' + b'3' * 32
        + b'\nencoding-size = 100 90\nvfs-root = ' + b'4' * 32 + b' ' + b'5' * 32
        + b'\nvfs-root-size = 100 90\ndownload = ' + b'6' * 32 + b' ' + b'7' * 32
        + b'\nbuild-name = WOW-54261patch3.4.3_ClassicRetail\n')


def write_config(target, data):
    key = hashlib.md5(data).hexdigest()
    path = target / f'Data/config/{key[:2]}/{key[2:4]}/{key}'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return key


def write_catalog(target, key, version='3.4.3.54261', cdn='a' * 32):
    (target / '.build.info').write_text('Active!DEC:1|Product!STRING:0|Version!STRING:0|Build Key!HEX:16|CDN Key!HEX:16\n'
                                      f'1|wow_classic|{version}|{key}|{cdn}\n')


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name).resolve()
        self.base = write_config(self.target, BASE)
        self.pins = patch.dict(catalog.PINS, build_config=self.base, cdn_config='a' * 32)
        self.pins.start()
        self.addCleanup(self.pins.stop)
        write_catalog(self.target, self.base)

    def hd(self, data=None):
        data = data if data is not None else BASE.replace(b'root = ' + b'1' * 32, b'root = ' + b'8' * 32)
        key = write_config(self.target, data)
        write_catalog(self.target, key)
        return key, data

    def test_stock_and_derived_catalogs_validate_without_mutation(self):
        self.assertEqual(catalog.validate_catalog(self.target)['kind'], 'stock')
        key, data = self.hd()
        before = {str(p): p.read_bytes() for p in self.target.rglob('*') if p.is_file()}
        result = catalog.validate_catalog(self.target)
        self.assertEqual(result['build_key'], key)
        self.assertEqual(result['kind'], 'hd-derived')
        self.assertEqual(result['changed'], ['root'])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.target.rglob('*') if p.is_file()})

    def test_identity_manifest_missing_field_and_malformed_pointer_changes_rejected(self):
        for changed in (BASE.replace(b'WOW-54261', b'WOW-99999'),
                        BASE.replace(b'download = ' + b'6' * 32, b'download = ' + b'9' * 32),
                        BASE.replace(b'encoding-size = 100 90\n', b''),
                        BASE.replace(b'encoding = ' + b'2' * 32, b'encoding = INVALID')):
            with self.subTest(changed=changed):
                self.hd(changed)
                with self.assertRaises(ValueError):
                    catalog.validate_catalog(self.target)

    def test_corrupt_config_and_interrupted_hd_install_rejected(self):
        key, _ = self.hd()
        path = self.target / f'Data/config/{key[:2]}/{key[2:4]}/{key}'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            catalog.validate_catalog(self.target)
        (self.target / '.classic-hd-transaction.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Interrupted HD'):
            catalog.validate_catalog(self.target)

    def test_wrong_cdn_version_and_ambiguous_active_rows_rejected(self):
        for version, cdn in [('9.9.9', 'a' * 32), ('3.4.3.54261', 'b' * 32)]:
            write_catalog(self.target, self.base, version, cdn)
            with self.assertRaises(ValueError):
                catalog.validate_catalog(self.target)
        write_catalog(self.target, self.base)
        path = self.target / '.build.info'
        text = path.read_text()
        path.write_text(text + text.splitlines()[1] + '\n')
        with self.assertRaisesRegex(ValueError, 'one active'):
            catalog.validate_catalog(self.target)

    def test_metadata_serves_active_hd_key_and_local_config_without_mirror(self):
        key, data = self.hd()
        server = metadata_server.ThreadingHTTPServer(('127.0.0.1', 0), metadata_server.Handler)
        self.addCleanup(server.server_close)
        metadata_server.bind_catalog(server, self.target)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            origin = 'http://127.0.0.1:' + str(server.server_port)
            with patch.object(metadata_server, 'urlopen', side_effect=AssertionError('No mirror expected')):
                with urlopen(origin + '/versions') as reply:
                    versions = reply.read().decode()
                self.assertIn(key, versions)
                self.assertNotIn(metadata_server.BUILD, versions)
                with urlopen(origin + f'/tpr/wow/config/{key[:2]}/{key[2:4]}/{key}') as reply:
                    self.assertEqual(reply.read(), data)
        finally:
            server.shutdown()
            worker.join(timeout=3)
