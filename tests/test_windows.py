import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import pe
import windows
from common import lock


class WindowsTests(unittest.TestCase):
    def fixture(self):
        data = bytearray(2048)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3c, 64)
        data[64:70] = b'PE\0\0\x64\x86'
        struct.pack_into('<H', data, 70, 2)
        struct.pack_into('<H', data, 84, 0)
        for n, (name, start, size, flags) in enumerate(((b'.rdata', 256, 1024, 0x40000040), (b'.text', 1280, 768, 0x60000020))):
            entry = 88 + n * 40
            data[entry:entry + len(name)] = name
            struct.pack_into('<II', data, entry + 16, size, start)
            struct.pack_into('<I', data, entry + 36, flags)
        patterns = [bytes.fromhex('91d59bb7d4e183a5'), bytes.fromhex('15d618bd7db577bd'), b'.actual.battle.net', pe.REGISTRY_ORIGINAL,
                    b'http://%s.patch.battle.net:1119/%s/versions', b'http://%s.patch.battle.net:1119/%s/cdns']
        for offset, value in zip((256, 512, 544, 576, 640, 704), patterns):
            data[offset:offset + len(value)] = value
        return bytes(data)

    def test_patches_preserve_code_and_length(self):
        original = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            (source / 'src/trinity').mkdir(parents=True)
            (source / 'src/trinity/mod.rs').write_text('pub const RSA_MODULUS: &[u8] = &[' + ','.join(['0x12'] * 256) + '];\npub const CRYPTO_ED25519_PUBLIC_KEY: &[u8] = &[' + ','.join(['0x34'] * 32) + '];')
            with patch.dict(pe.PINS, windows_x64_executable_sha256=hashlib.sha256(original).hexdigest()):
                changed, report = pe.patch(original, source)
            self.assertEqual(len(changed), len(original))
            self.assertEqual(changed[1280:], original[1280:])
            self.assertEqual(len(report), 6)
            self.assertIn(pe.REGISTRY_LOCAL, changed)
            self.assertNotIn(pe.REGISTRY_ORIGINAL, changed)

    def test_unknown_build_rejected_before_reading_sources(self):
        with self.assertRaisesRegex(ValueError, 'original Windows'):
            pe.patch(self.fixture(), Path('missing'))

    def test_arm64_pe_rejected(self):
        data = bytearray(self.fixture())
        data[68:70] = b'\x64\xaa'
        with self.assertRaisesRegex(ValueError, 'x64'):
            pe.sections(data)

    def test_truncated_section_rejected(self):
        with self.assertRaises(ValueError):
            pe.sections(self.fixture()[:1300])

    def test_failed_proxy_does_not_wait_or_launch_client(self):
        proxy = Mock()
        proxy.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'stopped'):
            windows.wait_ready(proxy)

    def test_lock_is_exclusive_and_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'session.lock'
            with lock(path):
                with self.assertRaises(OSError):
                    with lock(path):
                        pass
            with lock(path):
                pass

    def test_windows_profile_uses_windows_protocol_os(self):
        config = windows.proxy_profile('example.test', 3724, Path('state'))
        self.assertEqual(config['ClientOptions']['ReportedOS'], 'Win')
        self.assertNotIn('CertificatePfxPath', config['ProxyNetworkOptions'])


class DiagnosticsTests(unittest.TestCase):
    def test_unknown_output_and_secrets_are_not_retained(self):
        import io
        import json
        from diagnostics import Diagnostics
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            diag = Diagnostics(Path(tmp), True)
            diag.consume(io.StringIO(
                'TLS handshake failed for SECRET: password=SECRET\n'
                'Authentication succeeded! account=SECRET\n'
                'unknown raw packet SECRET\n'), 'hermes')
            diag.consume(io.StringIO(
                'WRATH_DIAG certificate_match 1\n'
                'WRATH_DIAG password 123\n'
                'WRATH_DIAG http_status 200 SECRET\n'), 'helper')
            text = diag.path.read_text()
            self.assertNotIn('SECRET', text)
            self.assertNotIn('password', text)
            events = [json.loads(line)['event'] for line in text.splitlines()]
            self.assertIn('tls_handshake_failed', events)
            self.assertIn('helper_certificate_match', events)
            self.assertNotIn('helper_http_status', events)
            self.assertEqual(diag.counts['hermes_lines'], 3)

    def test_disabled_diagnostics_create_no_file(self):
        from diagnostics import Diagnostics
        with tempfile.TemporaryDirectory() as tmp:
            diag = Diagnostics(Path(tmp))
            diag.emit('test')
            self.assertFalse(diag.path.exists())

    def test_catalog_mismatch_is_recorded_without_raw_contents(self):
        from diagnostics import Diagnostics
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            target = Path(tmp)
            (target / '.build.info').write_text('SECRET modified catalog')
            diag = Diagnostics(target, True)
            diag.catalog(target)
            text = diag.path.read_text()
            self.assertIn('"build_config_matches": false', text)
            self.assertNotIn('SECRET', text)

    def test_repeated_events_are_bounded_but_counted(self):
        import io
        from diagnostics import Diagnostics
        with tempfile.TemporaryDirectory() as tmp, patch('builtins.print'):
            diag = Diagnostics(Path(tmp), True)
            diag.consume(io.StringIO('TLS handshake failed for secret\n' * 30), 'hermes')
            self.assertEqual(diag.counts['tls_handshake_failed'], 30)
            self.assertEqual(diag.path.read_text().count('tls_handshake_failed'), 20)
