"""Synthetic CASC data exercises HD reference checks without game assets."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from audit import verify_hd_references
from casc_batch import RecoveredStorage
from cascette_tools.core.local_storage import LocalStorage


def blob(data):
    return b'BLTE\0\0\0\0N' + data


def md5(data):
    return hashlib.md5(data).digest()


def encoding(root):
    # One CKey page and one EKey page; standard sequential encoding layout.
    key = md5(root)
    ek = md5(blob(root))
    cpage = (b'\1' + len(root).to_bytes(5, 'big') + key + ek).ljust(4096, b'\0')
    epage = bytes(4096)
    header = b'EN\1\x10\x10' + struct.pack('>HHIIBI', 4, 4, 1, 1, 0, 2)
    return header + b'n\0' + key + md5(cpage) + cpage + bytes(16) + md5(epage) + epage


class HDAuditTests(unittest.TestCase):
    def fixture(self, target, missing_root=False):
        root = b'synthetic root'
        enc = encoding(root)
        vfs = b'synthetic vfs'
        local = LocalStorage(target)
        local.initialize()
        for data in ([enc, vfs] if missing_root else [root, enc, vfs]):
            local.write_content(md5(blob(data)), blob(data))
        store = RecoveredStorage(target)
        store.full_keys = set()
        store._scan()
        pair = lambda data: md5(data).hex() + ' ' + md5(blob(data)).hex()
        size = lambda data: str(len(data)) + ' ' + str(len(blob(data)))
        catalog = {'active': {'root': md5(root).hex(), 'encoding': pair(enc), 'encoding-size': size(enc),
                              'vfs-root': pair(vfs), 'vfs-root-size': size(vfs)},
                   'changed': ['root', 'encoding', 'encoding-size', 'vfs-root', 'vfs-root-size']}
        return catalog, store

    def test_active_encoding_root_and_vfs_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog, store = self.fixture(Path(tmp))
            self.assertEqual(verify_hd_references(catalog, store), 3)

    def test_missing_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog, store = self.fixture(Path(tmp), missing_root=True)
            with self.assertRaisesRegex(ValueError, 'HD root'):
                verify_hd_references(catalog, store)

    def test_wrong_content_hash_and_size_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog, store = self.fixture(Path(tmp))
            original = catalog['active']['vfs-root']
            catalog['active']['vfs-root'] = 'f' * 32 + original[32:]
            with self.assertRaisesRegex(ValueError, 'content checksum'):
                verify_hd_references(catalog, store)
            catalog['active']['vfs-root'] = original
            catalog['active']['vfs-root-size'] = '1 2'
            with self.assertRaisesRegex(ValueError, 'size mismatch'):
                verify_hd_references(catalog, store)
