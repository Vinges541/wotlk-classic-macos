import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from casc_batch import RecoveredStorage, group_ranges, verify_blob
from cascette_tools.core.local_storage import LocalFileHeader, LocalStorage
from cascette_tools.core.cdn_archive_fetcher import IndexMap, ArchiveLocation


class RecoveryTests(unittest.TestCase):
    def test_native_completed_blte_recovers_full_key_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = LocalStorage(root)
            original.initialize()
            original.write_content(hashlib.md5(b"seed").digest(), b"seed")
            path = root / "Data/data/data.000"
            payload = b"BLTE\0\0\0\0Nnative payload"
            key = hashlib.md5(payload).digest()
            offset = path.stat().st_size
            with path.open("ab") as stream:
                stream.write(
                    LocalFileHeader.new(
                        key[:9] + bytes(7), len(payload) + 30, offset
                    ).to_bytes()
                )
                stream.write(payload)
            before = path.read_bytes()
            recovered = RecoveredStorage(root)
            recovered.full_keys = set()
            recovered._scan()
            self.assertIn(key, recovered.full_keys)
            self.assertEqual(path.read_bytes(), before)

    def test_native_prefix_does_not_allow_corrupt_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = LocalStorage(root)
            original.initialize()
            original.write_content(hashlib.md5(b"seed").digest(), b"seed")
            path = root / "Data/data/data.000"
            payload = b"BLTE\0\0\0\0Nnative payload"
            key = hashlib.md5(payload).digest()
            offset = path.stat().st_size
            with path.open("ab") as stream:
                stream.write(
                    LocalFileHeader.new(
                        key[:9] + bytes(7), len(payload) + 30, offset
                    ).to_bytes()
                )
                stream.write(payload[:-1] + b"X")
            before = path.read_bytes()
            recovered = RecoveredStorage(root)
            recovered.full_keys = set()
            with self.assertRaisesRegex(ValueError, "Native EKey prefix mismatch"):
                recovered._scan()
            self.assertEqual(path.read_bytes(), before)

    def test_hash_failure_rejected(self):
        raw = b"BLTE\0\0\0\0Npayload"
        key = hashlib.md5(raw).digest()
        verify_blob(raw, key)
        with self.assertRaises(ValueError):
            verify_blob(raw[:-1] + b"x", key)
        chunk = b"Nchunk"
        header = b"BLTE" + (36).to_bytes(4, "big") + b"\x0f\0\0\1"
        header += (
            len(chunk).to_bytes(4, "big")
            + (5).to_bytes(4, "big")
            + hashlib.md5(chunk).digest()
        )
        key = hashlib.md5(header).digest()
        verify_blob(header + chunk, key)
        with self.assertRaises(ValueError):
            verify_blob(header + chunk[:-1] + b"x", key)

    def test_recovery_without_indices_across_segments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = LocalStorage(root)
            original.initialize()
            raw = b"BLTE\0\0\0\0Npayload"
            key = hashlib.md5(raw).digest()
            original.write_content(key, raw)
            original.current_archive_id = 1
            original.current_archive_offset = 0
            raw2 = b"BLTE\0\0\0\0Nx"
            key2 = hashlib.md5(raw2).digest()
            original.write_content(key2, raw2)
            recovered = RecoveredStorage(root)
            recovered.initialize()
            self.assertEqual(recovered.full_keys, {key, key2})
            self.assertEqual(recovered.current_archive_id, 1)
            self.assertEqual(
                recovered.current_archive_offset,
                (root / "Data/data/data.001").stat().st_size,
            )
            before = (root / "Data/data/data.000").read_bytes()
            recovered.write_content(key, raw)
            recovered.flush_indices()
            self.assertEqual((root / "Data/data/data.000").read_bytes(), before)

    def test_failed_native_download_is_not_resident_and_empty_tail_is_repaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = LocalStorage(root)
            original.initialize()
            raw = b"BLTE\0\0\0\0Nverified"
            key = hashlib.md5(raw).digest()
            original.write_content(key, raw)
            path = root / "Data/data/data.000"
            zero_key = b"reserved1" + bytes(7)
            tail_key = b"reserved2" + bytes(7)
            start = path.stat().st_size
            zero_span = LocalFileHeader.new(zero_key, 94, start).to_bytes() + bytes(64)
            tail_start = start + len(zero_span)
            tail = LocalFileHeader.new(tail_key, 999, tail_start).to_bytes()
            with path.open("ab") as stream:
                stream.write(zero_span + tail)
            before = path.read_bytes()

            audit = RecoveredStorage(root)
            audit.full_keys = set()
            audit._scan()
            self.assertEqual(path.read_bytes(), before, "Audits must be read-only")
            self.assertEqual(audit.full_keys, {key})
            self.assertNotIn(zero_key[:9], audit._written_keys)
            self.assertNotIn(tail_key[:9], audit._written_keys)
            self.assertEqual(len(audit.native_unresident_spans), 1)
            self.assertEqual(len(audit.native_incomplete_tails), 1)

            repaired = RecoveredStorage(root)
            repaired.initialize()
            self.assertEqual(path.read_bytes(), before[:-30])
            self.assertEqual(repaired.current_archive_offset, tail_start)
            new_data = b"BLTE\0\0\0\0Nreplacement"
            new_key = hashlib.md5(new_data).digest()
            repaired.write_content(new_key, new_data)
            again = RecoveredStorage(root)
            again.initialize()
            self.assertEqual(again.full_keys, {key, new_key})
            self.assertFalse(again.native_incomplete_tails)

    def test_partial_real_payload_is_rejected_without_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = LocalStorage(root)
            original.initialize()
            raw = b"BLTE\0\0\0\0Npayload"
            original.write_content(hashlib.md5(raw).digest(), raw)
            path = root / "Data/data/data.000"
            offset = path.stat().st_size
            truncated_key = b"reserved1" + bytes(7)
            with path.open("ab") as stream:
                stream.write(LocalFileHeader.new(truncated_key, 99, offset).to_bytes())
                stream.write(b"partial")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "Incomplete local payload"):
                RecoveredStorage(root).initialize()
            self.assertEqual(path.read_bytes(), before)

    def test_range_gaps_and_limits(self):
        keys = [bytes([i]) * 16 for i in range(3)]
        entries = [SimpleNamespace(ekey=key, size=10) for key in keys]
        index = IndexMap(
            entries={
                key: ArchiveLocation("abc", offset, 10)
                for key, offset in zip(keys, [0, 15, 200])
            }
        )
        groups, loose = group_ranges(entries, index, gap=10, maximum=100)
        self.assertEqual(
            [(g[1], g[2], len(g[3])) for g in groups], [(0, 25, 2), (200, 210, 1)]
        )
        self.assertEqual(loose, [])


if __name__ == "__main__":
    unittest.main()
