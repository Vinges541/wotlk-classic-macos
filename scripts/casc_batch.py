"""Private, verified range batching and recovery for this pinned install."""

import asyncio
import hashlib
import time
from collections import defaultdict

from cascette_tools.core.local_storage import (
    LocalFileHeader,
    LocalIndexEntry,
    LocalStorage,
    compute_bucket,
)


def verify_blob(data, ekey):
    if data[:2] == b"PA":
        from cascette_tools.formats.patch_archive import PatchArchiveParser

        manifest = PatchArchiveParser().parse(data)
        if (
            not manifest.blocks
            or hashlib.md5(data[: manifest.blocks[0].block_offset]).digest() != ekey
        ):
            raise ValueError("Patch manifest header hash mismatch")
        h = manifest.header
        for index, block in enumerate(manifest.blocks):
            limit = (
                manifest.blocks[index + 1].block_offset
                if index + 1 < len(manifest.blocks)
                else len(data)
            )
            pos = block.block_offset
            while pos < limit and data[pos]:
                count = data[pos]
                pos += (
                    1
                    + h.file_key_size
                    + 5
                    + count * (h.old_key_size + 5 + h.patch_key_size + 5)
                )
            if pos >= limit or any(data[pos:limit]):
                raise ValueError("Patch manifest block bounds/padding mismatch")
            if (
                hashlib.md5(data[block.block_offset : pos + 1]).digest()
                != block.block_md5
            ):
                raise ValueError("Patch manifest block hash mismatch")
        return
    if data[:4] != b"BLTE":
        # Raw manifests are indexed by their content MD5 instead of a BLTE EKey.
        if hashlib.md5(data).digest() != ekey:
            raise ValueError(f"Raw content hash mismatch: {ekey.hex()}")
        return
    if len(data) < 9:
        raise ValueError("Incomplete BLTE header")
    header_size = int.from_bytes(data[4:8], "big")
    if header_size and not 12 <= header_size <= len(data):
        raise ValueError("BLTE header outside file")
    if hashlib.md5(data[:header_size] if header_size else data).digest() != ekey:
        raise ValueError(f"EKey mismatch: {ekey.hex()}")
    if not header_size:
        return
    count = int.from_bytes(data[9:12], "big")
    if data[8] != 0x0F or header_size != 12 + 24 * count:
        raise ValueError("Unsupported BLTE chunk table")
    position = header_size
    for i in range(count):
        size = int.from_bytes(data[12 + i * 24 : 16 + i * 24], "big")
        expected = data[20 + i * 24 : 36 + i * 24]
        chunk = data[position : position + size]
        if len(chunk) != size or hashlib.md5(chunk).digest() != expected:
            raise ValueError(f"BLTE chunk hash mismatch: {ekey.hex()}:{i}")
        position += size
    if position != len(data):
        raise ValueError("BLTE trailing bytes")


class RecoveredStorage(LocalStorage):
    """Recover from actual segment contents before the first resumed write."""

    def initialize(self):
        super().initialize()
        self.full_keys = set()
        self._scan()
        for tail in self.native_incomplete_tails:
            path = self.data_path / f"data.{tail['segment']:03d}"
            if path.stat().st_size != tail["offset"] + 30:
                raise ValueError("Native incomplete tail changed during recovery")
            with path.open("r+b") as stream:
                stream.truncate(tail["offset"])

    def load_existing_entries(self):
        # initialize already recovered full keys, indices and the final write offset.
        pass

    def _scan(self):
        self.native_unresident_spans = []
        self.native_incomplete_tails = []
        for path in sorted(self.data_path.glob("data.[0-9][0-9][0-9]")):
            segment = int(path.suffix[1:])
            length = path.stat().st_size
            position = 0
            with path.open("rb") as stream:
                while position < length:
                    raw = stream.read(30)
                    if len(raw) != 30:
                        raise ValueError(
                            f"Incomplete local header: {path.name}:{position}"
                        )
                    header = LocalFileHeader.from_bytes(raw)
                    end = position + header.encoded_size
                    if header.encoded_size < 30:
                        raise ValueError(
                            f"Incomplete local entry: {path.name}:{position}"
                        )
                    global_offset = segment * (1 << 30) + position
                    if header.checksum_a != header.compute_checksum_a(raw):
                        raise ValueError("Local header checksum A mismatch")
                    if header.checksum_b != header.compute_checksum_b(
                        raw, global_offset
                    ):
                        raise ValueError("Local header checksum B mismatch")
                    key = header.original_encoding_key()
                    if end > length:
                        if (
                            position >= 480
                            and position + 30 == length
                            and key[9:] == bytes(7)
                        ):
                            self.native_incomplete_tails.append(
                                {
                                    "segment": segment,
                                    "offset": position,
                                    "key_prefix": key[:9].hex(),
                                }
                            )
                            break
                        raise ValueError(
                            f"Incomplete local payload: {path.name}:{position}"
                        )
                    payload = stream.read(header.encoded_size - 30)
                    reconstruction = position < 480
                    if reconstruction:
                        if header.encoded_size != 30 or header.flags != 1:
                            raise ValueError("Invalid segment reconstruction header")
                    else:
                        # A failed native streamer can reserve a sparse span
                        # with only the 9-byte key prefix and zero payload.
                        # Keep its physical space, but never mark it resident
                        # or count it as verified/downloaded content.
                        if key[9:] == bytes(7) and payload and not any(payload):
                            self.native_unresident_spans.append(
                                {
                                    "segment": segment,
                                    "offset": position,
                                    "size": header.encoded_size,
                                    "key_prefix": key[:9].hex(),
                                }
                            )
                            position = end
                            continue
                        try:
                            if key[9:] == bytes(7) and payload[:4] == b"BLTE":
                                if len(payload) < 9:
                                    raise ValueError("Incomplete native BLTE header")
                                header_size = int.from_bytes(payload[4:8], "big")
                                if header_size and not 12 <= header_size <= len(
                                    payload
                                ):
                                    raise ValueError(
                                        "Native BLTE header outside payload"
                                    )
                                derived = hashlib.md5(
                                    payload[:header_size] if header_size else payload
                                ).digest()
                                if derived[:9] != key[:9]:
                                    raise ValueError("Native EKey prefix mismatch")
                                # Native streaming stores a 9-byte prefix; recover
                                # the full key, then still verify every BLTE chunk.
                                key = derived
                            verify_blob(payload, key)
                        except ValueError as exc:
                            raise ValueError(f"{path.name}:{position}: {exc}") from exc
                        self.full_keys.add(key)
                        self._written_keys[key[:9]] = len(payload)
                    bucket = compute_bucket(key[:9], seed=int(reconstruction))
                    self.bucket_entries[bucket].append(
                        LocalIndexEntry(
                            key=key[:9],
                            archive_id=segment,
                            archive_offset=position,
                            size=header.encoded_size,
                        )
                    )
                    position = end
            self.current_archive_id = segment
            self.current_archive_offset = position
        print(
            f"Recovered and hash-verified {len(self.full_keys):,} stored blobs",
            flush=True,
        )


def group_ranges(entries, index_map, gap=262144, maximum=8 * 1024 * 1024):
    archives = defaultdict(list)
    loose = []
    for entry in entries:
        location = index_map.find(entry.ekey)
        if location is None:
            loose.append(entry)
        else:
            if location.size != entry.size:
                raise ValueError(f"Manifest/index size mismatch: {entry.ekey.hex()}")
            archives[location.archive_hash].append((location.offset, entry))
    groups = []
    for archive, items in sorted(archives.items()):
        current = []
        start = end = 0
        for offset, entry in sorted(items, key=lambda item: item[0]):
            new_end = offset + entry.size
            if current and (offset > end + gap or new_end - start > maximum):
                groups.append((archive, start, end, current))
                current = []
            if not current:
                start = offset
            current.append((offset, entry))
            end = new_end
        if current:
            groups.append((archive, start, end, current))
    return groups, loose


async def download_batched(entries, fetcher, cdn_client, storage, state, console):
    # The segment scan is the authority; state can lag the last successful write.
    entries = [e for e in entries if e.ekey not in storage.full_keys]
    groups, loose = group_ranges(entries, fetcher.index_map)
    requested = sum(end - start for _, start, end, _ in groups)
    useful = sum(e.size for e in entries)
    console.print(
        f"Batched: {len(entries):,} files, {len(groups):,} ranges, "
        f"{len(loose)} loose, {requested / 2**30:.2f} GiB transferred / "
        f"{useful / 2**30:.2f} GiB content"
    )
    mirrors = list(
        dict.fromkeys(cdn_client.cdn_servers + cdn_client.config.fallback_mirrors)
    )
    installed = failed = total_bytes = 0
    queue = asyncio.Queue()
    for group in groups:
        queue.put_nowait(group)
    for entry in loose:
        queue.put_nowait((None, 0, 0, [(0, entry)]))
    last_save = time.monotonic()

    def checkpoint():
        storage.flush_indices()
        state.save()
        console.print(
            f"Checkpoint: {installed:,}/{len(entries):,} new files, "
            f"{total_bytes / 2**20:.1f} MiB, {failed} failed"
        )

    async def worker():
        nonlocal installed, failed, total_bytes, last_save
        while True:
            try:
                archive, start, end, items = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            payloads = None
            for attempt in range(3):
                for mirror in mirrors:
                    try:
                        if archive is None:
                            key = items[0][1].ekey
                            data = await cdn_client.fetch_data_async(
                                key.hex(), quiet=True
                            )
                            candidate = [(items[0][1], data)]
                        else:
                            url = f"{mirror}/{cdn_client.cdn_path}/data/{archive[:2]}/{archive[2:4]}/{archive}"
                            response = await cdn_client.async_client.get(
                                url,
                                headers={
                                    "Range": f"bytes={start}-{end - 1}",
                                    "Accept-Encoding": "identity",
                                },
                                timeout=90,
                            )
                            if (
                                response.status_code != 206
                                or len(response.content) != end - start
                            ):
                                raise ValueError(
                                    f"Invalid range response {response.status_code}"
                                )
                            if not response.headers.get("content-range", "").startswith(
                                f"bytes {start}-{end - 1}/"
                            ):
                                raise ValueError("Wrong Content-Range")
                            candidate = [
                                (
                                    e,
                                    response.content[
                                        offset - start : offset - start + e.size
                                    ],
                                )
                                for offset, e in items
                            ]
                        for entry, data in candidate:
                            if len(data) != entry.size:
                                raise ValueError("Wrong payload size")
                            verify_blob(data, entry.ekey)
                        payloads = candidate
                        break
                    except Exception as exc:
                        console.print(
                            f"Range retry ({attempt + 1}): {type(exc).__name__}: {exc}"
                        )
                if payloads is not None:
                    break
                await asyncio.sleep(0.5 * 2**attempt)
            if payloads is None:
                for _, entry in items:
                    state.mark_failed(entry.ekey, entry.priority)
                    failed += 1
            else:
                for entry, data in payloads:
                    storage.write_content(entry.ekey, data)
                    storage.full_keys.add(entry.ekey)
                    state.mark_downloaded(entry.ekey, len(data), entry.priority)
                    installed += 1
                    total_bytes += len(data)
            if time.monotonic() - last_save >= 15:
                checkpoint()
                last_save = time.monotonic()

    try:
        async with asyncio.TaskGroup() as tasks:
            for _ in range(6):
                tasks.create_task(worker())
    finally:
        checkpoint()
    return installed, failed, 0, total_bytes


def install_overrides(module):
    module.LocalStorage = RecoveredStorage
    module._download_casc_files = download_batched
