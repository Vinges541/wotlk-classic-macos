"""Read-only CASC integrity and cross-manifest selection audit."""

import hashlib
import json
import logging
import urllib.request
import structlog
from common import PINS, write_json
from casc_batch import RecoveredStorage, verify_blob
from cascette_tools.commands.install import filter_entries_by_tags
from cascette_tools.core.local_storage import parse_local_idx_file
from cascette_tools.formats.blte import decompress_blte
from cascette_tools.formats.download import DownloadParser
from cascette_tools.formats.size import SizeParser

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING)
)
MANIFESTS = {
    "download": "50bc469d89a446e232f4f1ca49df586d",
    "size": "a3d629171ee8eb6e800b4458e5eefd09",
}


def manifest(kind, state, store):
    key = MANIFESTS[kind]
    entry = store.find_entry(bytes.fromhex(key))
    if entry is not None:
        data = store.read_content(entry)
        verify_blob(data, bytes.fromhex(key))
        return decompress_blte(data)
    path = state / "cache/manifests" / key
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        for mirror in (
            "https://casc.wago.tools",
            "https://cdn.arctium.tools",
            "https://archive.wow.tools",
        ):
            url = f"{mirror}/tpr/wow/data/{key[:2]}/{key[2:4]}/{key}"
            request = urllib.request.Request(
                url, headers={"User-Agent": "cascette-py/0.3.0"}
            )
            try:
                with urllib.request.urlopen(request, timeout=45) as response:
                    data = response.read()
                verify_blob(data, bytes.fromhex(key))
            except (OSError, ValueError):
                continue
            path.write_bytes(data)
            break
        else:
            raise RuntimeError(
                "Pinned manifest unavailable locally and on all mirrors: " + kind
            )
    data = path.read_bytes()
    verify_blob(data, bytes.fromhex(key))
    return decompress_blte(data)


def verify_hd_references(catalog, store):
    """Check active encoding/root and modified VFS objects against local CASC."""
    from cascette_tools.formats.encoding import EncodingParser
    active = catalog['active']
    verified = set()

    def content(ckey, ekey, sizes=None):
        ck, ek = bytes.fromhex(ckey), bytes.fromhex(ekey)
        if ek not in store.full_keys:
            raise ValueError('HD metadata object missing from local CASC: ' + ekey)
        entry = store.find_entry(ek)
        if entry is None:
            raise ValueError('HD metadata object missing from index: ' + ekey)
        blob = store.read_content(entry)
        verify_blob(blob, ek)
        data = decompress_blte(blob)
        if hashlib.md5(data).digest() != ck:
            raise ValueError('HD metadata content checksum mismatch: ' + ckey)
        if sizes is not None and (len(data), len(blob)) != tuple(map(int, sizes.split())):
            raise ValueError('HD metadata size mismatch: ' + ekey)
        verified.add(ekey)
        return data

    encoding = content(*active['encoding'].split(), active['encoding-size'])
    parser = EncodingParser()
    parsed = parser.parse(encoding)
    root_key = bytes.fromhex(active['root'])
    root_encodings = parser.find_content_key_sequential(encoding, parsed, root_key) or []
    resident = [key for key in root_encodings if key in store.full_keys]
    if not resident:
        raise ValueError('HD root is not resident in the active encoding table/local CASC')
    content(active['root'], resident[0].hex())
    vfs_names = {name.removesuffix('-size') for name in catalog['changed'] if name.startswith('vfs-')}
    for name in sorted(vfs_names):
        ck, ek = active[name].split()
        content(ck, ek, active[name + '-size'])
    return len(verified)


def audit(target, state, locale, platform="OSX", arch="x86_64"):
    if (target / "Data/.install_state.json").exists():
        raise RuntimeError("Incomplete CASC install")
    from catalog import validate_catalog
    catalog = validate_catalog(target)
    store = RecoveredStorage(target)
    store.full_keys = set()
    store._scan()  # Deliberately do not call initialize(), which may repair files.
    hd_references = verify_hd_references(catalog, store) if catalog['kind'] == 'hd-derived' else 0
    dl = DownloadParser().parse(manifest("download", state, store))
    ds = SizeParser().parse(manifest("size", state, store))
    selected = filter_entries_by_tags(
        dl.entries,
        dl.tags,
        platform=platform,
        arch=arch,
        locale=locale,
        size_tags=ds.tags,
        size_entries=ds.entries,
    )
    alternate = filter_entries_by_tags(
        dl.entries, dl.tags, platform=platform, arch=arch, locale=locale
    )
    if not selected or {e.ekey for e in selected} != {e.ekey for e in alternate}:
        raise RuntimeError("Download/size tag selections disagree")
    missing = [
        e
        for e in selected
        if e.ekey not in store.full_keys or store._written_keys[e.ekey[:9]] != e.size
    ]
    if missing:
        raise RuntimeError(f"CASC is missing {len(missing)} selected objects")

    def signature(entry):
        return entry.key, entry.archive_id, entry.archive_offset, entry.size

    newest = {}
    for path in store.data_path.glob("*.idx"):
        bucket = int(path.name[:2], 16)
        if bucket not in newest or path.name > newest[bucket].name:
            newest[bucket] = path
    actual = []
    for path in newest.values():
        raw = path.read_bytes()
        update_start = (40 + int.from_bytes(raw[32:36], "little") + 4095) & ~4095
        if len(raw) - update_start < 0xC000:
            raise RuntimeError("CASC index lacks native update reserve")
        actual.extend(signature(e) for e in parse_local_idx_file(raw).entries)
    expected = [
        signature(e) for entries in store.bucket_entries.values() for e in entries
    ]
    if sorted(actual) != sorted(expected):
        raise RuntimeError("CASC indices disagree with verified segment contents")
    report = {
        "build": PINS["build"],
        "build_config": catalog["build_key"],
        "catalog_kind": catalog["kind"],
        "hd_references_verified": hd_references,
        "selected_files": len(selected),
        "stored_objects_verified": len(store.full_keys),
        "index_entries_verified": len(actual),
        "missing": 0,
    }
    write_json(state / "casc-audit.json", report)
    print(json.dumps(report, indent=2))
    return report
