"""Data-only patches for the hash-pinned Windows x64 54261 executable.

No code-section patching, DLL injection or certificate-store changes.
"""
import hashlib
import re
import struct
from pathlib import Path
from common import PINS

REGISTRY_ORIGINAL = b'Software\\Blizzard Entertainment\\Battle.net\\Launch Options\\'
REGISTRY_LOCAL = b'Software\\WotLK HermesProxy\\Battle.net\\Launch Options\\'


def sections(data):
    if data[:2] != b'MZ' or len(data) < 64:
        raise ValueError('Not a PE executable')
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    if data[offset:offset + 6] != b'PE\0\0\x64\x86':
        raise ValueError('Expected Windows x64 PE')
    count = struct.unpack_from('<H', data, offset + 6)[0]
    optional_size = struct.unpack_from('<H', data, offset + 20)[0]
    result = []
    for n in range(count):
        entry = offset + 24 + optional_size + 40 * n
        name = data[entry:entry + 8].rstrip(b'\0').decode('ascii')
        size, start = struct.unpack_from('<II', data, entry + 16)
        flags = struct.unpack_from('<I', data, entry + 36)[0]
        if start + size > len(data):
            raise ValueError('Truncated PE section')
        result.append((name, start, size, flags))
    return result


def patch(original, patcher_source):
    if hashlib.sha256(original).hexdigest() != PINS['windows_x64_executable_sha256']:
        raise ValueError('Expected original Windows x64 3.4.3.54261 executable')
    layout = sections(original)
    constants = (Path(patcher_source) / 'src/trinity/mod.rs').read_text()
    def key(name):
        value = constants.split(f'pub const {name}:', 1)[1].split('= &[', 1)[1].split('];', 1)[0]
        result = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', value))
        if len(result) != (256 if name == 'RSA_MODULUS' else 32):
            raise ValueError('Unexpected upstream public key size')
        return result
    replacements = [
        ('connect-to', bytes.fromhex('91d59bb7d4e183a5'), key('RSA_MODULUS'), 256),
        ('ed25519', bytes.fromhex('15d618bd7db577bd'), key('CRYPTO_ED25519_PUBLIC_KEY'), 32),
        ('portal', b'.actual.battle.net', b'.actual.wow.test', len(b'.actual.battle.net')),
        ('launcher-login', REGISTRY_ORIGINAL, REGISTRY_LOCAL, len(REGISTRY_ORIGINAL)),
        ('versions', b'http://%s.patch.battle.net:1119/%s/versions', b'http://127.0.0.1:8090/versions', len(b'http://%s.patch.battle.net:1119/%s/versions')),
        ('cdns', b'http://%s.patch.battle.net:1119/%s/cdns', b'http://127.0.0.1:8090/cdns', len(b'http://%s.patch.battle.net:1119/%s/cdns')),
    ]
    result = bytearray(original)
    report = []
    for name, pattern, replacement, length in replacements:
        matches = [m.start() for m in re.finditer(re.escape(pattern), original)]
        if len(matches) != 1 or len(replacement) > length:
            raise ValueError(f'Unexpected {name} patch layout: {len(matches)} matches')
        offset = matches[0]
        owner = next((s for s in layout if s[1] <= offset and offset + length <= s[1] + s[2]), None)
        if owner is None or owner[0] not in ('.rdata', '.data') or owner[3] & 0x20000000:
            raise ValueError(f'{name} is outside a non-executable data section')
        result[offset:offset + length] = replacement.ljust(length, b'\0')
        report.append({'patch': name, 'offset': offset, 'length': length, 'section': owner[0]})
    for name, start, size, flags in layout:
        if flags & 0x20000000 and result[start:start + size] != original[start:start + size]:
            raise ValueError('Executable section changed')
    return bytes(result), report
