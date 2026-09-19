"""Read-only validation of stock and additive HD build catalogs."""
import hashlib
import re
from common import PINS, checked_path

HEX = re.compile(r'[0-9a-f]{32}\Z')
VFS = re.compile(r'vfs-(?:root|[1-9][0-9]*)(?:-size)?\Z')


def fields(data):
    result = {}
    for line in data.decode('utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name, separator, value = line.partition('=')
        name, value = name.strip(), value.strip()
        if not separator or not name or name in result:
            raise ValueError('Invalid or duplicate build configuration field')
        result[name] = value
    return result


def read_config(target, key):
    if not HEX.fullmatch(key):
        raise ValueError('Invalid build configuration key')
    path = checked_path(target / f'Data/config/{key[:2]}/{key[2:4]}/{key}')
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Build configuration is too large')
    data = path.read_bytes()
    if hashlib.md5(data).hexdigest() != key:
        raise ValueError('Build configuration checksum mismatch: ' + key)
    return data


def validate_catalog(target):
    target = checked_path(target)
    if (target / '.classic-hd-transaction.json').exists():
        raise ValueError('Interrupted HD installation; recover it with the HD installer first')
    lines = checked_path(target / '.build.info').read_text(encoding='utf-8-sig').splitlines()
    if not lines:
        raise ValueError('Empty .build.info')
    names = [column.split('!', 1)[0] for column in lines[0].split('|')]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate .build.info columns')
    rows = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split('|')
        if len(values) != len(names):
            raise ValueError('Malformed .build.info row')
        row = dict(zip(names, values))
        if row.get('Active') == '1' and row.get('Product') == 'wow_classic':
            rows.append(row)
    if len(rows) != 1:
        raise ValueError('Expected one active wow_classic catalog row')
    row = rows[0]
    if row.get('Version') != PINS['build'] or row.get('CDN Key') != PINS['cdn_config']:
        raise ValueError('Catalog version/CDN does not match pinned ' + PINS['build'])
    key = row.get('Build Key', '')
    base_data = read_config(target, PINS['build_config'])
    data = base_data if key == PINS['build_config'] else read_config(target, key)
    base, active = fields(base_data), fields(data)
    changed = sorted(name for name in base.keys() | active.keys() if base.get(name) != active.get(name))
    for name in changed:
        if name not in active or (name not in ('root', 'encoding', 'encoding-size') and not VFS.fullmatch(name)):
            raise ValueError('Unsupported HD build configuration change: ' + name)
    if not HEX.fullmatch(active.get('root', '')):
        raise ValueError('Invalid root content key')
    for name, value in active.items():
        if name == 'encoding' or (VFS.fullmatch(name) and not name.endswith('-size')):
            pair = value.split()
            sizes = active.get(name + '-size', '').split()
            if len(pair) != 2 or not all(HEX.fullmatch(key) for key in pair):
                raise ValueError('Invalid content/encoding keys: ' + name)
            if len(sizes) != 2 or not all(v.isdecimal() and int(v) > 0 for v in sizes):
                raise ValueError('Invalid content/encoding sizes: ' + name)
        elif VFS.fullmatch(name) and name.endswith('-size') and name[:-5] not in active:
            raise ValueError('VFS size has no matching object')
    return dict(build_key=key, kind='stock' if key == PINS['build_config'] else 'hd-derived',
                config=data, active=active, changed=changed)
