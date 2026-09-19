"""Bounded, allowlisted game login diagnostics; never copy raw game log lines."""
import ipaddress
import re


def endpoint_kind(value):
    value = value.strip()
    if value == 'nullopt':
        return 'absent'
    host = value
    if value.startswith('['):
        host = value.split(']', 1)[0][1:]
    elif value.count(':') == 1:
        host = value.split(':', 1)[0]
    if host.lower().rstrip('.') == 'localhost':
        return 'loopback'
    try:
        address = ipaddress.ip_address(host)
        if address.is_loopback or (getattr(address, 'ipv4_mapped', None) and address.ipv4_mapped.is_loopback):
            return 'loopback'
    except ValueError:
        pass
    return 'non_loopback_or_unknown'


def login_events(text):
    patterns = (
        ('Starting login', 'login_started'),
        ('Attempting logon', 'logon_attempt'),
        ('Waiting for server response', 'waiting_for_server'),
        ('Logon complete', 'logon_complete'),
        ('Waiting for realm list', 'waiting_for_realms'),
        ('Received realm list ticket', 'realm_ticket_received'),
        ('Front disconnected', 'front_disconnected'),
        ('Fatal error while logging in', 'login_failed'),
        ('Attempt to launcher login, but no WEB_TOKEN', 'launcher_ticket_missing'),
        ('Attempt to launcher login, but no game account', 'launcher_account_missing'),
    )
    for line in text.splitlines():
        event = next((event for pattern, event in patterns if pattern in line), None)
        if event is None:
            continue
        fields = {'stage': event}
        for name in ('launcherPortal', 'loginPortal', 'host'):
            match = re.search(r'\b' + name + r'=([^|\s]+)', line)
            if match:
                fields[name] = endpoint_kind(match[1])
        code = re.search(r'\bcode=ERROR_[A-Z0-9_]+\s*\((\d{1,10})\)', line)
        if code:
            fields['error_code'] = int(code[1])
        port = re.search(r'\bport=(\d{1,5})(?=\s|\||$)', line)
        if port and 0 < int(port[1]) <= 65535:
            fields['port'] = int(port[1])
        yield fields


class ClientLogProbe:
    """Capture only this launch's appended/replaced BattleNet.log, after exit."""
    limit = 1024 * 1024

    def __init__(self, target, diagnostics):
        self.diag = diagnostics
        self.path = target / '_classic_/Logs/BattleNet.log'
        self.before = None
        self.failed = False
        if not diagnostics.enabled:
            return
        try:
            with self.path.open('rb') as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 128))
                self.before = (size, stream.read(128))
        except FileNotFoundError:
            pass
        except OSError as error:
            self.failed = True
            self.diag.emit('client_login_log_unavailable', error_type=type(error).__name__)

    def collect(self):
        if not self.diag.enabled or self.failed:
            return
        try:
            with self.path.open('rb') as stream:
                stream.seek(0, 2)
                size = stream.tell()
                start = 0
                if self.before:
                    old_size, anchor = self.before
                    if size >= old_size:
                        stream.seek(max(0, old_size - 128))
                        if stream.read(len(anchor)) == anchor:
                            start = old_size
                truncated = size - start > self.limit
                stream.seek(max(start, size - self.limit))
                data = stream.read(self.limit)
                if truncated:
                    data = data.partition(b'\n')[2]
        except FileNotFoundError:
            self.diag.emit('client_login_log', status='missing')
            return
        except OSError as error:
            self.diag.emit('client_login_log_unavailable', error_type=type(error).__name__)
            return
        self.diag.emit('client_login_log', status='updated' if data else 'unchanged',
                       bytes_read=len(data), truncated=truncated)
        counts = {}
        for fields in login_events(data.decode('utf-8-sig', errors='replace')):
            stage = fields['stage']
            counts[stage] = counts.get(stage, 0) + 1
            if counts[stage] <= 20:
                self.diag.emit('client_login_stage', **fields)
        self.diag.emit('client_login_log_summary', counts=counts)
