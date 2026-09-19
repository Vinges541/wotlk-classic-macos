"""Opt-in, structured diagnostics. Never persist raw child output or credentials."""
import datetime
import json
import platform
import re
import socket
import threading
from collections import Counter


class Diagnostics:
    def __init__(self, state, enabled=False):
        self.enabled = enabled
        self.guard = threading.Lock()
        self.path = state / 'verbose.jsonl'
        self.counts = Counter()
        if enabled:
            self.path.write_text('', encoding='utf-8')
            print('Verbose diagnostics: ' + str(self.path), flush=True)
            self.emit('environment', python=platform.python_version(), os=platform.system(),
                      release=platform.release(), machine=platform.machine())

    def emit(self, event, **fields):
        if not self.enabled:
            return
        record = dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      event=event, **fields)
        line = json.dumps(record, sort_keys=True)
        with self.guard:
            with self.path.open('a', encoding='utf-8') as stream:
                stream.write(line + '\n')
            print('[verbose] ' + line, flush=True)

    def network(self, ports):
        from common import port_open
        self.emit('loopback_ports', ports={str(p): port_open(p) for p in ports})
        for host in ('localhost', 'localhost.', '127.0.0.1'):
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 1119, type=socket.SOCK_STREAM)})
                self.emit('portal_resolution', host=host, addresses=addresses)
            except OSError as error:
                self.emit('portal_resolution_failed', host=host, errno=error.errno)

    def catalog(self, target):
        if not self.enabled:
            return
        from common import PINS
        path = target / '.build.info'
        text = path.read_text(encoding='utf-8-sig') if path.exists() else ''
        self.emit('casc_catalog', exists=path.exists(),
                  expected_build_config=PINS['build_config'],
                  expected_cdn_config=PINS['cdn_config'],
                  build_config_matches=PINS['build_config'] in text,
                  cdn_config_matches=PINS['cdn_config'] in text)

    def consume(self, stream, source):
        # Map known messages to fixed events; no raw lines, even on errors.
        with stream:
            for line in stream:
                event = None
                if source == 'hermes':
                    for pattern, name in (
                        ('TLS handshake failed for ', 'tls_handshake_failed'),
                        ('Connecting to auth server...', 'backend_auth_attempt'),
                        ('Authentication succeeded!', 'authentication_succeeded'),
                        ('Authentication failed!', 'authentication_failed'),
                        ('Login failed. Reason:', 'authentication_failed'),
                        ('BNet TLS certificate:', 'tls_certificate_loaded'),
                        ('AuthenticationException', 'tls_exception'),
                        ('SocketException', 'socket_exception'),
                        ('Unhandled exception.', 'unhandled_exception'),
                    ):
                        if pattern in line:
                            event = name
                            break
                    if event is None and re.search(r'Received \d+ realms\.', line):
                        event = 'realm_list_received'
                elif source == 'helper':
                    # Helper emits a deliberately tiny numeric/boolean protocol.
                    match = re.fullmatch(r'WRATH_DIAG ([a-z_]+) (-?\d+)\s*', line)
                    if match and match[1] in {
                        'phase', 'saved_account', 'certificate_match', 'ssl_policy_errors',
                        'http_status', 'client_pid', 'client_exit', 'failure_hresult',
                    }:
                        self.emit('helper_' + match[1], value=int(match[2]))
                        continue
                self.counts[source + '_lines'] += 1
                if event:
                    self.counts[event] += 1
                    # Bound repeated events while retaining totals at shutdown.
                    if self.counts[event] <= 20:
                        self.emit(event, source=source)
        self.emit('output_closed', source=source)
