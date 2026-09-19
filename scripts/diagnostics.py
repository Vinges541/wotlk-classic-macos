"""Opt-in setup diagnostics with redacted tool output and allowlisted auth events."""
import contextlib
import contextvars
import datetime
import os
import subprocess
import time
import traceback
import uuid
from pathlib import Path
import json
import ipaddress
import platform
import re
import socket
import threading
from collections import Counter


ACTIVE_SETUP = contextvars.ContextVar('setup_diagnostics', default=None)


def sanitize(text):
    """Redact common tool credentials; auth/packet streams never enter this path."""
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(text))
    text = re.sub(r'(?i)(https?://)[^/\s@]+@', r'\1[redacted]@', text)
    text = re.sub(r'(https?://[^\s?#]+)[?#][^\s]*', r'\1?[redacted]', text)
    # Drop the entire line for credential-bearing headers/assignments, including
    # quoted values containing spaces. Do not guess where a secret ends.
    if re.search(r'(?i)(authorization|password|passwd|token|secret|api[_-]?key|cookie)\s*["\']?\s*[:=]|\bBearer\s+|HP-[0-9a-f]{40}|gh[pousr]_[A-Za-z0-9]+|github_pat_', text):
        return '[credential-bearing tool line redacted]'
    return text[:16384]


class Diagnostics:
    def __init__(self, state, enabled=False, session=None):
        self.enabled = enabled
        self.session = session or uuid.uuid4().hex
        self.phase = 'initializing'
        self.client_pid = None
        self.last_client_connections = None
        self.guard = threading.Lock()
        self.path = state / 'verbose.jsonl'
        self.counts = Counter()
        if enabled:
            # Append across invocations; bootstrap and child share a session ID.
            self.path.touch(exist_ok=True)
            print('Verbose diagnostics: ' + str(self.path), flush=True)
            self.emit('environment', python=platform.python_version(), os=platform.system(),
                      release=platform.release(), machine=platform.machine())

    def emit(self, event, **fields):
        if not self.enabled:
            return
        record = dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      event=event, session=self.session, process_id=os.getpid(), **fields)
        line = json.dumps(record, sort_keys=True)
        with self.guard:
            with self.path.open('a', encoding='utf-8') as stream:
                stream.write(line + '\n')
            print('[verbose] ' + line, flush=True)

    @contextlib.contextmanager
    def setup(self):
        token = ACTIVE_SETUP.set(self if self.enabled else None)
        try:
            yield
        finally:
            ACTIVE_SETUP.reset(token)

    def mark(self, phase):
        self.phase = phase
        self.emit('phase_started', phase=phase)

    def failure(self, error, include_message=True):
        self.emit('failure', phase=self.phase, error_type=type(error).__name__,
                  message=sanitize(str(error)) if include_message else '[omitted for authentication]',
                  errno=getattr(error, 'errno', None),
                  winerror=getattr(error, 'winerror', None),
                  returncode=getattr(error, 'returncode', None),
                  frames=[dict(file=Path(frame.filename).name, line=frame.lineno,
                               function=frame.name)
                          for frame in traceback.extract_tb(error.__traceback__)])

    def run_tool(self, argv, **kwargs):
        """Stream build tools only. Arguments/env are deliberately not logged."""
        if not self.enabled:
            return subprocess.run([str(a) for a in argv], check=True, **kwargs)
        program = Path(str(argv[0])).name
        started = time.monotonic()
        self.emit('tool_started', program=program, phase=self.phase)
        output = []
        try:
            with subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True,
                                  encoding='utf-8', errors='replace', **kwargs) as process:
                try:
                    for line in process.stdout:
                        output.append(line[:16384])
                        output = output[-100:]
                        self.emit('tool_output', program=program, text=sanitize(line.rstrip()))
                    code = process.wait()
                except BaseException:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    raise
            self.emit('tool_finished', program=program, returncode=code,
                      elapsed_seconds=round(time.monotonic() - started, 3))
            if code:
                # Do not include argv (which can contain URLs/credentials) in errors.
                raise subprocess.CalledProcessError(code, program)
            return subprocess.CompletedProcess(program, code, ''.join(output))
        except OSError as error:
            self.failure(error)
            raise

    def network(self, ports):
        from common import port_open
        self.emit('loopback_ports', ports={str(p): port_open(p) for p in ports})
        for host in ('localhost', 'localhost.', '127.0.0.1'):
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 1119, type=socket.SOCK_STREAM)})
                self.emit('portal_resolution', host=host, addresses=addresses)
            except OSError as error:
                self.emit('portal_resolution_failed', host=host, errno=error.errno)

    def client_connections(self):
        if not self.enabled or not self.client_pid:
            return
        try:
            result = subprocess.run(['netstat', '-ano'], capture_output=True,
                                    text=True, errors='replace', timeout=4, check=True)
            connections = parse_client_connections(result.stdout, self.client_pid)
            if connections != self.last_client_connections:
                self.emit('client_tcp_connections', connections=connections)
                self.last_client_connections = connections
        except (OSError, subprocess.SubprocessError) as error:
            self.emit('client_tcp_inspection_failed', error_type=type(error).__name__)

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
        from catalog import validate_catalog
        try:
            catalog = validate_catalog(target)
        except (OSError, ValueError) as error:
            self.emit('catalog_validation', accepted=False, error_type=type(error).__name__)
        else:
            self.emit('catalog_validation', accepted=True, build_config=catalog['build_key'],
                      kind=catalog['kind'])

    def consume(self, stream, source):
        # Map known messages to fixed events; no raw lines, even on errors.
        with stream:
            for line in stream:
                event = None
                if source == 'hermes':
                    for pattern, name in (
                        ('TLS handshake failed for ', 'tls_handshake_failed'),
                        ('Accepting connection from ', 'connection_accepted'),
                        ('Client requested service ', 'bnet_service_request'),
                        ('Battlenet.LogonRequest:', 'bnet_logon_rejected'),
                        ('Dropping frame service ', 'bnet_frame_rejected'),
                        ('Malformed frame header from ', 'bnet_frame_malformed'),
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
                        if match[1] == 'client_pid':
                            self.client_pid = int(match[2])
                        self.emit('helper_' + match[1], value=int(match[2]))
                        continue
                self.counts[source + '_lines'] += 1
                if event:
                    self.counts[event] += 1
                    # Bound repeated events while retaining totals at shutdown.
                    if self.counts[event] <= 20:
                        self.emit(event, source=source)
        self.emit('output_closed', source=source)


def parse_client_connections(output, pid):
    """Extract only owning PID, state and ports; omit remote addresses and unrelated processes."""
    connections = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) != 5 or columns[0] != 'TCP' or columns[-1] != str(pid):
            continue
        try:
            local_port = int(columns[1].rsplit(':', 1)[1])
            host, remote_port = columns[2].rsplit(':', 1)
            remote_port = int(remote_port)
            address = ipaddress.ip_address(host.strip('[]').split('%', 1)[0])
            loopback = address.is_loopback or bool(getattr(address, 'ipv4_mapped', None) and address.ipv4_mapped.is_loopback)
        except ValueError:
            continue
        status = columns[3] if columns[3] in {
            'CLOSED', 'LISTENING', 'SYN_SENT', 'SYN_RECEIVED', 'SYN_RECV', 'ESTABLISHED',
            'FIN_WAIT_1', 'FIN_WAIT_2', 'CLOSE_WAIT', 'CLOSING', 'LAST_ACK', 'TIME_WAIT',
        } else 'unknown'
        connections.append(dict(local_port=local_port, remote_port=remote_port,
                                remote_loopback=loopback, state=status))
    return sorted(connections, key=lambda c: (c['local_port'], c['remote_port'], c['state']))[:64]
