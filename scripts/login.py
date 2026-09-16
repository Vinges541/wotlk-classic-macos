"""Fresh HTTPS login ticket delivered once to the native client over local IPC."""
import ctypes
import hashlib
import http.client
import json
import os
import platform
from pathlib import Path
import re
import socket
import ssl
import tempfile
import threading
import time

from accounts import Keychain, service

TICKET = re.compile(r"HP-[0-9A-Fa-f]{40}\Z")


def authenticate(state, config, credentials):
    context = ssl.create_default_context(cafile=str(state / "tls/localhost.crt"))
    body = json.dumps({"inputs": [
        {"input_id": "account_name", "value": credentials["username"]},
        {"input_id": "password", "value": credentials["password"]},
    ]}).encode()
    locale = config["locale"]
    if not re.fullmatch(r"[a-z]{2}[A-Z]{2}", locale):
        raise RuntimeError("Invalid login locale.")
    with socket.create_connection(("127.0.0.1", 8081), timeout=20) as conn:
        with context.wrap_socket(conn, server_hostname="localhost.") as tls:
            if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() != config["hashes"]["certificate"]:
                raise RuntimeError("Local login certificate changed.")
            client_platform = "MacA" if platform.machine() == "arm64" else "Mc64"
            headers = (f"POST /bnetserver/login/{client_platform}/54261/{locale}/ HTTP/1.1\r\n"
                       "Host: localhost.:8081\r\nContent-Type: application/json\r\n"
                       f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
            tls.sendall(headers + body)
            response = http.client.HTTPResponse(tls)
            response.begin()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise RuntimeError("Local login request failed.")
            data = json.loads(raw)
    if not isinstance(data, dict):
        raise RuntimeError("Invalid local login response.")
    ticket = data.get("login_ticket")
    if data.get("authentication_state") != "DONE" or not isinstance(ticket, str) or not TICKET.fullmatch(ticket):
        raise RuntimeError("Saved game account was not accepted by the server.")
    return ticket.encode("ascii")


def peer_executable(conn):
    # Darwin LOCAL_PEERPID, not user-supplied data. Never inspect command arguments.
    pid = conn.getsockopt(0, 2)
    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    lib.proc_pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    if lib.proc_pidpath(pid, buffer, len(buffer)) <= 0:
        return None
    return os.fsdecode(buffer.value)


class TicketServer:
    """Short-lived private socket; only the expected native executable receives data."""
    def __init__(self, ticket, executable):
        self.ticket = ticket
        self.executable = str(executable)
        self.directory = tempfile.TemporaryDirectory(prefix="wrath-login-", dir="/private/tmp")
        self.path = Path(self.directory.name) / "ticket.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.closed = threading.Event()
        self.delivered = threading.Event()
        try:
            self.server.bind(str(self.path))
            self.path.chmod(0o600)
            self.server.listen(2)
            self.server.settimeout(0.25)
        except BaseException:
            self.server.close()
            self.directory.cleanup()
            raise
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        deadline = time.monotonic() + 45
        try:
            while not self.closed.is_set() and time.monotonic() < deadline:
                try:
                    conn, _ = self.server.accept()
                except socket.timeout:
                    continue
                with conn:
                    if peer_executable(conn) != self.executable:
                        continue
                    conn.settimeout(3)
                    conn.sendall(self.ticket)
                    self.delivered.set()
                    return
        except OSError:
            pass
        finally:
            self.ticket = b""
            self.server.close()
            self.path.unlink(missing_ok=True)

    def close(self):
        self.closed.set()
        self.thread.join(timeout=4)
        self.server.close()
        self.directory.cleanup()


def prepare(state, config, executable, stack):
    profile = json.loads((state / "hermes.json").read_text())
    credentials = Keychain().read(service(profile))
    if credentials is None:
        return []
    ticket = authenticate(state, config, credentials)
    account = credentials["username"].strip().upper().encode("utf-8")
    if not account or len(account) > 640 or any(b in account for b in (0, 10, 13)):
        raise RuntimeError("Saved game account name is invalid.")
    del credentials
    server = TicketServer(ticket + b"\n" + account, executable)
    stack.callback(server.close)
    # The path is not a credential. Password/ticket never enter argv or the environment.
    return ["--env", "WRATH_LOGIN_SOCKET=" + str(server.path), "--args", "-launcherlogin"]
