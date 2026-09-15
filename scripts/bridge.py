"""Supervise the loopback bridge and one native client without raw protocol logs."""

import contextlib
import ctypes
import os
import platform
import signal
import subprocess
import threading
import time
from pathlib import Path
from common import checked_path, game_processes, lock, port_open, sha, write_json
from client import APP_REL, EXE_REL
from metadata_server import Handler, ThreadingHTTPServer

PORTS = (1119, 8081, 8084, 8086, 8090)


def session_unlocked():
    cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    cg.CGSessionCopyCurrentDictionary.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFBooleanGetValue.argtypes = [ctypes.c_void_p]
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    session = cg.CGSessionCopyCurrentDictionary()
    if not session:
        return False
    key = cf.CFStringCreateWithCString(None, b"CGSSessionScreenIsLocked", 0x08000100)
    try:
        locked = cf.CFDictionaryGetValue(session, key)
        return not (locked and cf.CFBooleanGetValue(locked))
    finally:
        cf.CFRelease(key)
        cf.CFRelease(session)


def verify(config):
    target = checked_path(config["target"])
    paths = {
        "client": target / EXE_REL,
        "library": target / "LocalConnection/libwrath_local_tls.dylib",
        "certificate": target / "LocalConnection/localhost.der",
        "proxy": Path(config["proxy"]),
    }
    for key, path in paths.items():
        checked_path(path)
        if sha(path) != config["hashes"][key]:
            raise RuntimeError("Installed component changed: " + key)
    return target


def counters(stream, state):
    counts = {
        "backend_auth_succeeded": 0,
        "backend_auth_failed": 0,
        "realm_list_received": 0,
    }
    for line in stream:
        event = None
        if "AuthClient" in line:
            if "Authentication succeeded!" in line:
                event = "backend_auth_succeeded"
            elif "Login failed. Reason:" in line or "Authentication failed!" in line:
                event = "backend_auth_failed"
            elif "Received " in line and " realms." in line:
                event = "realm_list_received"
        # No raw proxy lines, packets, account names or session tickets are retained.
        if event:
            counts[event] += 1
            write_json(state / "connection-status.json", counts)


def launch(state, config):
    if not session_unlocked():
        raise RuntimeError("Unlock the macOS session before launching native WoW.")
    target = verify(config)
    exe, app = target / EXE_REL, target / APP_REL
    running = game_processes()
    if running:
        if len(running) == 1 and running[0][1] == str(exe):
            subprocess.run(["open", "-a", str(app)], check=True)
            return
        raise RuntimeError(
            "Another WoW client is running. Close it before starting Classic."
        )
    with contextlib.ExitStack() as stack:
        stack.enter_context(lock(state / "session.lock"))
        if config.get("shared_lock"):
            stack.enter_context(lock(checked_path(config["shared_lock"])))
        if game_processes():
            raise RuntimeError("A WoW client was started concurrently.")
        occupied = [p for p in PORTS if port_open(p)]
        if occupied:
            raise RuntimeError(
                "Required loopback ports are already occupied: " + str(occupied)
            )
        server = ThreadingHTTPServer(("127.0.0.1", 8090), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        env = dict(
            os.environ,
            DOTNET_DbgEnableMiniDump="0",
            DOTNET_hostBuilder__reloadConfigOnChange="false",
        )
        proxy = subprocess.Popen(
            [config["proxy"], "--config", str(state / "hermes.json")],
            cwd=Path(config["proxy"]).parent,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        threading.Thread(
            target=counters, args=(proxy.stdout, state), daemon=True
        ).start()
        client_pid = None
        stopping = threading.Event()

        def stop(*_):
            stopping.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                if proxy.poll() is not None:
                    raise RuntimeError(
                        "HermesProxy exited during startup (exit %s)" % proxy.returncode
                    )
                if all(port_open(p) for p in PORTS):
                    break
                if stopping.wait(0.2):
                    return
            else:
                raise RuntimeError(
                    "HermesProxy did not become ready within 35 seconds."
                )
            subprocess.run(
                [
                    "open",
                    "--arch",
                    "arm64" if platform.machine() == "arm64" else "x86_64",
                    "-a",
                    str(app),
                    "--stdout",
                    "/dev/null",
                    "--stderr",
                    "/dev/null",
                ],
                check=True,
            )
            for _ in range(100):
                matches = [
                    pid for pid, command in game_processes() if command == str(exe)
                ]
                if matches:
                    if len(matches) != 1:
                        raise RuntimeError("More than one native client was started.")
                    client_pid = matches[0]
                    break
                time.sleep(0.1)
            if not client_pid:
                raise RuntimeError("The native client did not start.")
            write_json(
                state / "running.json",
                {
                    "supervisor_pid": os.getpid(),
                    "proxy_pid": proxy.pid,
                    "client_pid": client_pid,
                },
            )
            print("WoW Classic and its local bridge are running.", flush=True)
            while (
                (client_pid, str(exe)) in game_processes()
                and proxy.poll() is None
                and not stopping.wait(1)
            ):
                pass
            if proxy.poll() is not None:
                raise RuntimeError("HermesProxy stopped while the client was running.")
        finally:
            if proxy.poll() is None:
                proxy.terminate()
                try:
                    proxy.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait()
            server.shutdown()
            server.server_close()
            (state / "running.json").unlink(missing_ok=True)
