"""Supervise the loopback bridge and one native client without raw protocol logs."""

import contextlib
import ctypes
import json
import os
import platform
import signal
import subprocess
import threading
import time
from pathlib import Path
from common import checked_path, game_processes, lock, port_open, sha, write_json
from client import APP_REL, EXE_REL, update_wtf
from metadata_server import Handler, ThreadingHTTPServer, bind_catalog
import login

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
        "backend_auth_attempts": 0,
        "backend_auth_succeeded": 0,
        "backend_auth_failed": 0,
        "realm_list_received": 0,
    }
    write_json(state / "connection-status.json", counts)
    for line in stream:
        event = None
        if "AuthClient" in line:
            if "Connecting to auth server..." in line:
                event = "backend_auth_attempts"
            elif "Authentication succeeded!" in line:
                event = "backend_auth_succeeded"
            elif "Login failed. Reason:" in line or "Authentication failed!" in line:
                event = "backend_auth_failed"
            elif "Received " in line and " realms." in line:
                event = "realm_list_received"
        # No raw proxy lines, packets, account names or session tickets are retained.
        if event:
            counts[event] += 1
            write_json(state / "connection-status.json", counts)


def existing_client(exe):
    running = game_processes()
    if not running:
        return None
    if len(running) != 1 or running[0][1] != str(exe):
        raise RuntimeError(
            "Another WoW client is running. Close it before starting Classic."
        )
    return running[0][0]


def managed_bridge_ready(state, config, client_pid):
    try:
        running = json.loads((state / "running.json").read_text())
        if running["client_pid"] != client_pid:
            return False
        supervisor, proxy = int(running["supervisor_pid"]), int(running["proxy_pid"])
        if supervisor <= 0 or proxy <= 0:
            return False
        output = subprocess.run(
            ["ps", "-p", f"{supervisor},{proxy}", "-o", "pid=,comm="],
            check=False, capture_output=True, text=True,
        ).stdout
        processes = {}
        for line in output.splitlines():
            fields = line.strip().split(maxsplit=1)
            if len(fields) == 2:
                processes[int(fields[0])] = fields[1]
        return (
            supervisor in processes
            and processes.get(proxy) == config["proxy"]
            and all(port_open(p) for p in PORTS)
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False


def launch(state, config):
    if not session_unlocked():
        raise RuntimeError("Unlock the macOS session before launching native WoW.")
    target = verify(config)
    exe, app = target / EXE_REL, target / APP_REL
    client_pid = existing_client(exe)
    if client_pid and managed_bridge_ready(state, config, client_pid):
        subprocess.run(["open", "-a", str(app)], check=True)
        return
    with contextlib.ExitStack() as stack:
        stack.enter_context(lock(state / "session.lock"))
        if config.get("shared_lock"):
            stack.enter_context(lock(checked_path(config["shared_lock"])))
        # A directly opened client may be waiting on localhost without its bridge.
        # Attach to that same client after starting the missing services.
        client_pid = existing_client(exe)
        occupied = [p for p in PORTS if port_open(p)]
        if occupied:
            raise RuntimeError(
                "Required loopback ports are already occupied: " + str(occupied)
            )
        server = ThreadingHTTPServer(("127.0.0.1", 8090), Handler)
        stack.callback(server.server_close)
        bind_catalog(server, target)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stack.callback(server.shutdown)
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
            login_args = []
            if not client_pid:
                # A client settings reset can restore Blizzard's regional portal.
                # This launcher always connects through the local Hermes bridge.
                wtf = checked_path(target / "_classic_/WTF/Config.wtf")
                current = wtf.read_text() if wtf.exists() else ""
                wtf.parent.mkdir(parents=True, exist_ok=True)
                wtf.write_text(update_wtf(current, {"portal": "localhost."}))
                try:
                    login_args = login.prepare(state, config, exe, stack)
                except (OSError, RuntimeError, ValueError):
                    # Do not log exception bodies from authentication responses.
                    print("Automatic login unavailable; use the game's login form.", flush=True)
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
                ] + login_args,
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
            (state / "running.json").unlink(missing_ok=True)
