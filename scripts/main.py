"""Single entry point for installation, health checks and supervised launch."""

import argparse
import json
import os
import plistlib
import re
import shlex
import shutil
import sys
from pathlib import Path
from common import PINS, REPO, checked_path, game_closed, lock, port_open, write_json


def profile(server, port, state):
    return {
        "ClientOptions": {
            "ClientBuild": "V3_4_3_54261",
            "SeedHex": "179D3DC3235629D07113A9B3867F97A7",
            "ReportedOS": "OSX",
            "ReportedPlatform": "x86",
        },
        "LegacyServerOptions": {"Build": "12340", "Address": server, "Port": port},
        "ProxyNetworkOptions": {
            "ExternalAddress": "127.0.0.1",
            "RestPort": 8081,
            "BNetPort": 1119,
            "RealmPort": 8084,
            "InstancePort": 8086,
            "CertificatePfxPath": str(state / "tls/localhost.pfx"),
        },
        "LoggingOptions": {
            "MinimumLevel": "Information",
            "ServerLevel": "Information",
            "NetworkLevel": "Information",
            "StorageLevel": "Warning",
            "PacketLevel": "Warning",
            "ConsoleLevel": "Information",
            "ToFile": False,
            "Directory": "Logs",
        },
        "DiagnosticsOptions": {
            "PacketsLog": False,
            "EnableMetrics": False,
            "EnableVersionCheck": False,
            "ForwardTransportsV343": True,
        },
        "ThrottlingOptions": {"PartyMemberStateMinIntervalMs": 200},
    }


def install_launcher(state, destination):
    destination = checked_path(destination)
    marker = destination / "Contents/Resources/wotlk-classic-macos.json"
    if destination.exists() and not marker.exists():
        raise RuntimeError(
            "Refusing to replace an unrelated application: " + str(destination)
        )
    if marker.exists() and json.loads(marker.read_text()).get("state") != str(state):
        raise RuntimeError(
            "This launcher belongs to another setup state; choose a different --launcher."
        )
    runtime = state / "runtime"
    runtime.mkdir(exist_ok=True)
    shutil.copytree(
        REPO / "scripts",
        runtime / "scripts",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copyfile(REPO / "pins.json", runtime / "pins.json")
    (destination / "Contents/MacOS").mkdir(parents=True, exist_ok=True)
    marker.parent.mkdir(parents=True, exist_ok=True)
    write_json(marker, {"state": str(state)})
    executable = destination / "Contents/MacOS/Launch"
    executable.write_text(
        "#!/bin/sh\nexport WRATH_STATE="
        + shlex.quote(str(state))
        + "\nexec "
        + shlex.quote(sys.executable)
        + " "
        + shlex.quote(str(runtime / "scripts/main.py"))
        + " run --state "
        + shlex.quote(str(state))
        + " >>"
        + shlex.quote(str(state / "launcher.log"))
        + " 2>&1\n"
    )
    executable.chmod(0o755)
    info = {
        "CFBundleExecutable": "Launch",
        "CFBundleIdentifier": "dev.wotlk-classic-macos.launcher",
        "CFBundleName": "WotLK Classic",
        "CFBundleDisplayName": "WotLK Classic",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "LSUIElement": True,
    }
    (destination / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["install", "prepare", "run", "check", "audit"]
    )
    parser.add_argument("--state", type=Path, default=Path(os.environ["WRATH_STATE"]))
    parser.add_argument(
        "--target", type=Path, default=Path.home() / "Games/WotLK Classic"
    )
    parser.add_argument(
        "--launcher", type=Path, default=Path.home() / "Applications/WotLK Classic.app"
    )
    parser.add_argument("--server")
    parser.add_argument("--auth-port", type=int, default=3724)
    parser.add_argument(
        "--locale",
        choices=[
            "enUS",
            "ruRU",
            "deDE",
            "frFR",
            "esES",
            "esMX",
            "koKR",
            "ptBR",
            "zhCN",
            "zhTW",
        ],
        default="ruRU",
    )
    parser.add_argument("--adopt", action="store_true")
    parser.add_argument(
        "--original-executable",
        type=Path,
        help="Verified original input for adopting a previously patched client",
    )
    parser.add_argument(
        "--shared-lock",
        type=Path,
        help="Optional lock shared with another local WoW launcher",
    )
    parser.add_argument("--no-launch", action="store_true")
    args = parser.parse_args()
    state = checked_path(args.state)
    config_file = state / "installation.json"
    if args.command == "prepare":
        with lock(state / "session.lock"):
            if config_file.exists():
                game_closed()
            from build_tools import build

            build(state)
        print("Pinned tools are ready; no client files were changed.")
        return
    if args.command == "install":
        if not args.server or not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", args.server):
            parser.error("--server must be a hostname or IP address")
        if not 1 <= args.auth_port <= 65535:
            parser.error("Invalid --auth-port")
        target = checked_path(args.target)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Hold the same lock as the launcher for all mutations, including component builds.
        import contextlib

        with contextlib.ExitStack() as stack:
            stack.enter_context(lock(state / "session.lock"))
            if args.shared_lock:
                stack.enter_context(lock(checked_path(args.shared_lock)))
            game_closed()
            existing = (
                json.loads(config_file.read_text()) if config_file.exists() else None
            )
            if existing and existing["target"] != str(target):
                raise RuntimeError("This state belongs to a different --target")
            from build_tools import build

            tools = build(state)
            from client import configure, download_client

            if not args.adopt and not existing:
                download_client(target, state, args.locale)
            from audit import audit

            audit(target, state, args.locale)
            hashes = configure(
                target, state, tools, args.locale, existing, args.original_executable
            )
            write_json(
                state / "hermes.json", profile(args.server, args.auth_port, state)
            )
            launcher = install_launcher(state, args.launcher)
            config = {
                "build": PINS["build"],
                "target": str(target),
                "proxy": str(tools["proxy"]),
                "locale": args.locale,
                "hashes": hashes,
                "launcher": str(launcher),
                "shared_lock": str(checked_path(args.shared_lock))
                if args.shared_lock
                else None,
            }
            write_json(config_file, config)
        print("Ready: " + str(launcher), flush=True)
        if not args.no_launch:
            from bridge import launch

            launch(state, config)
    else:
        if not config_file.exists():
            raise RuntimeError("Run install first with the same --state directory.")
        config = json.loads(config_file.read_text())
        from bridge import PORTS, launch, verify

        target = verify(config)
        if args.command == "run":
            launch(state, config)
        elif args.command == "audit":
            from audit import audit

            audit(target, state, config["locale"])
        else:
            print(
                json.dumps(
                    {
                        "build": config["build"],
                        "component_hashes_verified": True,
                        "ports_open": {str(p): port_open(p) for p in PORTS},
                    },
                    indent=2,
                )
            )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError) as error:
        print("Error: " + str(error), file=sys.stderr)
        raise SystemExit(1)
