"""Install, verify and configure the native client while it is closed."""

import hashlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from common import PINS, REPO, checked_path, game_closed, run, sha, write_json
from macho import architectures

APP_REL = Path("_classic_/World of Warcraft Classic.app")
EXE_REL = APP_REL / "Contents/MacOS/World of Warcraft Classic"


def update_wtf(text, settings):
    for key, value in settings.items():
        if "\n" in value or '"' in value:
            raise ValueError("Invalid config value")
        pattern = r"^SET " + re.escape(key) + r' ".*"$'
        line = f'SET {key} "{value}"'
        if re.search(pattern, text, re.M):
            text = re.sub(pattern, line, text, flags=re.M)
        else:
            text = text.rstrip("\n") + "\n" + line + "\n"
    return text.lstrip("\n")


def download_client(target, state, locale, platform="OSX", arch="x86_64"):
    executable = EXE_REL if platform == "OSX" else Path("_classic_/WowClassic.exe")
    for relative in (
        "Data",
        "Data/data",
        "Data/config",
        "Data/indices",
        "_classic_",
        str(executable),
    ):
        checked_path(target / relative)
    if (
        shutil.disk_usage(target.parent).free < 22 * 1024**3
        and not (target / ".build.info").exists()
    ):
        raise RuntimeError(
            "At least 22 GiB free is required for the initial client download."
        )
    config = {
        "config_dir": str(state / "cache/casc-config"),
        "data_dir": str(state / "cache/casc-metadata"),
        "default_region": "eu",
        "cdn_timeout": 30,
        "cdn_max_retries": 2,
        "mirrors": {
            "product_overrides": {
                "wow_classic": {
                    "urls": [
                        "https://casc.wago.tools",
                        "https://cdn.arctium.tools",
                        "https://archive.wow.tools",
                    ]
                }
            }
        },
        "log_level": "WARNING",
    }
    file = state / "cascette.json"
    write_json(file, config)
    run(
        [
            sys.executable,
            REPO / "scripts/run_install.py",
            "--config",
            file,
            "install",
            "install-to-casc",
            PINS["build_config"],
            PINS["cdn_config"],
            target,
            "--product",
            "wow_classic",
            "--platform",
            platform,
            "--arch",
            arch,
            "--locale",
            locale,
            "--region",
            "eu",
        ]
    )
    if (target / "Data/.install_state.json").exists():
        raise RuntimeError("CASC download is incomplete; repeat setup to resume.")


def expected_sections(original, patcher_source):
    constants = (patcher_source / "src/trinity/mod.rs").read_text()

    def public_key(name):
        value = (
            constants.split(f"pub const {name}:", 1)[1]
            .split("= &[", 1)[1]
            .split("];", 1)[0]
        )
        return bytes(int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", value))

    replacements = [
        (bytes.fromhex("91d59bb7d4e183a5"), public_key("RSA_MODULUS"), 256),
        (
            bytes.fromhex("15d618bd7db577bd"),
            public_key("CRYPTO_ED25519_PUBLIC_KEY"),
            32,
        ),
        (b".actual.battle.net", b".actual.wow.test", 18),
        (
            b"http://%s.patch.battle.net:1119/%s/versions",
            b"http://127.0.0.1:8090/versions",
            43,
        ),
        (b"http://%s.patch.battle.net:1119/%s/cdns", b"http://127.0.0.1:8090/cdns", 40),
    ]
    expected = architectures(original)
    if set(expected) != {0x1000007, 0x100000C}:
        raise ValueError("Expected universal x86_64 + arm64 client")
    for sections in expected.values():
        for pattern, replacement, size in replacements:
            hits = [
                (name, body.find(pattern))
                for name, body in sections.items()
                if pattern in body
            ]
            if len(hits) != 1:
                raise ValueError("Ambiguous or missing client patch site")
            name, offset = hits[0]
            if name not in (("__TEXT", "__const"), ("__TEXT", "__cstring")):
                raise ValueError("Patch would modify executable code")
            body = sections[name]
            if body.count(pattern) != 1:
                raise ValueError("Duplicate client patch site")
            sections[name] = (
                body[:offset] + replacement.ljust(size, b"\0") + body[offset + size :]
            )
    return expected


def certificate(state):
    directory = state / "tls"
    directory.mkdir(mode=0o700, exist_ok=True)
    crt = directory / "localhost.crt"
    if crt.exists():
        result = subprocess.run(
            ["openssl", "x509", "-checkend", "604800", "-noout", "-in", str(crt)],
            stdout=subprocess.DEVNULL,
        )
        if result.returncode:
            raise RuntimeError(
                "Local certificate expires soon; renew it before continuing. See docs/TLS.md."
            )
        return directory
    config = directory / "openssl.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:localhost.,IP:127.0.0.1,IP:::1\n"
    )
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "365",
            "-sha256",
            "-config",
            config,
            "-keyout",
            directory / "localhost.key",
            "-out",
            crt,
        ],
        stderr=subprocess.DEVNULL,
    )
    (directory / "localhost.key").chmod(0o600)
    run(
        [
            "openssl",
            "x509",
            "-in",
            crt,
            "-outform",
            "DER",
            "-out",
            directory / "localhost.der",
        ]
    )
    run(
        [
            "openssl",
            "pkcs12",
            "-export",
            "-inkey",
            directory / "localhost.key",
            "-in",
            crt,
            "-out",
            directory / "localhost.pfx",
            "-passout",
            "pass:",
        ]
    )
    (directory / "localhost.pfx").chmod(0o600)
    return directory


def configure(target, state, tools, locale, existing=None, original_path=None):
    game_closed()
    app = checked_path(target / APP_REL)
    exe = checked_path(target / EXE_REL)
    if not exe.is_file():
        raise RuntimeError("Native macOS client executable is missing")
    info_path = checked_path(app / "Contents/Info.plist")
    info = plistlib.loads(info_path.read_bytes())
    env = info.setdefault("LSEnvironment", {})
    support = checked_path(target / "LocalConnection")
    library, leaf = support / "libwrath_local_tls.dylib", support / "localhost.der"
    checked_path(library)
    checked_path(leaf)
    known = {"DYLD_INSERT_LIBRARIES": str(library), "WRATH_TLS_LEAF_DER": str(leaf)}
    for key, value in known.items():
        if key in env and env[key] != value:
            raise RuntimeError("Conflicting native app launch environment: " + key)
    original = exe.read_bytes()
    # Adoption of an already patched client requires a separately verified original.
    if original_path:
        original = checked_path(original_path).read_bytes()
    if hashlib.sha256(original).hexdigest() == PINS["original_executable_sha256"]:
        expected = expected_sections(original, state / "src/wow-patcher")
        if original_path and architectures(exe.read_bytes()) != expected:
            raise RuntimeError(
                "Existing patched client differs from the reviewed data-only patch"
            )
    elif existing and sha(exe) == existing["hashes"]["client"]:
        expected = architectures(exe.read_bytes())
    else:
        raise RuntimeError(
            "Unexpected client executable. Only build 3.4.3.54261 is supported."
        )
    entitlements = subprocess.check_output(
        ["codesign", "-d", "--entitlements", ":-", str(app)], stderr=subprocess.DEVNULL
    )
    plistlib.loads(entitlements)
    if sha(exe) == PINS["original_executable_sha256"]:
        run(["codesign", "--verify", "--strict", "--deep", "--all-architectures", app])
        temporary = exe.with_name(".wrath-patched")
        run(
            [
                tools["patcher"],
                "-l",
                exe,
                "-o",
                temporary,
                "--bgs-portal-domain",
                "wow.test",
                "--version-url",
                "http://127.0.0.1:8090/versions",
                "--cdns-url",
                "http://127.0.0.1:8090/cdns",
            ]
        )
        if architectures(temporary.read_bytes()) != expected:
            raise RuntimeError("Unexpected Mach-O section change")
        temporary.replace(exe)
    tls = certificate(state)
    support.mkdir(exist_ok=True)
    shutil.copyfile(tools["tls"], library)
    library.chmod(0o755)
    shutil.copyfile(tls / "localhost.der", leaf)
    leaf.chmod(0o644)
    run(["codesign", "--force", "--sign", "-", "--timestamp=none", library])
    env.update(known)
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
    with tempfile.NamedTemporaryFile(suffix=".plist", dir=state) as tmp:
        tmp.write(entitlements)
        tmp.flush()
        run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--entitlements",
                tmp.name,
                "--timestamp=none",
                app,
            ]
        )
    run(["codesign", "--verify", "--strict", "--deep", "--all-architectures", app])
    if architectures(exe.read_bytes()) != expected:
        raise RuntimeError("Signing changed a Mach-O section")
    run(
        [
            "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
            "-f",
            app,
        ]
    )
    wtf = checked_path(target / "_classic_/WTF/Config.wtf")
    wtf.parent.mkdir(exist_ok=True)
    current = wtf.read_text() if wtf.exists() else ""
    settings = {"portal": "localhost.", "gxApi": "MTL"}
    if not current:
        settings.update(
            textLocale=locale,
            audioLocale=locale,
            gxWindow="1",
            gxMaximize="1",
            playIntroMovie="3",
            hwDetect="0",
        )
    wtf.write_text(update_wtf(current, settings))
    return {
        "client": sha(exe),
        "library": sha(library),
        "certificate": sha(leaf),
        "proxy": sha(tools["proxy"]),
    }
