"""Pinned source builds; local source patches are kept reviewable in patches/."""

import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from common import PINS, REPO, run, write_json

PATCHES = {
    "wow-patcher": "wow-patcher-universal.patch",
    "cascette-py": "cascette-macos.patch",
    "HermesProxy": None,
}


def source(name, state):
    pin = PINS["sources"][name]
    destination = state / "src" / name
    patch = REPO / "patches" / PATCHES[name] if PATCHES[name] else None
    stamp = destination / ".wrath-source.json"
    # ZIPs and older Windows Git checkouts may contain CRLF despite attributes.
    # Hash and apply the same canonical bytes on every platform.
    patch_bytes = patch.read_bytes().replace(b"\r\n", b"\n") if patch else None
    patch_hash = hashlib.sha256(patch_bytes).hexdigest() if patch_bytes is not None else None
    expected = {"commit": pin["commit"], "patch_sha256": patch_hash}
    if stamp.exists():
        installed = json.loads(stamp.read_text())
        if installed != expected and patch_bytes is not None:
            # Migrate only a known CRLF representation of this exact patch/commit.
            # Different source pins or patch contents still fail below.
            crlf_hash = hashlib.sha256(patch_bytes.replace(b"\n", b"\r\n")).hexdigest()
            if installed == {"commit": pin["commit"], "patch_sha256": crlf_hash}:
                write_json(stamp, expected)
                installed = expected
                from diagnostics import ACTIVE_SETUP
                diag = ACTIVE_SETUP.get()
                if diag is not None:
                    diag.emit('source_patch_line_endings_normalized', component=name)
        if installed != expected:
            raise RuntimeError(
                f"Source pin changed for {name}: installed commit={installed.get('commit')}, "
                f"expected commit={expected['commit']}; installed patch SHA256={installed.get('patch_sha256')}, "
                f"expected patch SHA256={expected['patch_sha256']}. "
                "Source was left unchanged; use a matching source version or a separate --state directory."
            )
        return destination
    if destination.exists():
        # A failed network fetch is resumable; an unknown checkout is not overwritten.
        marker = destination / ".git/wrath-owned"
        if not marker.exists():
            raise RuntimeError("Unknown source directory: " + str(destination))
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "init", str(destination)])
        (destination / ".git/wrath-owned").touch()
        run(["git", "-C", destination, "remote", "add", "origin", pin["url"]])
    run(["git", "-C", destination, "config", "core.autocrlf", "false"])
    run(["git", "-C", destination, "fetch", "--depth=1", "origin", pin["commit"]])
    run(["git", "-C", destination, "checkout", "--detach", pin["commit"]])
    if patch_bytes is not None:
        # Close the file before git opens it (required on Windows).
        with tempfile.TemporaryDirectory(prefix="source-patch-", dir=state) as temporary:
            normalized_patch = Path(temporary) / patch.name
            normalized_patch.write_bytes(patch_bytes)
            run(["git", "-C", destination, "apply", "--check", normalized_patch])
            run(["git", "-C", destination, "apply", normalized_patch])
    write_json(stamp, expected)
    return destination


def version_source(repo):
    # GitVersion traverses history; this build uses an exact commit and explicit version.
    version = PINS["sources"]["HermesProxy"]["version"]
    major, minor, patch = version.split(".")
    from diagnostics import ACTIVE_SETUP
    diag = ACTIVE_SETUP.get()
    command = ["git", "-C", str(repo), "show", "-s", "--format=%cI", "HEAD"]
    date = (diag.run_tool(command).stdout if diag is not None
            else subprocess.check_output(command, text=True)).strip()
    fields = {
        "Major": major,
        "Minor": minor,
        "Patch": patch,
        "MajorMinorPatch": version,
        "CommitsSinceVersionSource": "0",
        "UncommittedChanges": "1",
        "ShortSha": PINS["sources"]["HermesProxy"]["commit"][:7],
        "CommitDate": date,
    }
    code = "// Generated for a pinned patched build.\ninternal static class GitVersionInformation\n{\n"
    code += (
        "".join(
            "    public const string %s = %s;\n" % (key, json.dumps(value))
            for key, value in fields.items()
        )
        + "}\n"
    )
    (repo / "HermesProxy/PinnedBuildVersion.cs").write_text(code)


def build(state):
    sources = {name: source(name, state) for name in PATCHES}
    uv = state / "tools/uv/bin/uv"
    run(
        [
            uv,
            "pip",
            "install",
            "--python",
            sys.executable,
            "--no-deps",
            "--no-build-isolation",
            sources["cascette-py"],
        ]
    )
    run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            sources["wow-patcher"] / "Cargo.toml",
        ]
    )
    # Use an external build directory so no compiled library becomes repository content.
    tls_target = state / "build/tls"
    run(
        [
            "cargo",
            "build",
            "--release",
            "--manifest-path",
            REPO / "tls/Cargo.toml",
            "--target-dir",
            tls_target,
        ]
    )
    version_source(sources["HermesProxy"])
    proxy_version = PINS["sources"]["HermesProxy"]["version"]
    proxy = state / "components/hermes"
    run(
        [
            "dotnet",
            "publish",
            sources["HermesProxy"] / "HermesProxy",
            "--configuration",
            "Release",
            "--runtime",
            "osx-arm64" if platform.machine() == "arm64" else "osx-x64",
            "-p:UsePublishBuildSettings=true",
            "-p:DisableGitVersionTask=true",
            "-p:GenerateGitVersionInformation=false",
            "-p:UpdateVersionProperties=false",
            f"-p:Version={proxy_version}",
            f"-p:AssemblyVersion={proxy_version}",
            f"-p:FileVersion={proxy_version}",
            f"-p:InformationalVersion={proxy_version}-wotlk-classic-macos",
            "-o",
            proxy,
        ]
    )
    return {
        "patcher": sources["wow-patcher"] / "target/release/wow-patcher",
        "tls": tls_target / "release/libwrath_local_tls.dylib",
        "proxy": proxy / "HermesProxy",
        "cascette": sources["cascette-py"],
    }
