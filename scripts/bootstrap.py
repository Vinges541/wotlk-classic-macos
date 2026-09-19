"""Bootstrap scoped tools; no system package manager, sudo, or root CA changes."""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from paths import default_state

REPO = Path(__file__).resolve().parents[1]


def state_arg(argv):
    if "--state" in argv:
        return Path(argv[argv.index("--state") + 1]).expanduser().absolute()
    return default_state().expanduser().absolute()


def download(pin, cache):
    cache.mkdir(parents=True, exist_ok=True)
    algorithm = "sha256" if "sha256" in pin else "sha512"
    expected = pin[algorithm].lower()
    path = cache / (expected[:16] + "-" + pin["url"].rsplit("/", 1)[1])

    def valid():
        if not path.is_file():
            return False
        digest = hashlib.new(algorithm)
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest() == expected

    if not valid():
        partial = path.with_suffix(path.suffix + ".part")
        print("Downloading " + pin["url"].rsplit("/", 1)[1], flush=True)
        with (
            urllib.request.urlopen(pin["url"], timeout=60) as source,
            partial.open("wb") as out,
        ):
            shutil.copyfileobj(source, out)
        partial.replace(path)
    if not valid():
        raise RuntimeError("Tool archive checksum mismatch: " + path.name)
    return path


def unpack(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive) as package:
        for member in package.getmembers():
            target = (root / member.name).resolve()
            if root != target and root not in target.parents:
                raise ValueError("Unsafe archive path")
            if member.isdev() or member.isfifo():
                raise ValueError("Unsupported archive member")
            if member.issym() or member.islnk():
                link = (
                    (target.parent if member.issym() else root) / member.linkname
                ).resolve()
                if root != link and root not in link.parents:
                    raise ValueError("Unsafe archive link")
        package.extractall(root)


def main():
    args = sys.argv[1:]
    if not args or "-h" in args or "--help" in args:
        print(
            "Usage: ./setup.sh install --server HOST [--target DIRECTORY] [--state DIRECTORY] [--adopt]\n"
            "       ./setup.sh prepare|run|check|audit [--state DIRECTORY]\n\n"
            "       ./setup.sh remember-account|forget-account [--state DIRECTORY]\n\n"
            "install downloads build 3.4.3.54261, builds patched tools and creates a launcher.\n"
            "--adopt verifies an existing installation instead of downloading game files.\n"
            "Requires macOS and Apple Command Line Tools (xcode-select --install).\n"
            "All other missing tools are installed under --state; no sudo is used."
        )
        return
    if platform.system() != "Darwin":
        raise SystemExit("The launcher requires macOS.")
    if platform.machine() not in ("arm64", "x86_64"):
        raise SystemExit("Unsupported Mac architecture")
    state = state_arg(args)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if state.resolve() != state:
        raise SystemExit("State path must not contain symlinks")
    pins = json.loads((REPO / "pins.json").read_text())
    env = dict(
        os.environ,
        WRATH_STATE=str(state),
        UV_CACHE_DIR=str(state / "cache/uv"),
        UV_PYTHON_INSTALL_DIR=str(state / "tools/python"),
        DOTNET_NOLOGO="1",
        DOTNET_CLI_TELEMETRY_OPTOUT="1",
        DOTNET_GENERATE_ASPNET_CERTIFICATE="false",
        DOTNET_CLI_HOME=str(state / "tools/dotnet-home"),
        NUGET_HTTP_CACHE_PATH=str(state / "cache/nuget-http"),
        NUGET_PACKAGES=str(state / "cache/nuget-packages"),
        CARGO_HOME=str(state / "cache/cargo"),
    )
    # Apple's installed Command Line Tools can be used without changing xcode-select.
    developer = Path("/Library/Developer/CommandLineTools")
    if developer.is_dir():
        env["DEVELOPER_DIR"] = str(developer)
    cpu = platform.machine()
    toolroot = state / "tools"
    uv = toolroot / "uv/bin/uv"
    if not uv.exists():
        with tempfile.TemporaryDirectory(dir=state) as tmp:
            unpack(
                download(pins["tools"]["uv-" + cpu], state / "cache/downloads"),
                Path(tmp),
            )
            executable = next(Path(tmp).glob("*/uv"))
            uv.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(executable, uv)
    venv = state / "venv"
    if not (venv / "bin/python").exists():
        subprocess.run(
            [str(uv), "venv", "--python", "3.13", str(venv)], env=env, check=True
        )
    python = venv / "bin/python"
    if args[0] in ("install", "prepare"):
        subprocess.run(
            ["xcrun", "--find", "clang"], env=env, check=True, stdout=subprocess.DEVNULL
        )
        for tool, executable in [("rust", "cargo"), ("dotnet", "dotnet")]:
            installed = shutil.which(executable)
            if installed:
                version = subprocess.check_output(
                    [installed, "--version"], env=env, text=True
                ).split()[1 if tool == "rust" else 0]
                numbers = tuple(int(x) for x in version.split(".")[:2])
                if numbers >= ((1, 92) if tool == "rust" else (10, 0)):
                    continue
            prefix = toolroot / tool
            expected = prefix / ("bin/cargo" if tool == "rust" else "dotnet")
            if not expected.exists():
                with tempfile.TemporaryDirectory(dir=state) as tmp:
                    unpack(
                        download(
                            pins["tools"][tool + "-" + cpu], state / "cache/downloads"
                        ),
                        Path(tmp),
                    )
                    if tool == "rust":
                        script = next(Path(tmp).glob("*/install.sh"))
                        subprocess.run(
                            [
                                "sh",
                                str(script),
                                "--prefix=" + str(prefix),
                                "--disable-ldconfig",
                                "--without=rust-docs",
                            ],
                            env=env,
                            check=True,
                        )
                    else:
                        prefix.mkdir(parents=True, exist_ok=True)
                        shutil.copytree(tmp, prefix, dirs_exist_ok=True)
            env["PATH"] = str(expected.parent) + os.pathsep + env["PATH"]
            if tool == "dotnet":
                env["DOTNET_ROOT"] = str(prefix)
        subprocess.run(
            [
                str(uv),
                "pip",
                "sync",
                "--python",
                str(python),
                str(REPO / "requirements.lock"),
            ],
            env=env,
            check=True,
        )
    os.execve(str(python), [str(python), str(REPO / "scripts/main.py"), *args], env)


if __name__ == "__main__":
    main()
