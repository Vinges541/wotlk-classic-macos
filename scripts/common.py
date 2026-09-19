"""Filesystem and process guards shared by setup and launch."""

import contextlib
import hashlib
import json
import os
import socket
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PINS = json.loads((REPO / "pins.json").read_text())


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    temporary.replace(path)


def checked_path(path):
    path = Path(path).expanduser().absolute()
    if path.resolve() != path:
        raise ValueError("Symlinks are not allowed in managed paths: " + str(path))
    return path


def game_processes():
    if os.name == "nt":
        import csv
        rows = csv.reader(subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"], text=True
        ).splitlines())
        return [(int(row[1]), row[0]) for row in rows
                if row and row[0].lower() in ("wow.exe", "wowclassic.exe")]
    result = []
    for line in subprocess.check_output(
        ["ps", "-axo", "pid=,comm="], text=True
    ).splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) == 2 and Path(fields[1]).name.lower() in (
            "wow.exe",
            "wowclassic.exe",
            "world of warcraft classic",
        ):
            result.append((int(fields[0]), fields[1]))
    return result


def game_closed():
    if game_processes():
        raise RuntimeError(
            "Close World of Warcraft before installing or changing components."
        )


@contextlib.contextmanager
def lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except OSError:
        return False


def run(argv, **kwargs):
    from diagnostics import ACTIVE_SETUP
    diag = ACTIVE_SETUP.get()
    if diag is not None:
        return diag.run_tool(argv, **kwargs)
    print("Running " + Path(str(argv[0])).name, flush=True)
    subprocess.run([str(a) for a in argv], check=True, **kwargs)
