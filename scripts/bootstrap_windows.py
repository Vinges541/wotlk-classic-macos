"""Windows bootstrap: keep Python dependencies in the selected state directory."""
import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from paths import default_state
from diagnostics import Diagnostics

REPO = Path(__file__).resolve().parents[1]


def require_windows():
    if os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise RuntimeError('Windows x64 is required. ARM64 support is deferred.')


def main():
    args = sys.argv[1:]
    if not args or '--help' in args or '-h' in args:
        subprocess.run([sys.executable, str(REPO / 'scripts/windows.py'), '--help'], check=True)
        return
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('--state', type=Path, default=default_state(windows=True))
    options.add_argument('--verbose', action='store_true')
    parsed, _ = options.parse_known_args(args)
    state = parsed.state.expanduser().absolute()
    try:
        if state.resolve() != state:
            raise RuntimeError('State must not contain symlinks or junctions')
        state.mkdir(parents=True, exist_ok=True)
        diag = Diagnostics(state, parsed.verbose)
    except (OSError, RuntimeError) as error:
        # An unwritable state must not hide the very failure being diagnosed.
        if parsed.verbose:
            import tempfile
            diag = Diagnostics(Path(tempfile.mkdtemp(prefix='WoTLK-Classic-setup-')), True)
            diag.mark('state_directory')
            diag.failure(error)
        raise
    diag.emit('bootstrap_started', command=args[0])
    try:
        diag.mark('prerequisites')
        require_windows()
        python = state / 'venv/Scripts/python.exe'
        if args[0] in ('install', 'prepare'):
            for command in ('git', 'dotnet'):
                if not shutil.which(command):
                    raise RuntimeError(f'Install {command} first (Git and .NET SDK 10 are required)')
            if diag.enabled:
                version = diag.run_tool(['dotnet', '--version']).stdout
            else:
                version = subprocess.check_output(['dotnet', '--version'], text=True)
            if int(version.strip().split('.')[0]) < 10:
                raise RuntimeError('.NET SDK 10 or later is required')
            diag.mark('python_environment')
            if not python.exists():
                diag.run_tool([sys.executable, '-m', 'venv', str(state / 'venv')])
            diag.mark('python_dependencies')
            diag.run_tool([str(python), '-m', 'pip', 'install', '--require-hashes', '-r',
                           str(REPO / 'requirements.lock')])
        if not python.exists():
            raise RuntimeError('Run install first')
        env = dict(os.environ, WRATH_STATE=str(state), DOTNET_CLI_TELEMETRY_OPTOUT='1',
                   DOTNET_GENERATE_ASPNET_CERTIFICATE='false',
                   NUGET_PACKAGES=str(state / 'cache/nuget-packages'))
        if diag.enabled:
            env['WOTLK_DIAGNOSTIC_SESSION'] = diag.session
        diag.mark('launcher_process')
        code = subprocess.call([str(python), str(REPO / 'scripts/windows.py'), *args,
                                '--state', str(state)], env=env)
        diag.emit('bootstrap_finished', returncode=code)
        return code
    except BaseException as error:
        diag.failure(error)
        raise


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'Setup: {error}', file=sys.stderr)
        raise SystemExit(1)
