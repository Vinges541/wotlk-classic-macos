"""Windows bootstrap: keep Python dependencies in the selected state directory."""
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main():
    args = sys.argv[1:]
    if not args or '--help' in args or '-h' in args:
        subprocess.run([sys.executable, str(REPO / 'scripts/windows.py'), '--help'], check=True)
        return
    if os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('Windows x64 is required. ARM64 support is deferred.')
    state = Path(os.environ.get('WRATH_STATE', str(Path(os.environ['LOCALAPPDATA']) / 'Wrath Classic Bridge')))
    if '--state' in args:
        state = Path(args[args.index('--state') + 1])
    state = state.expanduser().absolute()
    if state.resolve() != state:
        raise SystemExit('State must not contain symlinks or junctions')
    state.mkdir(parents=True, exist_ok=True)
    python = state / 'venv/Scripts/python.exe'
    if args[0] in ('install', 'prepare'):
        for command in ('git', 'dotnet'):
            if not shutil.which(command):
                raise SystemExit(f'Install {command} first (Git and .NET SDK 10 are required)')
        if int(subprocess.check_output(['dotnet', '--version'], text=True).split('.')[0]) < 10:
            raise SystemExit('.NET SDK 10 or later is required')
        if not python.exists():
            subprocess.run([sys.executable, '-m', 'venv', str(state / 'venv')], check=True)
        subprocess.run([str(python), '-m', 'pip', 'install', '--require-hashes', '-r',
                        str(REPO / 'requirements.lock')], check=True)
    if not python.exists():
        raise SystemExit('Run install first')
    env = dict(os.environ, WRATH_STATE=str(state), DOTNET_CLI_TELEMETRY_OPTOUT='1',
               DOTNET_GENERATE_ASPNET_CERTIFICATE='false',
               NUGET_PACKAGES=str(state / 'cache/nuget-packages'))
    raise SystemExit(subprocess.call([str(python), str(REPO / 'scripts/windows.py'), *args,
                                      '--state', str(state)], env=env))


if __name__ == '__main__':
    main()
