"""Windows x64 installation and supervised Hermes/native launch."""
import argparse
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import time
import threading
from pathlib import Path

from common import PINS, REPO, checked_path, game_closed, game_processes, lock, port_open, run, sha, write_json

PORTS = (1119, 8081, 8084, 8086, 8090)
EXE = Path('_classic_/WowClassic.exe')


def validate_client(target):
    exe = checked_path(target / EXE)
    with exe.open('rb') as stream:
        if stream.read(2) != b'MZ':
            raise ValueError('Expected a Windows PE executable')
        stream.seek(0x3c)
        offset = struct.unpack('<I', stream.read(4))[0]
        stream.seek(offset)
        if stream.read(6) != b'PE\0\0\x64\x86':
            raise ValueError('Only Windows x64 clients are supported')
    if sha(exe) != PINS['windows_x64_executable_sha256']:
        raise ValueError('Expected the unmodified Windows x64 3.4.3.54261 executable')
    return exe


def build(state):
    from build_tools import source, version_source
    cascette = source('cascette-py', state)
    run([sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-build-isolation', cascette])
    hermes = source('HermesProxy', state)
    source('wow-patcher', state)
    version_source(hermes)
    proxy = state / 'components/hermes'
    launcher = state / 'components/login'
    version = PINS['sources']['HermesProxy']['version']
    run(['dotnet', 'publish', hermes / 'HermesProxy', '-c', 'Release', '-r', 'win-x64',
         '--self-contained', 'true', '-p:DisableGitVersionTask=true',
         '-p:GenerateGitVersionInformation=false', '-p:UpdateVersionProperties=false',
         f'-p:Version={version}', f'-p:AssemblyVersion={version}', f'-p:FileVersion={version}',
         '-o', proxy])
    run(['dotnet', 'publish', REPO / 'windows', '-c', 'Release', '-r', 'win-x64',
         '--self-contained', 'true', '-p:BaseIntermediateOutputPath=' + str(state / 'build/login-obj') + '/',
         '-o', launcher])
    certificate = state / 'tls/BNetServer.pfx'
    certificate.parent.mkdir(exist_ok=True)
    shutil.copyfile(hermes / 'HermesProxy/BNetServer.pfx', certificate)
    return {'proxy': str(proxy / 'HermesProxy.exe'),
            'launcher': str(launcher / 'WrathLogin.exe'),
            'certificate_pfx': str(certificate)}



def proxy_profile(server, port, state):
    from main import profile
    value = profile(server, port, state)
    value['ClientOptions']['ReportedOS'] = 'Win'
    # The first Windows probe uses Hermes' existing bundled certificate.
    value['ProxyNetworkOptions'].pop('CertificatePfxPath')
    return value


def configure(target, state, server, port):
    from client import update_wtf
    config = checked_path(target / '_classic_/WTF/Config.wtf')
    config.parent.mkdir(parents=True, exist_ok=True)
    text = config.read_text(encoding='utf-8') if config.exists() else ''
    config.write_text(update_wtf(text, {'portal': '127.0.0.1'}), encoding='utf-8')
    write_json(state / 'hermes.json', proxy_profile(server, port, state))


def install_launcher(target, state):
    runtime = state / 'runtime'
    shutil.copytree(REPO / 'scripts', runtime / 'scripts', dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copyfile(REPO / 'pins.json', runtime / 'pins.json')
    shortcut = target / 'Play WotLK Classic.lnk'
    if shortcut.exists() and not (state / 'installation.json').exists():
        raise RuntimeError('Refusing to replace an unowned shortcut')
    run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
         runtime / 'scripts/windows-shortcut.ps1', '-Destination', shortcut,
         '-Python', sys.executable, '-Arguments', subprocess.list2cmdline([
             str(runtime / 'scripts/windows.py'), 'run', '--state', str(state)]),
         '-WorkingDirectory', state, '-Icon', target / EXE])


def verify(config):
    target = checked_path(config['target'])
    if sha(target / EXE) != config['hashes']['client']:
        raise RuntimeError('Client changed; repeat installation')
    for key in ('proxy', 'launcher', 'certificate_pfx'):
        if sha(config[key]) != config['hashes'][key]:
            raise RuntimeError(f'{key} changed; repeat installation')
    return target


def wait_ready(proxy, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proxy.poll() is not None:
            raise RuntimeError('HermesProxy stopped before opening its ports')
        if all(port_open(port) for port in PORTS):
            return
        time.sleep(.25)
    raise RuntimeError('HermesProxy startup timed out')


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def launch(state, config):
    with lock(state / 'session.lock'):
        target = verify(config)
        game_closed()
        if any(port_open(port) for port in PORTS):
            raise RuntimeError('A bridge port is occupied; close the other bridge first')
        # Keep the portal on the local bridge even after a client rewrites its WTF.
        configure(target, state, config['server'], config['auth_port'])
        from metadata_server import Handler, ThreadingHTTPServer
        server = ThreadingHTTPServer(('127.0.0.1', 8090), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        proxy = launcher = None
        try:
            proxy = subprocess.Popen([config['proxy'], '--config', str(state / 'hermes.json')],
                                     cwd=Path(config['proxy']).parent,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_ready(proxy)
            launcher = subprocess.Popen([config['launcher'], 'run', str(state / 'installation.json')],
                                        cwd=Path(config['launcher']).parent)
            while launcher.poll() is None:
                if proxy.poll() is not None:
                    raise RuntimeError('HermesProxy stopped; close the game and restart the launcher')
                time.sleep(.5)
            if launcher.returncode:
                raise RuntimeError('Client/login helper exited with an error')
        finally:
            stop(launcher)
            stop(proxy)
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)



def main(argv=None):
    parser = argparse.ArgumentParser(description='WotLK Classic HermesProxy Launcher — Windows x64')
    parser.add_argument('command', choices=('prepare', 'install', 'run', 'check', 'audit', 'remember-account', 'forget-account'))
    parser.add_argument('--state', type=Path, default=Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'Wrath Classic Bridge')
    parser.add_argument('--target', type=Path, default=Path.home() / 'Games/WotLK Classic')
    parser.add_argument('--server')
    parser.add_argument('--auth-port', type=int, default=3724)
    parser.add_argument('--locale', choices=('ruRU', 'enUS'), default='ruRU')
    parser.add_argument('--adopt', action='store_true')
    parser.add_argument('--no-launch', action='store_true')
    parser.add_argument('--experimental', action='store_true', help='Acknowledge Windows gameplay is not yet verified')
    args = parser.parse_args(argv)
    if os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64') or os.environ.get('PROCESSOR_ARCHITEW6432', '').lower() == 'arm64':
        parser.error('This entry point requires Windows x64; native Windows ARM64 is deferred')
    state = checked_path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    os.environ['WRATH_STATE'] = str(state)
    if args.command == 'prepare':
        with lock(state / 'session.lock'):
            build(state)
        return
    if args.command == 'install':
        if not args.experimental:
            parser.error('Windows is a test build: supply --experimental to install it')
        if not args.server or not 1 <= args.auth_port <= 65535:
            parser.error('install requires --server and a valid auth port')
        with lock(state / 'session.lock'):
            game_closed()
            target = checked_path(args.target)
            target.mkdir(parents=True, exist_ok=True)
            prior = state / 'installation.json'
            if prior.exists() and json.loads(prior.read_text())['target'] != str(target):
                raise RuntimeError('State already manages another client; use a different --state')
            tools = build(state)
            if not args.adopt:
                from client import download_client
                download_client(target, state, args.locale, platform='Windows')
            original = state / 'original-WowClassic.exe'
            if sha(target / EXE) == PINS['windows_x64_executable_sha256']:
                shutil.copyfile(target / EXE, original)
            elif not original.exists():
                raise RuntimeError('Original executable is required for patch verification')
            from pe import patch
            patched, report = patch(original.read_bytes(), state / 'src/wow-patcher')
            if sha(target / EXE) != PINS['windows_x64_executable_sha256'] and (target / EXE).read_bytes() != patched:
                raise RuntimeError('Unexpected executable changes; refusing to overwrite')
            from audit import audit
            audit(target, state, args.locale, platform='Windows')
            replacement = target / '_classic_/WowClassic.exe.tmp'
            checked_path(replacement).write_bytes(patched)
            replacement.replace(target / EXE)
            write_json(state / "pe-patches.json", report)
            configure(target, state, args.server, args.auth_port)
            install_launcher(target, state)
            config = dict(tools, target=str(target), server=args.server,
                          auth_port=args.auth_port, locale=args.locale,
                          hashes={**{key: sha(value) for key, value in tools.items()}, "client": sha(target / EXE)})
            write_json(state / 'installation.json', config)
        if not args.no_launch:
            launch(state, config)
        return
    config = json.loads((state / 'installation.json').read_text())
    if args.command in ('remember-account', 'forget-account'):
        if args.command == 'remember-account':
            verify(config)
        run([config['launcher'], 'remember' if args.command == 'remember-account' else 'forget', state / 'installation.json'])
    elif args.command == 'run':
        launch(state, config)
    elif args.command == 'audit':
        from audit import audit
        audit(verify(config), state, config['locale'], platform='Windows')
    else:
        verify(config)
        print('Installed executable hashes verified.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'Launcher: {error}', file=sys.stderr)
        raise SystemExit(1)
