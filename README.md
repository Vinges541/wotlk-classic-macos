# WoTLK Classic HermesProxy Launcher

**English** | [Русский](README.ru.md)

Run **WoTLK Classic 3.4.3.54261** against an existing **AzerothCore 3.3.5a / build 12340** server. The launcher installs the pinned client and starts its local HermesProxy bridge.

| Platform | Status |
|---|---|
| macOS Apple Silicon | Login, character selection and world entry tested |
| macOS Intel | Build path available; gameplay not tested on Intel hardware |
| Windows x64 | Experimental source implementation; client TLS and automatic login need a Windows gameplay test |
| Windows ARM64 | Deferred |

## macOS

Install Apple Command Line Tools (`xcode-select --install`), then run:

```sh
./setup.sh install --server YOUR_SERVER_ADDRESS
./setup.sh remember-account
```

Open **World of Warcraft Classic.app** to play. The optional second command saves your server account in the macOS login Keychain and enables automatic login.

Setup installs missing tools into its private state directory. Allow **30 GiB** for the client, tools and builds.

| Item | Default |
|---|---|
| Client | `~/Games/WotLK Classic` |
| State | `~/Library/Application Support/WoTLK Classic Bridge` |
| Launcher | `~/Applications/World of Warcraft Classic.app` |
| Language | `ruRU` (also supports `enUS`) |
| Server auth port | `3724` |

```sh
./setup.sh install --server server.example --locale enUS --no-launch
./setup.sh install --server server.example --launcher "/Applications/World of Warcraft Classic.app"
./setup.sh run
./setup.sh check
./setup.sh audit
./setup.sh forget-account
```

Use `--target DIRECTORY` for another client location and `--state DIRECTORY` for separate bridge state. Keep supplying the same state on later commands. `--adopt` uses an existing stock client or a verified additive HD catalog; an already patched Mac client additionally requires `--original-executable FILE`.

Existing macOS launcher identifiers, Keychain entries and installation paths remain compatible with the previous `wotlk-classic-macos` name.

## Windows x64 — test build

Requires **Python 3.13+**, **Git** and **.NET SDK 10+** on PATH. From PowerShell in this repository:

```powershell
.\setup.ps1 install --experimental --server YOUR_SERVER_ADDRESS --no-launch
.\setup.ps1 remember-account
.\setup.ps1 run
```

Use `--adopt --target "D:\Games\WotLK Classic"` for an existing **Windows x64 54261** client, including a verified additive HD catalog. Close WoW before installation. The installer creates **Play WotLK Classic.lnk** in the client directory. State defaults to `%LOCALAPPDATA%\WoTLK Classic Bridge`.

The Windows path uses a build-specific data patcher and our small .NET login helper, with no Arctium dependency. The helper saves the password in **Windows Credential Manager**, obtains a new Hermes ticket on each launch, and supplies a DPAPI-encrypted ticket through a separate launcher registry key. `forget-account` removes the saved password.

This path is ready for a controlled Windows test, **not yet verified for gameplay**. In particular, the stock client's certificate acceptance, auth seed and reading of the generated login ticket still need validation. Details and the test sequence: [Windows implementation](docs/WINDOWS.md).

## How launch works

The launcher starts the bridge and local metadata service before opening WoW, then stops its services when the game exits. It refuses occupied ports. Services use loopback ports **1119, 8081, 8084, 8086 and 8090**. Raw authentication and packet output is not saved.

On macOS, automatic login uses a process-local TLS and ticket helper. On Windows, the current probe keeps client code unchanged and uses Hermes' bundled certificate. Neither setup adds a system root certificate.

The repository contains source and configuration templates. Client data is downloaded from historical CASC mirrors; availability depends on those mirrors. HD assets are managed separately by [wotlk-classic-hd](https://github.com/Vinges541/wotlk-classic-hd). The launcher preserves compatible HD catalogs and advertises their active BuildConfig; see [HD validation](docs/WINDOWS.md#existing-hd-installations).

## Development

Exact upstream commits and tool checksums are in [pins.json](pins.json). Components are built from [HermesProxy](https://github.com/Vinges541/HermesProxy), [wow-patcher](https://github.com/wowemulation-dev/wow-patcher), [cascette-py](https://github.com/wowemulation-dev/cascette-py), and this repository's helpers.

```sh
./setup.sh prepare --state "$PWD/.state"
PYTHONPATH=scripts .state/venv/bin/python -m unittest discover -s tests
```

On Windows, `setup.ps1 prepare` builds the pinned dependencies and helper without installing or launching the game.

[Login design](docs/LOGIN.md) · [macOS TLS](docs/TLS.md) · [Validation](docs/VALIDATION.md) · [Third-party licenses](docs/THIRD_PARTY.md)

License: GPL-3.0.

Windows diagnostics: add `--verbose` to `install` or `run` to append setup and launch events to
`%LOCALAPPDATA%\WoTLK Classic Bridge\verbose.jsonl`. Setup tool output and early
errors are included; previous attempts are retained. Close WoW to finish a run log. See [helper update instructions
and diagnostic fields](docs/WINDOWS.md#verbose-diagnostics).

Existing installations in the former state directory are detected automatically
when the new default directory does not exist. Their paths and saved accounts
are retained; the launcher does not move existing state. `--state` and
`WRATH_STATE` still override the default. For verbose logs, use the actual path
printed by the launcher.
