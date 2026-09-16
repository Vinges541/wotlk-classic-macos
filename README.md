# WotLK Classic on macOS

Run the **native World of Warcraft Wrath Classic 3.4.3.54261** client with **Metal** against an existing **AzerothCore 3.3.5a / build 12340** server through a local HermesProxy.

This is an experimental client and protocol bridge, not a renderer transplant. It does not add Vulkan or DirectX to macOS, modify the server, or make every Classic feature compatible with a 3.3.5a server.

## One-command setup

Download or clone this repository, open Terminal in it, then run:

```sh
./setup.sh install --server YOUR_SERVER_ADDRESS
```

The script:

1. Installs missing Python, Rust and .NET tools into a private state directory; no `sudo` or Homebrew changes.
2. Fetches exact upstream commits, applies the included reviewed patches and builds the tools.
3. Restores the pinned Mac client from historical CASC mirrors, resuming interrupted transfers.
4. Checks the selected content, CASC indices, original executable hash and Mach-O sections.
5. Patches connection data in both native architectures and preserves executable code sections.
6. Generates a unique local TLS certificate, installs the process-local trust helper and signs the app locally.
7. Creates **WotLK Classic.app** in your user's Applications folder and starts the game with its bridge.

Enter your existing server account in the game. The installer never asks for a game password.

### Requirements

- macOS with Apple Command Line Tools installed: `xcode-select --install`.
- At least **22 GiB free**, plus space for source builds and toolchains. Allow **30 GiB** for a fresh setup.
- Internet access to GitHub, NuGet, Rust/Python distribution servers and the configured historical CASC mirrors.
- A running compatible 3.3.5a server with auth and world ports reachable from your Mac.
- Close other WoW clients during installation and before starting this client.

Apple Silicon is the locally tested architecture. Intel builds are supported by the scripts but have not been tested on an Intel Mac. Apple's Command Line Tools installation and license acceptance remain manual prerequisites.

The historical game files are fetched from external mirrors; their future availability cannot be guaranteed. No game client, Blizzard asset archive, account data or server credentials are included in this repository.

## Paths and options

| Item | Default |
|---|---|
| Client data | `~/Games/WotLK Classic` |
| Tools, local certificate, settings | `~/Library/Application Support/Wrath Classic Bridge` |
| Launcher | `~/Applications/WotLK Classic.app` |
| Text/audio locale | `ruRU` |
| Auth port | `3724` |

```sh
./setup.sh install --server server.example --auth-port 3724 --locale enUS
./setup.sh install --server server.example --target "/Volumes/Games/WotLK Classic"
./setup.sh install --server server.example --no-launch
./setup.sh run
./setup.sh check
./setup.sh audit
```

`--state DIRECTORY` selects a separate setup state and must be supplied consistently. `prepare` builds only the pinned tools. `--adopt --target DIRECTORY` uses an existing **unmodified** Mac 54261 installation instead of downloading it. An already patched client requires `--original-executable FILE`: the original must match the pinned SHA-256, and every section of the installed client must match the expected patch.

The launcher starts Hermes and the pinned metadata service automatically, keeps them alive while the client runs, and stops its own services when the client exits. It refuses occupied ports rather than terminating another service. It does not install a login item or background system service. Move neither the private state directory nor the client directory after installation; rerun setup with the intended paths instead.

## Pinned sources

Exact commits and archive checksums are in [`pins.json`](pins.json).

- [Vinges541/HermesProxy, `wotlk-classic-macos` branch](https://github.com/Vinges541/HermesProxy/tree/wotlk-classic-macos): fork of Xian55/HermesProxy v4.5.3, preserving declined-name flags from legacy servers.
- [wowemulation-dev/wow-patcher](https://github.com/wowemulation-dev/wow-patcher): universal Mach-O support in [`patches/wow-patcher-universal.patch`](patches/wow-patcher-universal.patch).
- [wowemulation-dev/cascette-py](https://github.com/wowemulation-dev/cascette-py): corrected cross-manifest selection and CASC index capacity in [`patches/cascette-macos.patch`](patches/cascette-macos.patch).
- [`tls/`](tls/): Rust process-local exact-leaf trust helper.

Dependencies are built from source. This project does not depend on the author's workstation, compiled artifacts or private paths.

## Validation and known limits

Native ARM64 startup, Metal rendering, BNet/REST authentication and the character list have been verified on an Apple M3 Pro. After the declined-name flag correction, the tester confirmed successful world entry and character control with the ruRU client; a supplied screenshot shows the character inside Acherus. The existing character-list tests also pass. See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the full validation scope.

For Russian names, upstream Hermes v4.5.3 clears a flag meaning “declined names exist or are not required.” This makes the client request name cases even when the backend disabled them. Our fork preserves that flag. It does **not** implement the full declined-name editing protocol for servers that actually require it.

The old Metal client has produced early startup crashes on some attempts; their root cause is not established. Long gameplay sessions, raids, all server modules, Intel hardware and a clean install on another Mac have not been validated. Modern content and protocol differences remain subject to HermesProxy's support.

## Security and troubleshooting

- All bridge services bind to `127.0.0.1`: ports **1119, 8081, 8084, 8086 and 8090**.
- The portal must be **`localhost.`**, including the trailing dot. Bare `localhost` is interpreted by the client as a Battle.net region.
- A unique certificate is generated for each installation. The helper only accepts an exact DER leaf match and then asks Security.framework to check validity and hostname. Unrelated certificates and wrong hostnames still fail.
- No root certificate or system trust exception is installed. The native app gets `LSEnvironment` entries and an ad-hoc signature.
- Raw proxy output, packets, passwords and session tickets are not written to logs. `connection-status.json` contains only fixed counters. `launcher.log` contains setup/launcher errors.
- TLS certificate lifecycle: [`docs/TLS.md`](docs/TLS.md).
- Keep server-side modules and gameplay testing separate from successful client authentication.

## Development

```sh
./setup.sh prepare --state "$PWD/.state"
PYTHONPATH=scripts .state/venv/bin/python -m unittest discover -s tests
cargo fmt --manifest-path tls/Cargo.toml -- --check
cargo clippy --manifest-path tls/Cargo.toml -- -D warnings
```

The Python suite uses the patched cascette package installed by `prepare`. The TLS helper builds only on macOS. CI checks Python behavior and both architecture patch inputs through the source patches; no proprietary game data is uploaded to CI.

License: GPL-3.0. Upstream patch context retains its original licensing; see [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md).
