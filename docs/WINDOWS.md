# Windows x64 probe

## Design

The Windows launcher uses the same HermesProxy and CASC source pins as macOS. It has no Arctium dependency and no injected DLL. `scripts/pe.py` accepts only the SHA-256-pinned stock x64 executable from build 54261 and modifies six data slots: ConnectTo RSA key, Ed25519 key, portal domain, launcher registry prefix, versions URL and CDN URL. Each pattern must occur exactly once, wholly inside a non-executable `.rdata` or `.data` section. Code sections and file size remain unchanged.

`windows/` is a .NET 10 helper with no third-party NuGet packages. It:

- stores an opt-in server account using Windows Credential Manager, scoped to the server address and auth port;
- obtains a fresh ticket from the loopback Hermes REST endpoint, validating the exact certificate from the pinned Hermes source;
- encrypts the ticket with current-user DPAPI and places it in `HKCU\Software\WotLK HermesProxy\Battle.net\Launch Options\WoW`, alongside `GAME_ACCOUNT` and the local `CONNECTION_STRING`;
- starts the client with `-launcherlogin`, waits for it, and removes the temporary registry values after two minutes or on normal exit;
- never places passwords or tickets in process arguments, environment variables or log messages.

A helper crash may leave an encrypted ticket in the private registry branch. The next launch clears it. Its issuing Hermes instance stops when the supervising launcher exits. The game password remains only in Credential Manager until `forget-account` is used.

## Verified and unresolved

Verified offline: six unique patches in the actual stock 54261 Windows x64 file; preserved executable sections and file size; helper cross-build for `win-x64`; synthetic PE rejection and process-lock tests. Windows CI additionally exercises native Credential Manager and DPAPI round trips.

**These checks do not prove login or world entry.** The following remain runtime questions:

1. Does this client accept the bundled Hermes TLS certificate after data-only patching?
2. Does its launcher-login reader consume the current DPAPI/registry representation?
3. Does the client's authentication seed match the configured Hermes seed without a code patch?
4. Does it stay connected through world entry and normal gameplay?

The helper's pinned HTTPS verification secures its own REST request; it does not change WoW's TLS verifier. If the client rejects the certificate, a separate runtime solution must be investigated. Windows code is protected at rest, so macOS function hooks cannot be copied directly. Do not label Windows support stable until these gates pass.

## Test sequence

1. Use a stock Windows x64 54261 client, or let the installer restore one. `--adopt` preserves WTF/account settings, but expects the stock build catalog and executable on first installation. Modified HD catalogs are not yet supported by the install audit.
2. Run `setup.ps1 install --experimental --server HOST --no-launch` and `setup.ps1 check`.
3. Run `setup.ps1 run` without a saved account. Check character selection and world entry using manual login first.
4. Exit, run `setup.ps1 remember-account`, then `setup.ps1 run`. Confirm automatic account login.
5. Exit and relaunch to confirm a fresh ticket is issued. Run `forget-account` and confirm manual login returns.
6. Check that occupied ports are rejected and no bridge process remains after normal game exit.

Use `--state` consistently for isolated tests. macOS Keychain items and installed apps are unaffected. Native Windows ARM64 is deferred; this patcher deliberately rejects ARM64 PE files.
