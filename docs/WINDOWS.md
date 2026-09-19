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

## Verbose diagnostics

After updating the source, repeat the original
`setup.ps1 install --experimental --server HOST --no-launch` command with the same
state/target (and `--adopt` if applicable). Installation rebuilds the login helper
and records its new hash. `prepare` alone leaves the installed hash outdated. Do not remove the CASC or executable checks to finish an installation.
A missing `installation.json` means installation has not completed in that state;
a catalog mismatch means `.build.info` does not contain the pinned build/CDN keys.

```powershell
.\setup.ps1 run --verbose
```

Reproduce the disconnect, then close WoW normally so the supervisor writes its
summary. Send `%LOCALAPPDATA%\WoTLK Classic Bridge\verbose.jsonl` together with the
client's `Connection.log` and `WowConnection.log`. With `--state`, the diagnostic
file is in that directory. New attempts append to this file; they do not erase
previous failures. Each record carries a session ID and process ID, with the
same session shared by bootstrap and launcher. `--verbose` applies to
install/prepare/run/check/audit and starts before prerequisite checks and pip.
If the state directory cannot be used, setup prints a temporary diagnostic path.
Python itself must be available to start bootstrap and create diagnostics.

The JSONL log includes installation phases (prerequisites, virtual environment,
dependencies, source retrieval, builds, download/adoption, executable checks,
CASC audit, shortcut and installation manifest), redacted stdout/stderr from
Git/pip/.NET/CASC setup tools, command exit codes and elapsed times. Failures
include their phase, exception type/message, OS error codes and Python frame
locations without locals or source-line contents. Tool arguments and environment
variables are not dumped. Common credential headers/assignments and URL userinfo
or query strings are redacted from tool output. Build logs can contain local
paths; they are distinct from game authentication output.

Runtime events include timestamps, OS/Python version, verified component hashes,
localhost resolution, loopback port readiness, process IDs/exit codes, metadata
request/failure totals and an allowlist of Hermes authentication/TLS events.
Unknown proxy output is discarded; repeated events are capped at 20 with totals
retained. No raw packets, account names, passwords, tickets or HTTP bodies are
written. TLS handshake failures are recorded without their raw exception text.

The updated login helper reports saved-account presence, certificate match,
.NET `SslPolicyErrors` flags, HTTP status and numeric failure HRESULT. Phases are
1: credential lookup, 2: certificate/ticket request, 3: encrypted registry ticket,
4: client start. These HTTPS diagnostics apply to the helper; they do **not** prove
that WoW accepts the certificate. Manual login skips the helper's HTTPS request.
A `bridge_ready` event only establishes TCP listeners, not successful TLS/login.

The new default state directory is `WoTLK Classic Bridge`. An existing directory
under the former name is reused if the new directory does not exist. Explicit
`--state` / `WRATH_STATE` settings take precedence; use the log path printed at
startup for existing installations. Internal credential and helper identifiers
remain compatible, preserving saved login.


Patch pins use LF-normalized bytes on all platforms. Older ZIP/Git checkouts
with CRLF patches are normalized before hashing and applying, and a stored hash
for the CRLF representation of the same patch/commit is upgraded automatically.
This does not accept different commits or patch contents. A line-ending-only
`Source pin changed` failure can be retried after updating the launcher using
the existing state; no client download or state deletion is needed for this fix.
