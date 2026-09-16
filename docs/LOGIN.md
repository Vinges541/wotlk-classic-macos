# Automatic login

Saving an account is opt-in through `./setup.sh remember-account`; `forget-account` removes it. The installer and source repository contain no credentials.

## Flow

1. Wait for all bridge services to be ready. Reopening a running game does not trigger another login.
2. Read the server-scoped generic password item from macOS Keychain. The stored payload contains the game account and password; the service identifier hashes the configured legacy host, port and build.
3. Authenticate through the loopback HTTPS REST endpoint. Validate its hostname, certificate and exact installed leaf hash. The same Hermes legacy authentication path used by manual login checks the password with the configured server.
4. Deliver the fresh ticket and game account once through a private Unix socket. Its directory is mode `0700`, socket mode `0600`, and Darwin's peer PID must resolve to the expected game executable. The listener expires after 45 seconds and removes its socket after delivery or cancellation.
5. Start the native client with `-launcherlogin`. Only the socket path enters the environment. The process-local Rust helper reads the frame into memory and supplies the game's launcher preference keys in domain `net.battle`.
6. The Mac preference reader expects binary `WEB_TOKEN` data decoded through legacy CSSM. The helper supplies its own fixed marker and handles only that exact marker, returning the ticket already received over IPC. All other crypto calls pass through to Security.framework. No saved Battle.net token is decrypted by the helper.
7. Hermes verifies `LogonRequest.cached_web_credentials` through its existing web-ticket handler. Unknown tickets are rejected; program, platform, locale and build validation still run first.

The helper also supplies `GAME_ACCOUNT` and the loopback connection string. A missing or malformed IPC frame returns no token instead of falling back to an unrelated Battle.net credential. It does not write launcher credentials into preference files. Normal login without a saved account continues to work.

The password is held transiently in the launcher's memory while requesting the ticket. The client and proxy necessarily retain their session material while connected. The private state directory contains TLS keys and local settings, so it must not be published. Logs retain fixed status counters rather than raw authentication payloads.

## Validation

Synthetic native tests exercise real CoreFoundation/CSSM calls with the injected library, including valid and malformed frames, wrong peer executable, missing socket, unrelated preference domains and unrelated crypto input. TLS tests reject wrong hostnames and unrelated certificates. Hermes RPC tests cover valid/unknown cached tickets and platform validation.

Native ARM64 login with a real test account has reached the configured legacy world connection without keyboard input. Intel hardware and other client builds have not been tested. This mechanism targets build 3.4.3.54261; it is not a general Battle.net launcher replacement.
