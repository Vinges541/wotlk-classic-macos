# Validation scope

## Confirmed locally

- Native 3.4.3.54261 ARM64 launch and Metal rendering on Apple M3 Pro.
- Full pinned CASC recovery: 223,219 selected ruRU objects, with selected content present and indices checked against segment contents.
- Universal patch: five intended data changes in each architecture, code sections unchanged; strict ad-hoc signature verification passes.
- TLS positive case plus negative cases for wrong hostname, unrelated leaf and absence of the pin.
- Native authentication and display of existing characters through Hermes against a 12340 backend.
- Hermes declined-name flag correction builds; nine existing character-list tests pass.
- After deploying the declined-name correction, the tester confirmed successful world entry and character control with the native ruRU client on 2026-09-16. A supplied screenshot shows the character inside Acherus, the in-game UI and AzerothCore server messages.
- A fresh `prepare` run fetched the pinned public sources and built all three native tools without pre-existing build artifacts.
- Twenty-one installer/TLS tests pass; the patched Rust patcher passes 143 tests plus 18 documentation tests.
- The combined read-only audit accepted the existing native client and its CASC store.
- Installer unit tests cover interrupted CASC recovery, corrupt data rejection, unsafe archive paths, symlink refusal and preservation of unrelated WTF settings.

## Managed application launch, 2026-09-16

- Opening the installed launcher through macOS Launch Services started the metadata service, Hermes and the native client. All five local ports were ready, HTTPS login returned HTTP 200 with certificate validation, and native authentication reached the configured legacy server successfully.
- Reopening the application reused the same client and proxy processes. The deployed application and support files run independently of the source checkout.
- Five additional tests cover service readiness before opening the game, attaching to a directly opened client, service cleanup, rejecting a stale proxy PID and resetting counters without retaining raw protocol output.
- This local launcher deployment reuses the game-tested Hermes revision `e4217bfc722e65e7257d5a50084f8a34cb503b34`. Fresh installations use the newer source pin documented below.

## Upstream synchronization, 2026-09-16

- The pinned Hermes commit `15738894be2b255519fa88093e1dc0f0c15abdf7` includes Xian55 `master` at `9a8a9683ab373ccc4dd5df189413707e88ce51de` (tagged v4.5.5), plus the declined-name correction.
- Release publish for `osx-arm64` succeeded. All 16 installer/TLS checks passed, including the four Security.framework checks run with the prepared TLS helper.
- The full Hermes test run on macOS ARM64 with `en_US.UTF-8` reports 2,584 passed, 6 skipped and 1 failed. The failing upstream test, `SocketSendTimeoutTests.SendToAPeerThatNeverReads_TimesOutAndClosesTheConnection`, sets `SendBufferSize = 0`; macOS rejects that setup with `SocketException: Invalid argument` before the timeout assertion. The test file is unchanged from upstream.
- TLS socket tests require permission to create a temporary macOS Keychain. The metrics formatting test assumes a decimal point, so the full test run uses the English locale.
- The confirmed in-game session above used Hermes commit `e4217bfc722e65e7257d5a50084f8a34cb503b34`. Gameplay verification of the newly synchronized build is a separate step.

## Not yet established

- A fresh, complete one-command game download on another Mac. The combined installer packages the locally tested recovery/build/patch steps; it must not be described as a multi-machine tested release.
- Long gameplay sessions, every server module, Intel Macs or every supported locale.
- The root cause of intermittent Metal startup crashes observed during diagnosis.

Successful protocol tests do not establish gameplay compatibility. No private account or server identifiers are needed to reproduce the public tests.
