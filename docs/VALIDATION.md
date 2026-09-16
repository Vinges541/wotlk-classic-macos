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
- Sixteen installer/TLS tests pass; the patched Rust patcher passes 143 tests plus 18 documentation tests.
- The combined read-only audit accepted the existing native client and its CASC store.
- Installer unit tests cover interrupted CASC recovery, corrupt data rejection, unsafe archive paths, symlink refusal and preservation of unrelated WTF settings.

## Not yet established

- A fresh, complete one-command game download on another Mac. The combined installer packages the locally tested recovery/build/patch steps; it must not be described as a multi-machine tested release.
- Long gameplay sessions, every server module, Intel Macs or every supported locale.
- The root cause of intermittent Metal startup crashes observed during diagnosis.

Successful protocol tests do not establish gameplay compatibility. No private account or server identifiers are needed to reproduce the public tests.
