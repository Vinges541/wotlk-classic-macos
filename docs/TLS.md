# Local TLS trust

The native client connects to the local proxy using a unique, self-signed leaf certificate with `CA:FALSE`. Its SANs cover `localhost`, `localhost.`, `127.0.0.1` and `::1`.

The Rust helper is loaded only in the native game process. On a recoverable trust failure it compares the peer leaf's complete DER bytes to the installed leaf. Only an exact match is supplied to Security.framework as the sole anchor. The final trust evaluation still checks the certificate's validity and SSL policy. The helper does not fabricate success or disable validation for other hosts.

The private key and PFX are stored in the private state directory with restrictive permissions. The game receives only the public DER certificate. Do not publish the state directory or reuse the same certificate across unrelated installations.

Certificates last 365 days. Setup refuses a certificate with less than seven days remaining. To renew:

1. Close the client and its bridge.
2. Remove only `tls/localhost.crt`, `tls/localhost.der`, `tls/localhost.key` and `tls/localhost.pfx` from your selected state directory.
3. Run the same `./setup.sh install --server ...` command with the same state and target.

The regenerated certificate is installed and the app is re-signed. Never delete account data, CASC data or unrelated certificates as part of renewal.

The app's ad-hoc signature is intentional. Its original executable code sections and original entitlements are retained; its connection data and launch environment change. No system keychain trust operation is used.
