# GPGP

[![CI](https://github.com/KwisatzJim/gpgp/actions/workflows/ci.yml/badge.svg)](https://github.com/KwisatzJim/gpgp/actions/workflows/ci.yml)

A Swift companion app and MailKit extension for OpenPGP email on macOS 27. Packaged builds include a private GnuPG runtime and macOS passphrase dialog. Your keys remain in `~/.gnupg`, outside the app. Development builds can use a separately installed engine. This is a development preview. The self-contained 0.2.0 test app and DMG are Developer ID signed, notarized by Apple, and stapled.

No public binary release is available yet. The notarized 0.2.0 DMG is currently a private test artifact; this repository publishes the source and build instructions.

## Using the app

- **Overview:** readiness, personal identity, and Mail instructions.
- **My Key:** select a private key and sender address, inspect your personal fingerprint and expiration, export the public key, or create a private-key recovery backup. **Import Identity** restores a GPGP backup folder (including manifest checksum verification) or a single private-key file. Review the fingerprint before importing; the selected sender is kept until you explicitly choose the restored key. Recovery certificates are stored for backup, never imported as revocations. **Create New Identity** is always available and creates a separate signing key and encryption subkey for a name and email address, valid for one year. It does not change the selected sender; select the new identity explicitly when ready. Backups contain secrets; store them securely.
- **Recipients:** import a public key, compare its fingerprint with the recipient over a trusted channel, and approve the exact fingerprint for an email address. Approval can be removed without deleting the key. Your own key is included in encryption so Sent messages remain readable.
- **Connection:** enable/restart the helper and check GnuPG. Restart the helper after rebuilding it.
- **Diagnostics:** isolated test keys and Mail troubleshooting, separate from personal keys.

In Mail, enable GPGP under Settings → Extensions. Choose your private key and one of its email addresses in **My Key**, click **Use This Identity**, then compose from that address using Mail’s signing/encryption controls. GPGP supports one selected sender identity at a time; switching it keeps your keys and recipient approvals. Missing or invalid selections block signing instead of guessing another key. GnuPG’s native passphrase dialog handles private-key access; the app does not collect the passphrase. GnuPG may cache it for a while, so a dialog on every operation is not expected.

**Keep Undo Send off** under Mail → Settings → Composing. Signed sends with Undo Send enabled crashed this Mail version during testing. Drafts are saved as **unencrypted** editable messages, even when security is selected; protection is applied on send. Decryption integrity and digital signature verification are separate results. Neither verifies the outer From or Subject headers.

## Supported formats and limits

- PGP/MIME detached SHA-256 signing; SHA-256, SHA-384, and SHA-512 verification. Encrypt-only and sign-then-encrypt messages. The declared MIME digest must match GnuPG’s verified signature digest.
- Plain text, HTML, and standard multipart/mixed, multipart/alternative, and multipart/related content with ASCII MIME encoding (including base64 attachments).
- Input messages up to 2 MB; encryption overhead also counts toward the incoming limit. This is a small-message development limit.
- Approved To/Cc recipients, up to 100; encrypted Bcc is blocked. Send separate messages when hiding recipients.
- Local public keys only. No keyserver downloads, automatic imports, inline PGP, key rotation/revocation management, or support for every signature digest and MIME variant.
- Incoming MIME boundaries currently accept letters, digits, underscores, and hyphens. Some other clients’ MIME formats will be rejected explicitly.
- Invalid signatures, missing keys, damaged ciphertext, and unsupported formats produce an explicit error report instead of silently displaying unverified content. The original stored message is retained.

HTML and attachments are covered by isolated cryptographic round-trip tests. The real Mail workflow verified on this Mac is plain-text signing, encrypting, and displaying decrypted mail. Further interoperability testing is needed before relying on other clients’ formats.

## Development

Open `GPGP/GPGP.xcodeproj` in Xcode. Build scheme **GPGP**, using an Apple Development signing identity for all targets. Launch the containing **GPGP.app** to manage setup; choosing Mail as the extension’s run host launches Mail instead of the companion app.

End-user requirements: macOS 27 and Apple Silicon. Self-contained DMGs include GnuPG and pinentry-mac; Homebrew and GPG Suite are not required.

Source-build requirements: Xcode 27.1, and GnuPG with a graphical pinentry program for unbundled development builds. Supported development executable locations are `/opt/homebrew/bin/gpg`, `/usr/local/bin/gpg`, and `/usr/local/MacGPG2/bin/gpg`. Full Disk Access is not required for the current architecture.

The development project uses team `MV65BFBFT7`; another developer must change team and update the matching signing requirements and bundle/service identifiers throughout the project. This is intentional client authentication, not merely a build setting.

Run the regression suite from the project root:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test --scratch-path /tmp/gpgp-swift-tests
```

An optional independent implementation check uses pinned OpenPGP.js 6.3.2 (Node.js 18+). This is a development-only dependency; it is not bundled with the app. Install and run it with:

```sh
npm ci --prefix Scripts/Interop --ignore-scripts
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer npm test --prefix Scripts/Interop
```

It generates disposable OpenPGP.js keys and PGP/MIME messages, verifies/decrypts them through GPGP, then independently verifies/decrypts GPGP’s replies. Exact MIME content bytes are compared in both directions. It sends no mail and accesses no personal keys. The normal Swift suite skips this optional test unless the harness supplies its temporary fixtures. This does not replace real mail-client delivery testing.

Tests create disposable keys in their own temporary keyring, test signatures and tampering, encryption/decryption, HTML/attachment preservation, import review, recipient policy, malformed data, and MailKit line endings. They do not alter the personal keyring or send email.

CI runs the core regression suite, the independent OpenPGP.js check, and an unsigned app/extension build on GitHub’s Xcode 27 runner. It never accesses personal keys or signing credentials.

## Architecture

`GPGP` is the SwiftUI companion. `GPGPMail` is the sandboxed MailKit extension. `GPGPBridge` is the user background helper registered with SMAppService. `Shared` holds their common XPC contract, key metadata/policy, and MailKit MIME transport conversion.

The companion and helper run outside App Sandbox so GnuPG can access its installed dependencies, agent, and local keyring. The Mail extension stays sandboxed and has a narrow Mach-service lookup entitlement. The helper accepts only same-user, correctly signed clients from this app and extension; clients also check the helper’s code signature. No general shell execution API is exposed. The sender selection is pinned by email and fingerprint in `~/Library/Application Support/GPGP/sender.json`, shared by the companion and helper. The Mail extension asks the helper for availability and never reads that unsandboxed file directly. Only an explicit selection is saved; a sole available key is suggested but not automatically activated. Primary signing secrets are required in this version; signing-subkey-only identities are rejected. Existing approved recipients are stored in `~/Library/Application Support/GPGP/recipients.json` with owner-only permissions and checked against usable local keys on each send.

Cryptographic signing uses canonical CRLF MIME bytes. MailKit’s message handoff uses LF bytes. Keeping these boundaries separate fixes the blank-body issue while retaining the signed bytes for verification. Temporary plaintext work files use private directories and are removed after operations; no email content is intentionally logged. This is ordinary file deletion, not a secure-erasure guarantee.

## Artwork

The envelope-and-key app icon was generated for this project with OpenAI image generation. Source artwork: `Design/GPGP-Icon.png`. App Icon and BrandIcon assets are in the companion’s asset catalog. Self-contained builds bundle GnuPG and supporting free-software components; notices are in `Contents/Resources/GnuPG/Licenses`. The matching runtime source archive must accompany redistribution.

## Self-contained runtime packaging

`Scripts/bundle-gnupg.py NEW-RUNTIME --sources SOURCE-DIRECTORY` copies the installed Apple Silicon Homebrew components, records their exact recipes and receipts, and rewrites every non-system dynamic library reference to a bundled path. `Scripts/fetch-runtime-sources.py SOURCE-DIRECTORY` downloads checksum-verified upstream source archives and all recipe patches. The required component licenses are copied into the runtime. This packaging does not bundle any private keys, personal configuration, or passphrase cache.

Copy that runtime into the built app at `Contents/Resources/GnuPG`, then run `Scripts/sign-runtime.py GPGP.app --identity CERTIFICATE`. Sign libraries and nested tools before re-sealing the host app. Include the corresponding-source archive with test deliveries and releases. Existing user `gpg-agent.conf` settings are respected; fresh bundled setups use the included graphical prompt without writing an absolute application path into that file.

Native runtime launchers set a relocatable root via GnuPG’s `gpgconf.ctl`. This handles paths containing spaces and permits moving the app. A packaged runtime is preferred consistently by the app and helper; a damaged runtime does not silently fall back to Homebrew. Tests have passed with `/opt/homebrew` file access denied. A clean-machine interactive passphrase check is still required for the final packaged artifact.

## License

GPGP’s original application code, tests, packaging scripts, and documentation are licensed under the [MIT License](LICENSE), copyright 2026 Jim Kelley.

Bundled third-party programs and libraries retain their own licenses; the MIT license does not replace them. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the runtime inventory, license locations, and corresponding-source packaging requirements. OpenPGP.js is an optional development-only test dependency and is not included in the app.
