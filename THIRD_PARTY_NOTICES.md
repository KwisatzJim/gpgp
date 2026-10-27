# Third-party notices

GPGP’s own source is MIT licensed. The separately executed GnuPG runtime and its libraries remain under their respective upstream licenses. No bundled component is relicensed under MIT.

## Self-contained 0.2.0 runtime

The following inventory records the components actually used for the Apple Silicon test runtime. License expressions below are recorded from the archived Homebrew build recipes; the accompanying upstream license texts are authoritative.

| Component | Packaged version | Recorded license expression |
| --- | --- | --- |
| gnupg | 2.5.24_1 | `"GPL-3.0-or-later"` |
| pinentry-mac | 1.3.1.1 | `all_of: ["GPL-2.0-or-later", "GPL-3.0-or-later"]` |
| gettext | 1.0 | `all_of: [ "GPL-3.0-or-later", "LGPL-2.1-or-later", ]` |
| libgcrypt | 1.12.4 | `all_of: ["LGPL-2.1-or-later", "GPL-2.0-or-later"]` |
| readline | 8.3.6 | `"GPL-3.0-or-later"` |
| libassuan | 3.0.2 | `all_of: [ "LGPL-2.1-or-later", "GPL-3.0-or-later", "FSFULLR", ]` |
| npth | 1.8 | `"LGPL-2.1-or-later"` |
| libgpg-error | 1.61 | `"LGPL-2.1-or-later"` |
| libksba | 1.8.1 | `any_of: ["LGPL-3.0-or-later", "GPL-2.0-or-later"]` |
| gnutls | 3.8.13_2 | `all_of: ["LGPL-2.1-or-later", "GPL-3.0-only"]` |
| libusb | 1.0.30 | `"LGPL-2.1-or-later"` |
| p11-kit | 0.26.5 | `"BSD-3-Clause"` |
| libidn2 | 2.3.8 | `all_of: [ { any_of: ["GPL-2.0-or-later", "LGPL-3.0-or-later"] }, { all_of: ["Unicode-TOU", "Unicode-DFS-2016"] }, "GPL-3.0-or-later", "LGPL-2.1-or-later", "FSFAP-no-warranty-disclaimer", ]` |
| libunistring | 1.5 | `any_of: ["GPL-2.0-or-later", "LGPL-3.0-or-later"]` |
| libtasn1 | 4.21.0 | `"LGPL-2.1-or-later"` |
| nettle | 4.0 | `any_of: ["GPL-2.0-or-later", "LGPL-3.0-or-later"]` |
| gmp | 6.3.0 | `any_of: ["LGPL-3.0-or-later", "GPL-2.0-or-later"]` |

The app contains upstream notices and license texts under `GPGP.app/Contents/Resources/GnuPG/Licenses/<component>/`. The runtime manifest records source URLs and SHA-256 values.

Distribute the matching `GPGP-<version>-runtime-sources.zip` alongside each self-contained binary release. It contains the exact upstream source archives, applicable Homebrew patches and build recipes, build receipts, relocation/signing scripts, and GPGP integration source. Keep component notices intact. GPGP’s MIT license covers only its original code and scripts; upstream source archives and patches keep their original licensing.

## Development-only dependency

The optional interoperability harness in `Scripts/Interop` uses OpenPGP.js 6.3.2, licensed under LGPL-3.0-or-later. Its version and integrity hash are pinned in `package-lock.json`. It is not linked into or shipped with GPGP.app. See the dependency’s included LICENSE file and https://github.com/openpgpjs/openpgpjs.

## Artwork

The envelope-and-key icon was generated for GPGP using OpenAI image generation. Its source image is in `Design/GPGP-Icon.png`.
