# Publishing a CloudFS preview

Public releases live at [cloudfs-public Releases](https://github.com/joshrogers117/cloudfs-public/releases). Publish a preview until the supported platform and application matrix has been qualified. Do not describe a host/VM rehearsal as a broad production certification.

## Deliverables

| Artifact | Audience | Contents |
| --- | --- | --- |
| `CloudFS-Server-<version>.tar.gz` | Administrator | Guided installer, Worker/console source, lockfiles, deployment/backup tools, current guides, corresponding native source and build instructions. The supplied DMG is included under `macos/CloudFS.dmg`. |
| `CloudFS-<app-version>-x86_64-arm64.dmg` | Teammates | Universal signed/notarized app, embedded background engine and Finder integration. |
| SHA-256 checksums | Both | Integrity check for downloaded archives and DMG. |
| Source tag and release notes | Operators and contributors | Matching source, qualification, limitations, upgrade instructions and license information. |

The customer archive's `README.md` is the installation guide. `release-manifest.json` inventories file hashes and source provenance. Generated third-party notices cover locked runtime dependencies. The manifest is not a cryptographic publisher signature and does not by itself prove binary/source correspondence.

## Build and verify

Use the tools in [Build CloudFS](BUILD.md). Run `bash scripts/check-project.sh`, CLI type checking/tests, and both Swift suites for a source release. Review failed/skipped tests; opt-in live tests are separate from these suites.

Build the universal app with `client-app/scripts/make-release.sh`, a Developer ID identity, explicit app/build versions and an existing notarytool profile. Inspect all embedded component architectures and signatures. The outer DMG must also be notarized and stapled. Verify it with:

```sh
node scripts/check-mac-distribution.mjs /absolute/path/CloudFS.dmg
```

Apple's [distribution guidance](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution) explains container notarization. Never publish an app-only notarization as proof that its DMG is notarized.

From a clean, reviewed source commit, prepare a new candidate:

```sh
node scripts/package-server-release.mjs \
  --version 0.1.36-preview.1 \
  --mac-installer /absolute/path/CloudFS.dmg
```

The packager writes into `dist/releases/`, refuses overwrites and does not publish. It selects approved source paths, checks build-input coverage and documentation links, includes notices and verifies the supplied DMG. Review its manifest: source changes must be committed before packaging. Keep the release source commit/tag and the native build correspondence record with the release.

## Rehearse the recipient experience

Extract the exact archive that will be uploaded. Run `node scripts/install-cloudflare.mjs --check` and follow [INSTALL.md](../INSTALL.md) using an isolated deployment. Exercise initial provisioning, interrupted/resumed setup, first owner, email, invitation acceptance, normal-user browser-to-app sign-in and access restrictions. Rehearse an update without regenerating keys or duplicating resources.

Check upload durability, cold download checksums, remounts, file replacement/open lifetime, concurrent access and snapshot mount/copy/restore. Test the actual editing apps promised by the release. Rehearse independent backup and recovery; record whether recovered objects were also read through the native app.

Test installation on a clean Mac with no prior credentials, cache or approvals where available. Record any retained permissions and untested architectures honestly in [Compatibility](COMPATIBILITY.md). A fresh deployment in an existing Cloudflare account does not test first-account billing or onboarding policies.

## Source and privacy review

- Publish a clean source history. Exclude local deployment profiles, credentials, caches, screenshots, private validation captures and unrelated research.
- Review staged source and generated archives for tokens, personal email addresses, private origins, home paths and embedded account data. Example data should use reserved example domains.
- Preserve dependency license notices. Include the corresponding source and build instructions for shipped components.
- Enable GitHub Issues for support and private vulnerability reporting for security disclosures. No personal email address is required; keep [SECURITY.md](../SECURITY.md) aligned with the repository's actual reporting path.
- Release signing certificates expose the publisher's legal identity. Review this expected distribution metadata separately from accidental personal data in source.

## Publish and verify

Create a versioned source tag and a GitHub prerelease. Attach the server archive, notarized DMG and checksum files. Release notes must identify the app/build version, server package version, supported upgrade path and current limits.

Download the published artifacts again and verify their SHA-256 values. Check the release links, installation guide and private reporting entry point without relying on local files. Keep the exact release artifacts and matching source. Do not silently replace an existing release asset; issue a new version for a changed artifact.

The supported installation path is a guided local terminal program followed by browser setup. A browser-only infrastructure installer is not part of this preview. Ordinary users need only their invitation and the app; they never need provisioning credentials, a setup secret or a development toolchain.
