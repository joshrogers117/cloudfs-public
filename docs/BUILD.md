# Build CloudFS from source

Administrators deploying a release should start with [Install CloudFS](../INSTALL.md). They do not need Xcode or an Apple Developer account. These instructions are for maintainers rebuilding the source included in the server package.

## Server and browser console

Use Node.js 22.12 or newer with npm. From the package root:

```sh
npm ci --prefix backend
npm ci --prefix web
npm --prefix backend run typecheck
npm --prefix web run build
```

The production deploy command builds the console and packages it with the Worker. Use the guided installer for a fresh account or the named deployment commands in the installation guide for updates. Do not run a bare `wrangler deploy` against the development configuration.

## Native Mac app

Use macOS, Xcode with Swift 6.1 or newer, its command-line tools, and XcodeGen. From the package root:

```sh
swift test --package-path cloudfsd
swift test --package-path client-app
client-app/scripts/make-app-smb.sh
```

The build script generates the Xcode project and icon, builds the app, shared framework and Finder extension, then embeds the universal SMB engine. Development build output is under `client-app/build/smb/Build/Products/Release/CloudFSApp.app`. It is not a distribution-ready signed app.

For distribution, set `CLOUDFS_SIGN_IDENTITY` to your Developer ID Application identity, `CLOUDFS_SHORT_VERSION` and `CLOUDFS_BUILD_VERSION` to the release versions, and `CLOUDFS_RELEASE_DIR` to a new output directory. Set `CLOUDFS_NOTARY_PROFILE` to an existing notarytool Keychain profile, then run `client-app/scripts/make-release.sh`. This builds, signs, creates a drag-to-Applications DMG, submits notarization and staples its ticket. Keep credentials in Keychain. Without a notary profile the output is signed but explicitly not notarized.

Verify the release under [Publishing requirements](PUBLISHING.md), including the architectures of every embedded component and a fresh installation. Preserve the signing identity for updates. If distributing a fork with a different identity, review bundle identifiers, app groups and Keychain access; it is not automatically interchangeable with the original app.

The server package is a curated source/deployment archive. Private test captures and historical design drafts are excluded. Current qualification and limitations are summarized in [Compatibility](COMPATIBILITY.md). The manifest lists the exact included files; it does not certify that a prebuilt DMG was built from those files.
