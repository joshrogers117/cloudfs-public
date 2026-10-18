#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Assemble the release app with Finder Sync. make-release.sh signs the result.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PKG_DIR"
command -v xcodegen >/dev/null || { echo 'Install xcodegen to build Finder integration.' >&2; exit 2; }
swift "$SCRIPT_DIR/make-icon.swift" "$SCRIPT_DIR/.icon-build"
xcodegen generate --spec project-smb.yml
xcodebuild -project CloudFSDesktop.xcodeproj -scheme CloudFSApp -configuration Release \
  -derivedDataPath build/smb CODE_SIGNING_ALLOWED=NO \
  MARKETING_VERSION="${CLOUDFS_SHORT_VERSION:-0.1.0}" CURRENT_PROJECT_VERSION="${CLOUDFS_BUILD_VERSION:-1}" build
swift build --package-path ../cloudfsd --scratch-path ../cloudfsd/.build/universal-release --arch arm64 --arch x86_64 -c release --product cloudfsd
DAEMON="$(swift build --package-path ../cloudfsd --scratch-path ../cloudfsd/.build/universal-release --arch arm64 --arch x86_64 -c release --show-bin-path)/cloudfsd"
APP="$PKG_DIR/build/smb/Build/Products/Release/CloudFSApp.app"
cp "$DAEMON" "$APP/Contents/MacOS/cloudfsd"
mkdir -p "$APP/Contents/Library/LaunchAgents"
cp Resources/dev.cloudfs.daemon.plist "$APP/Contents/Library/LaunchAgents/"
echo "Release source assembled: $APP"
