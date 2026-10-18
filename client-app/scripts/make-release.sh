#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build, sign and package the native SMB app. Optional notarization uses an
# existing Keychain profile; credentials are never accepted on the command line.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IDENTITY="${CLOUDFS_SIGN_IDENTITY:-}"
VERSION="${CLOUDFS_SHORT_VERSION:-0.1.0}"
OUTPUT="${CLOUDFS_RELEASE_DIR:-${PKG_DIR}/dist}"
if [[ -z "$IDENTITY" ]]; then
  echo 'Set CLOUDFS_SIGN_IDENTITY to your Developer ID Application identity.' >&2
  exit 2
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'CLOUDFS_SHORT_VERSION must use major.minor.patch.' >&2
  exit 2
fi
if [[ "${CLOUDFS_SKIP_BUILD:-0}" != 1 ]]; then
  "$SCRIPT_DIR/make-app-smb.sh"
fi
SOURCE="${CLOUDFS_RELEASE_APP:-${PKG_DIR}/build/smb/Build/Products/Release/CloudFSApp.app}"
[[ -x "$SOURCE/Contents/MacOS/cloudfsd" ]] || { echo 'The release app must embed cloudfsd.' >&2; exit 2; }
[[ -x "$SOURCE/Contents/PlugIns/CloudFSFinderSync.appex/Contents/MacOS/CloudFSFinderSync" ]] || { echo 'The release app must embed Finder integration. Build with make-app-smb.sh.' >&2; exit 2; }
[[ -x "$SOURCE/Contents/Frameworks/CloudFSKit.framework/CloudFSKit" ]] || { echo 'The release app must embed the CloudFSKit framework.' >&2; exit 2; }
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
[[ ! -e "$OUTPUT/CloudFS.app" ]] || { echo "Release app already exists in $OUTPUT. Choose a new output directory." >&2; exit 2; }
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/cloudfs-release.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
# A transient Apple timestamp outage must not produce an unsigned or untimestamped
# release. Retry only that specific failure; certificate/entitlement errors stop.
sign_with_retry() {
  local delay output log="$STAGING/codesign-attempt.log"
  for delay in 0 2 5 10; do
    if [[ "$delay" != 0 ]]; then
      echo "Apple timestamp service unavailable; retrying signing in ${delay}s." >&2
      sleep "$delay"
    fi
    if /usr/bin/codesign "$@" > "$log" 2>&1; then
      cat "$log"
      return 0
    fi
    output="$(cat "$log")"
    printf '%s\n' "$output" >&2
    [[ "$output" == *'The timestamp service is not available.'* ||
       "$output" == *'A timestamp was expected but was not found.'* ]] || return 1
  done
  return 1
}
PAYLOAD="$STAGING/payload"
mkdir -p "$PAYLOAD"
APP="$PAYLOAD/CloudFS.app"
ditto "$SOURCE" "$APP"
# Determine the signing team from the selected certificate, never a committed ID.
sign_with_retry --force --sign "$IDENTITY" --options runtime --timestamp "$APP/Contents/MacOS/cloudfsd"
SIGNATURE="$(codesign --display --verbose=4 "$APP/Contents/MacOS/cloudfsd" 2>&1)"
[[ "$SIGNATURE" == *'Authority=Developer ID Application:'* ]] || { echo 'Distribution requires a Developer ID Application certificate.' >&2; exit 2; }
TEAM="$(sed -n 's/^TeamIdentifier=//p' <<< "$SIGNATURE")"
[[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || { echo 'Could not determine signing team.' >&2; exit 2; }
GROUP="$TEAM.dev.cloudfs.client"
cat > "$STAGING/group.entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>com.apple.security.application-groups</key><array><string>$GROUP</string></array>
</dict></plist>
EOF
cat > "$STAGING/finder.entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.application-groups</key><array><string>$GROUP</string></array>
</dict></plist>
EOF
set_group() {
  /usr/libexec/PlistBuddy -c 'Delete :CloudFSAppGroupIdentifier' "$1/Contents/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :CloudFSAppGroupIdentifier string $GROUP" "$1/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$1/Contents/Info.plist"
}
set_group "$APP"
sign_with_retry --force --sign "$IDENTITY" --options runtime --timestamp --entitlements "$STAGING/group.entitlements" "$APP/Contents/MacOS/cloudfsd"
if [[ -d "$APP/Contents/Frameworks" ]]; then
  for FRAMEWORK in "$APP/Contents/Frameworks/"*.framework; do
    [[ -d "$FRAMEWORK" ]] && sign_with_retry --force --sign "$IDENTITY" --options runtime --timestamp "$FRAMEWORK"
  done
fi
if [[ -d "$APP/Contents/PlugIns/CloudFSFinderSync.appex" ]]; then
  FINDER="$APP/Contents/PlugIns/CloudFSFinderSync.appex"
  set_group "$FINDER"
  sign_with_retry --force --sign "$IDENTITY" --options runtime --timestamp --entitlements "$STAGING/finder.entitlements" "$FINDER"
fi
sign_with_retry --force --sign "$IDENTITY" --options runtime --timestamp --entitlements "$STAGING/group.entitlements" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
ln -s /Applications "$PAYLOAD/Applications"
cat > "$PAYLOAD/Read me.txt" <<'EOF'
CloudFS for macOS 14 or later

Drag CloudFS to Applications, open it, and enter your team's server address.
Sign in with your browser, choose a filespace, and click Connect.
Your filespace opens as a normal volume in Finder.
When updating, quit CloudFS and let pending uploads finish before replacing
the app. Restart your Mac after replacement to load the new background engine.
Enable CloudFS Finder Integration in System Settings > General > Login Items
& Extensions > Finder Extensions to use pinning and file links in Finder.

Keep CloudFS running while files are uploading. The app waits for pending
changes to finish before disconnecting. Files needing attention can be saved
as a separate local copy from the dashboard.
EOF
ARCH="$(lipo -archs "$APP/Contents/MacOS/CloudFSApp" | tr ' ' '-')"
for CPU in $(lipo -archs "$APP/Contents/MacOS/CloudFSApp"); do
  lipo -verify_arch "$CPU" "$APP/Contents/MacOS/cloudfsd"
  if [[ -n "${FINDER:-}" ]]; then lipo -verify_arch "$CPU" "$FINDER/Contents/MacOS/CloudFSFinderSync"; fi
  if [[ -d "$APP/Contents/Frameworks/CloudFSKit.framework" ]]; then lipo -verify_arch "$CPU" "$APP/Contents/Frameworks/CloudFSKit.framework/CloudFSKit"; fi
done
DMG="$OUTPUT/CloudFS-${VERSION}-${ARCH}.dmg"
[[ ! -e "$DMG" ]] || { echo "Release already exists: $DMG. Choose a new version/output directory." >&2; exit 2; }
hdiutil create -volname "CloudFS ${VERSION}" -srcfolder "$PAYLOAD" -format UDZO -ov "$DMG"
sign_with_retry --force --sign "$IDENTITY" --timestamp "$DMG"
codesign --verify --verbose=2 "$DMG"
STATUS=signed
if [[ -n "${CLOUDFS_NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$DMG" --keychain-profile "$CLOUDFS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
  xcrun stapler validate "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
  STATUS=notarized
fi
shasum -a 256 "$DMG" > "$DMG.sha256"
printf 'status=%s\nversion=%s\narchitectures=%s\n' "$STATUS" "$VERSION" "$ARCH" > "$DMG.status"
ditto "$APP" "$OUTPUT/CloudFS.app"
echo "Created $STATUS installer: $DMG"
if [[ "$STATUS" != notarized ]]; then
  echo 'Apple notarization remains required for normal Gatekeeper distribution. Set CLOUDFS_NOTARY_PROFILE to a stored notarytool credential profile.'
fi
