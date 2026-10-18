#!/usr/bin/env bash
#
# make-app.sh — assemble CloudFSApp.app, a proper macOS application bundle.
#
# Why: `swift run CloudFSApp` runs a raw SwiftPM executable with no bundle and no
# app identity — screen-capture can't grant it and it won't behave like a real
# windowed app. This wraps the built binary in a CloudFSApp.app bundle with a
# proper Info.plist (bundle id dev.cloudfs.client, regular activation, the
# cloudfs:// URL scheme) so `open ./CloudFSApp.app` shows a normal window + Dock
# icon. This is also the first step toward a shippable, signable app.
#
# Usage:
#   ./scripts/make-app.sh             # debug build (fast)
#   ./scripts/make-app.sh release     # release build (-c release)
#   ./scripts/make-app.sh debug       # explicit debug
#
# Output: client-app/CloudFSApp.app   (then: open ./CloudFSApp.app)

set -euo pipefail

# --- Resolve paths (script dir → package root) -------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKG_DIR}"

# --- Config ------------------------------------------------------------------
APP_NAME="CloudFSApp"                  # CFBundleExecutable / .app stem
EXECUTABLE="CloudFSApp"                # the SwiftPM product name
SHORT_VERSION="${CLOUDFS_SHORT_VERSION:-0.1.0}"
BUILD_VERSION="${CLOUDFS_BUILD_VERSION:-1}"

CONFIG="${1:-debug}"
case "${CONFIG}" in
  debug|release) ;;
  *) echo "error: unknown config '${CONFIG}' (use 'debug' or 'release')" >&2; exit 2 ;;
esac

echo "==> Building ${EXECUTABLE} (${CONFIG})"
swift build -c "${CONFIG}" --product "${EXECUTABLE}"

BIN_DIR="$(swift build -c "${CONFIG}" --show-bin-path)"
BIN_PATH="${BIN_DIR}/${EXECUTABLE}"
if [[ ! -x "${BIN_PATH}" ]]; then
  echo "error: built binary not found at ${BIN_PATH}" >&2
  exit 1
fi

# --- Assemble the .app bundle ------------------------------------------------
APP_BUNDLE="${PKG_DIR}/${APP_NAME}.app"
CONTENTS="${APP_BUNDLE}/Contents"
MACOS_DIR="${CONTENTS}/MacOS"
RES_DIR="${CONTENTS}/Resources"

echo "==> Assembling ${APP_BUNDLE}"
rm -rf "${APP_BUNDLE}"
mkdir -p "${MACOS_DIR}" "${RES_DIR}"

# Executable
cp -f "${BIN_PATH}" "${MACOS_DIR}/${APP_NAME}"
chmod +x "${MACOS_DIR}/${APP_NAME}"

# Info.plist (token substitution from the template)
sed -e "s/@SHORT_VERSION@/${SHORT_VERSION}/g" \
    -e "s/@BUILD_VERSION@/${BUILD_VERSION}/g" \
    "${SCRIPT_DIR}/Info.plist.in" > "${CONTENTS}/Info.plist"

# PkgInfo (classic APPL signature; harmless + expected by some tooling)
printf 'APPL????' > "${CONTENTS}/PkgInfo"

# A normal app bundle includes its streaming engine. The Finder extension
# remains available through the signed Xcode build.
echo "==> Building and embedding the background engine"
DAEMON_PKG="${PKG_DIR}/../cloudfsd"
swift build --package-path "${DAEMON_PKG}" -c "${CONFIG}" --product cloudfsd
DAEMON_BIN="$(swift build --package-path "${DAEMON_PKG}" -c "${CONFIG}" --show-bin-path)/cloudfsd"
cp "${DAEMON_BIN}" "${MACOS_DIR}/cloudfsd"
mkdir -p "${CONTENTS}/Library/LaunchAgents"
cp "${PKG_DIR}/Resources/dev.cloudfs.daemon.plist" "${CONTENTS}/Library/LaunchAgents/"
if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - --timestamp=none "${MACOS_DIR}/cloudfsd"
fi

# --- App icon ----------------------------------------------------------------
# Render the canonical purple-drive SVG and copy AppIcon.icns into Resources,
# so the Dock / window / ⌘-Tab show the real cloud-fs mark. Reproducible: the
# mark is rendered fresh every build from scripts/make-icon.swift.
echo "==> Rendering app icon"
ICON_BUILD="${SCRIPT_DIR}/.icon-build"
swift "${SCRIPT_DIR}/make-icon.swift" "${ICON_BUILD}"
cp -f "${ICON_BUILD}/AppIcon.icns" "${RES_DIR}/AppIcon.icns"

# --- Ad-hoc codesign (so LaunchServices/Gatekeeper treat it as a real app) ---
# Ad-hoc (-) signing needs no certificate; it gives the bundle a stable identity
# for the URL-scheme registration and front-window activation. Non-fatal if the
# toolchain lacks codesign.
if command -v codesign >/dev/null 2>&1; then
  echo "==> Ad-hoc codesigning"
  codesign --force --sign - --timestamp=none "${APP_BUNDLE}" 2>/dev/null \
    || echo "    (codesign skipped — bundle still runnable locally)"
fi

# Nudge LaunchServices to (re)register the bundle + its cloudfs:// scheme.
LSREG="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
if [[ -x "${LSREG}" ]]; then
  "${LSREG}" -f "${APP_BUNDLE}" >/dev/null 2>&1 || true
fi

echo ""
echo "==> Done."
echo "    Bundle:  ${APP_BUNDLE}"
echo "    Run:     open \"${APP_BUNDLE}\""
echo "    Bundle id: dev.cloudfs.client   ·   version ${SHORT_VERSION} (${BUILD_VERSION})"
