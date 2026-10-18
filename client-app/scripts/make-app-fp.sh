#!/usr/bin/env bash
#
# make-app-fp.sh — build the macOS client app WITH its embedded File Provider
# extension, code-signed for your Apple Developer team.
#
# Unlike make-app.sh (a quick SwiftPM bundle for the GUI alone, no extension),
# this drives xcodegen + xcodebuild so the appex is a real, signed app extension
# with App Group entitlements — the only way macOS will load a File Provider
# extension.
#
# Signing team: read from CLOUDFS_DEV_TEAM (env) or client-app/.signing.env
# (gitignored). The repo itself stays generic — no team id is committed.
#
# Usage:
#   ./scripts/make-app-fp.sh                 # Debug build into build/
#   CONFIG=Release ./scripts/make-app-fp.sh  # Release build
#
# Output: client-app/build/Build/Products/<Config>/CloudFSApp.app
#         (with Contents/PlugIns/CloudFSFileProvider.appex embedded)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PKG_DIR}"

CONFIG="${CONFIG:-Debug}"

# --- Resolve signing team ---------------------------------------------------
if [[ -z "${CLOUDFS_DEV_TEAM:-}" && -f "${PKG_DIR}/.signing.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "${PKG_DIR}/.signing.env"; set +a
fi
if [[ -z "${CLOUDFS_DEV_TEAM:-}" ]]; then
  echo "error: CLOUDFS_DEV_TEAM is not set (export it, or create client-app/.signing.env)." >&2
  echo "       It is your 10-char Apple Developer Team ID, used for automatic signing." >&2
  exit 2
fi
export CLOUDFS_DEV_TEAM

# --- Tooling check ----------------------------------------------------------
command -v xcodegen >/dev/null 2>&1 || { echo "error: xcodegen not installed (brew install xcodegen)" >&2; exit 2; }

# Refresh the icon before Xcode reads Resources; never reuse an obsolete mark.
swift "${SCRIPT_DIR}/make-icon.swift" "${SCRIPT_DIR}/.icon-build"
cp "${SCRIPT_DIR}/.icon-build/AppIcon.icns" "${PKG_DIR}/Resources/AppIcon.icns"

# --- M7: build the daemon FIRST (the Xcode build phase embeds it) -----------
REPO_DIR="$(cd "${PKG_DIR}/.." && pwd)"
SWIFT_CONFIG="debug"; [[ "${CONFIG}" == "Release" ]] && SWIFT_CONFIG="release"
echo "==> Building cloudfsd (${SWIFT_CONFIG}) -- the embedded engine daemon"
if [[ "${SWIFT_CONFIG}" == "release" ]]; then
  ( cd "${REPO_DIR}/cloudfsd" && swift build -c release )
else
  ( cd "${REPO_DIR}/cloudfsd" && swift build )
fi

echo "==> Generating Xcode project (team ${CLOUDFS_DEV_TEAM})"
xcodegen generate --spec "${PKG_DIR}/project.yml"

echo "==> Building CloudFSApp (${CONFIG}) + embedded File Provider extension"
xcodebuild \
  -project "${PKG_DIR}/CloudFSClient.xcodeproj" \
  -scheme CloudFSApp \
  -configuration "${CONFIG}" \
  -derivedDataPath "${PKG_DIR}/build" \
  DEVELOPMENT_TEAM="${CLOUDFS_DEV_TEAM}" \
  build

APP="${PKG_DIR}/build/Build/Products/${CONFIG}/CloudFSApp.app"

echo ""
echo "==> Done."
echo "    App:    ${APP}"
echo "    Daemon: ${APP}/Contents/MacOS/cloudfsd (launch agent dev.cloudfs.daemon)"
echo "    Appex:  ${APP}/Contents/PlugIns/CloudFSFileProvider.appex (shelved; CLOUDFS_FP_DOMAINS=1)"
echo "    Run:    open \"${APP}\""
