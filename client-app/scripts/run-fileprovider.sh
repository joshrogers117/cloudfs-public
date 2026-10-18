#!/usr/bin/env bash
#
# run-fileprovider.sh — bring up the File Provider hybrid for live testing:
#   1. start the cloudfsd daemon bound to the App Group socket (the only socket a
#      sandboxed appex can reach) with decrypted-range spill INTO the App Group
#      container, connected to a real deployment;
#   2. launch the signed CloudFSApp (which embeds the File Provider appex).
#
# After this, sign in to your gateway in the app — it registers an
# NSFileProviderDomain per connected filespace, named after the filespace, so the
# Finder sidebar shows the filespace name and reads stream through the daemon.
#
# Daemon config comes from the environment, or from a gitignored client-app/.fp-test.env
# (so the repo stays generic). Required: CLOUDFS_GATEWAY, CLOUDFS_TOKEN_FILE,
# CLOUDFS_KEY_FILE, CLOUDFS_FILESPACE. Optional: CLOUDFS_CACHE_DIR.
#
# Usage:
#   ./scripts/run-fileprovider.sh           # build app (if needed), start daemon, launch app
#   ./scripts/run-fileprovider.sh stop      # stop the data-path daemon + remove its socket

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${PKG_DIR}/.." && pwd)"
cd "${PKG_DIR}"

GROUP_ID="group.dev.cloudfs.client"
GC="${HOME}/Library/Group Containers/${GROUP_ID}"
SOCK="${GC}/d.sock"
DAEMON="${REPO_DIR}/cloudfsd/.build/arm64-apple-macosx/debug/cloudfsd"
APP="${PKG_DIR}/build/Build/Products/Debug/CloudFSApp.app"
LOG="${GC}/daemon.log"

# --- stop ------------------------------------------------------------------
if [[ "${1:-}" == "stop" ]]; then
  pkill -f "cloudfsd .*${GROUP_ID}/d.sock" 2>/dev/null || true
  rm -f "${SOCK}"
  echo "stopped data-path daemon; removed ${SOCK}"
  exit 0
fi

# --- config ----------------------------------------------------------------
if [[ -f "${PKG_DIR}/.fp-test.env" ]]; then set -a; source "${PKG_DIR}/.fp-test.env"; set +a; fi
: "${CLOUDFS_GATEWAY:?set CLOUDFS_GATEWAY (gateway base URL)}"
: "${CLOUDFS_TOKEN_FILE:?set CLOUDFS_TOKEN_FILE (bearer token file)}"
: "${CLOUDFS_KEY_FILE:?set CLOUDFS_KEY_FILE (filespace master key hex)}"
: "${CLOUDFS_FILESPACE:?set CLOUDFS_FILESPACE (filespace id)}"
: "${CLOUDFS_KEY_FILE_ORG:?set CLOUDFS_KEY_FILE_ORG (authenticated organization ID)}"
CLOUDFS_CACHE_DIR="${CLOUDFS_CACHE_DIR:-/tmp/cfs-fp-cache}"

mkdir -p "${GC}"

# --- build the signed app if missing --------------------------------------
if [[ ! -d "${APP}" ]]; then
  echo "==> Signed app not found; building it first"
  "${SCRIPT_DIR}/make-app-fp.sh"
fi

# --- build the daemon if missing ------------------------------------------
if [[ ! -x "${DAEMON}" ]]; then
  echo "==> Building cloudfsd"
  ( cd "${REPO_DIR}/cloudfsd" && swift build )
fi

# --- start the daemon (idempotent) ----------------------------------------
if pgrep -f "cloudfsd .*${GROUP_ID}/d.sock" >/dev/null 2>&1; then
  echo "==> Data-path daemon already running on ${SOCK}"
else
  echo "==> Starting data-path daemon (socket + decrypted-range spill in App Group container)"
  rm -f "${SOCK}"
  CLOUDFS_SPILL_DIR="${GC}" \
  "${DAEMON}" \
    --gateway "${CLOUDFS_GATEWAY}" \
    --token-file "${CLOUDFS_TOKEN_FILE}" \
    --key-file "${CLOUDFS_KEY_FILE}" \
    --key-filespace "${CLOUDFS_FILESPACE}" \
    --key-gateway "${CLOUDFS_GATEWAY}" \
    --key-org "${CLOUDFS_KEY_FILE_ORG}" \
    --filespace "${CLOUDFS_FILESPACE}" \
    --cache-dir "${CLOUDFS_CACHE_DIR}" \
    --control-socket "${SOCK}" \
    > "${LOG}" 2>&1 &
  for _ in $(seq 1 20); do [[ -S "${SOCK}" ]] && break; sleep 0.25; done
  [[ -S "${SOCK}" ]] && echo "    daemon up; socket: ${SOCK}" || { echo "    daemon failed; see ${LOG}"; tail -5 "${LOG}"; exit 1; }
fi

# --- launch the app --------------------------------------------------------
echo "==> Launching ${APP}"
open "${APP}"

cat <<EOF

Next (in the app):
  1. Sign in to your gateway (URL + service token, or SSO).
  2. The app registers a File Provider domain per connected filespace —
     the Finder sidebar should show "${CLOUDFS_FILESPACE}" (the filespace name).
  3. Open it in Finder and read a file: bytes stream through the appex → daemon → R2.

Logs:   daemon → ${LOG}
        appex  → log stream --predicate 'subsystem == "dev.cloudfs.fileprovider"' --info
Stop:   ./scripts/run-fileprovider.sh stop
EOF
