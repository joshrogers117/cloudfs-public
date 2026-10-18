#!/usr/bin/env bash
# Self-contained data-path demo: starts MinIO, proves SigV4-presign → MinIO byte-range
# streaming (the exact read path the macOS engine uses), then tears it down.
# No Cloudflare account, no gateway, no signed token. Run from anywhere:
#   ./tools/run-dataplane-demo.sh
#
# The presign is done client-side with the SAME aws4fetch SigV4 the gateway's presign.ts
# uses (the gateway hop is now ACL-gated and needs a bootstrapped org/space + a signed
# token — the old `Bearer dev-token` bypass was retired). The byte-range proof is
# identical either way.
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=/tmp/cloudfs-minio; mkdir -p "$DATA"
echo "▶ starting MinIO (:9000)…"
MINIO_ROOT_USER=localdev MINIO_ROOT_PASSWORD=localdevsecret \
  minio server "$DATA" --address :9000 --console-address :9001 >/tmp/cloudfs-minio.log 2>&1 &
MINIO_PID=$!

cleanup() { kill "$MINIO_PID" 2>/dev/null || true; }
trap cleanup EXIT

curl -sS --retry 40 --retry-connrefused --retry-delay 1 -o /dev/null http://127.0.0.1:9000/minio/health/live
echo "▶ MinIO up — running demo"; echo
node tools/dataplane-demo.mjs
