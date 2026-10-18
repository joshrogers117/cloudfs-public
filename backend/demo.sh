#!/usr/bin/env bash
# RETIRED. This curl walkthrough was written against an early, pre-auth contract:
#   • it authenticated with a static `Bearer dev-token` — that bypass NO LONGER EXISTS;
#     the gateway now verifies a signed session/service token (security/auth.ts).
#   • it addressed items by path-derived ids (`?parent=projectA`) and locked by path —
#     inode ids are now OPAQUE (`ino-<uuid>`, Audit B17), so those calls would 404.
# Running it against the current gateway would only produce 401s/404s, so it is retired
# rather than left as misleading documentation.
#
# To exercise a real gateway end to end:
#   1. Bootstrap an org + admin token:        see backend/BOOTSTRAP.md
#   2. Drive the API with that token via the CLI (the supported client):
#        cloudfs --token "$ADMIN_TOKEN" filespace list
#        cloudfs --token "$ADMIN_TOKEN" ls <filespace> /
#        cloudfs --token "$ADMIN_TOKEN" snapshot list <filespace>
#   3. Prove the byte-range data path (presign -> MinIO 206) without an account:
#        ./tools/run-dataplane-demo.sh
echo "demo.sh is retired — see BOOTSTRAP.md for the real bootstrap+token flow, then drive the API with the 'cloudfs' CLI. For the data-path proof run ./tools/run-dataplane-demo.sh." >&2
exit 64  # EX_USAGE
