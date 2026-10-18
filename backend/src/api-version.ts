// SPDX-License-Identifier: AGPL-3.0-or-later
/// v3: uploads must honor signed integrity/conditional headers and verify an existing
/// object on retry; object verification precedes metadata commits. Use CloudFS 0.1.2+.
/// Wire-contract version (Audit: version handshake). Bumped on a BREAKING wire change
/// so a client can detect skew. Advertised on `GET /v1/health` (`apiVersion`) and on
/// every response via the `X-CloudFS-API-Version` header. v2 = opaque inode ids (B17):
/// item ids are no longer the path `parent/name`; clients must treat them as opaque and
/// resolve paths by walking the namespace (a v1 client that constructs `parent/name`
/// ids will silently miss). Keep in sync with the CLI's EXPECTED_API_VERSION.
///
/// NOTE: this lives in its own module — NOT exported from `index.ts` — because every
/// named export of the Worker ENTRY module is interpreted by the workerd runtime as a
/// handler / Durable Object class / binding. A bare `export const API_VERSION = 2` on
/// the entry made `wrangler dev`/`deploy` fail to boot ("Incorrect type for map entry
/// 'API_VERSION': not of type 'function or ExportedHandler'"), even though the vitest
/// pool imported it fine. Keep version constants off the entry module.
export const API_VERSION = 3;
