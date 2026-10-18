# cloudfsd — Control-Plane API (the local RPC contract)

> **The seam.** This is the contract for local RPC methods shared by the macOS
> GUI `EngineClient`, `cloudfsd`, and the `cloudfs` CLI. It specifies transport,
> request and response shapes, and error behavior. Release qualification and
> supported behavior are summarized in
> [Compatibility](../docs/COMPATIBILITY.md).

---

## 1. Transport & framing

- **Transport:** Unix-domain socket, JSON-RPC 2.0, **newline-delimited** (one JSON
  object per line, `\n`-terminated). UTF-8.
- **Socket:** `$XDG_RUNTIME_DIR/cloudfsd.sock` (Linux) /
  `~/Library/Application Support/cloudfs/cloudfsd.sock` (macOS); override with
  `cloudfsd --control-socket <path>`. Mode `0600`, owned by the session user —
  filesystem permissions ARE the auth for the local channel. No bearer token on the
  control channel; the gateway token cloudfsd uses for its own outbound HTTPS calls
  is configured at daemon start (`--token-file`), not sent per control request.
- **macOS GUI:** reaches the same logical methods over **NSXPC** (passes FDs for the
  data-path methods in §7). NSXPC and UDS are two encodings of this one method set.
- **Connect failure** (socket absent/unreachable) is the CLI's `ENGINE_UNAVAILABLE`
  / exit 42 — it is a *transport* condition, never a JSON-RPC error on the wire.

### 1.1 Request / response / notification

Standard JSON-RPC 2.0:

```jsonc
// request
{ "jsonrpc": "2.0", "id": 7, "method": "cache.setSize", "params": { ... } }
// success
{ "jsonrpc": "2.0", "id": 7, "result": { ... } }
// error
{ "jsonrpc": "2.0", "id": 7, "error": { "code": -32021, "message": "version conflict", "data": { "expected": 4, "actual": 5 } } }
// server→client notification (event stream, no id)
{ "jsonrpc": "2.0", "method": "transfer", "params": { ... } }
```

`id` may be number or string; the server echoes it. Notifications (events) carry no
`id` and expect no reply.

---

## 2. Error model

One error object `{ code, message, data? }`. `code` maps 1:1 onto the CLI's stable
exit codes (`cli/src/exit-codes.ts`) so the CLI surfaces the right exit code without
a translation table beyond this:

| `code` | `message` class | CLI exit code | Meaning |
|---|---|---|---|
| `-32602` | `invalid_params` | 2 `USAGE` | malformed/missing params |
| `-32010` | `not_connected` | 23 `NOT_CONNECTED` | filespace not connected/mounted |
| `-32020` | `not_found` | 20 `NOT_FOUND` | unknown path / item / filespace |
| `-32021` | `conflict` | 21 `CONFLICT` | optimistic-concurrency / CAS mismatch (`data:{expected,actual}`) |
| `-32022` | `locked` | 22 `LOCKED` | held by another lease (`data:{heldBy,expiresAt}`) |
| `-32030` | `permission_denied` | 30 `PERMISSION_DENIED` | ACL denial surfaced from the gateway |
| `-32040` | `gateway_error` | 40 `GATEWAY_ERROR` | gateway 5xx / presign failure (`data:{status,reason}`) |
| `-32041` | `network_error` | 41 `NETWORK_ERROR` | bucket/gateway unreachable |
| `-32050` | `sync_timeout` | 50 `SYNC_TIMEOUT` | `flush{wait}` deadline exceeded (`data:{pendingUploads,pendingBytes}`) |
| `-32051` | `sync_failed` | 51 `SYNC_FAILED` | an upload failed to commit durably (`data:{path,reason}`) |
| `-32603` | `internal` | 1 `GENERIC` | unexpected engine error |

---

## 3. Shared shapes

```ts
// A filespace as the engine sees it (superset of the CLI Filespace + mount state).
EngineFilespace {
  id: string;                 // gateway space id
  name: string;
  status: "connected" | "connecting" | "disconnected";
  mountPath: string | null;   // null when unmounted
  rootPoint: string | null;   // sub-path mount (RootPoint), or null
  role: string | null;        // caller's effective role
  paused?: boolean;          // authoritative transfer pause, independent of mount presence
}

CacheInfo {                   // matches cli/src/gateway/client.ts CacheInfo exactly
  filespace: string;
  location: string;           // absolute cache dir
  sizeBytes: number;          // current bytes resident
  usedBytes: number;          // == sizeBytes (kept distinct for symmetry with CLI)
  pinnedBytes: number;        // bytes held by pins (non-evictable)
  maxBytes: number;           // the ceiling (the "size" the user set)
  freeOnVolumeBytes: number;  // free space on the cache volume (drives min-free floor)
  hitRate: number;            // 0..1 rolling cache hit rate
}

PinState   {
  path: string;
  pinned: boolean;
  recursive: boolean;
  blocks: number;             // count of RESIDENT blocks the pin covers

  // Per-item byte accounting and state.
  //     Optional: older daemons omit them; decoders MUST tolerate the absence.
  cachedBytes?: number;       // UInt64 — Σ len over the pin's resident blocks now
  totalBytes?: number;        // UInt64 — full size the pin covers
  cacheState?: "pinned" | "pinning";
  failureReason?: string; // retained intent cannot currently finish; never reported fully pinned
}
PrefetchAck{ path: string; queuedBlocks: number }
EvictAck   { path: string; evictedBlocks: number; freedBytes: number }

SyncState {                   // matches cli SyncState
  path: string;
  inSync: boolean;
  pendingUploads: number;
  pendingBytes: number;
}

Transfer {
  id: string;                 // stable per in-flight transfer
  filespace: string;
  path: string;
  direction: "download" | "upload";
  bytesDone: number;
  bytesTotal: number;
  state: "queued" | "active" | "paused" | "done" | "error";
  error?: string;
}

EngineStatus {
  filespace: string;
  connection: "connected" | "connecting" | "disconnected" | "offline";
  mountPath: string | null;
  latencyMsToBucket: number | null;   // deprecated alias of storage.requestDurationMs; NEVER gateway latency
  gatewayLatencyMs?: number;         // EWMA metadata-server request duration
  storage?: StorageTelemetry;
  pendingUploads: number;
  pendingBytes: number;
  cache: CacheInfo;
  health: "green" | "yellow" | "red";
  // Optional, additive (older daemons omit them; clients must treat absence as "unknown"):
  lastSuccessAt?: number;             // epoch ms of the last successful gateway round trip
  lastFailureAt?: number;             // epoch ms of the most recent gateway transport/server failure
  lastFailureReason?: string;         // short, secret-free reason ("network: The Internet connection appears to be offline.")
  reachability?: "online" | "degraded" | "offline";
  mountedRootIds?: string[];          // grant-root ids a granted-folders mount was built from (omitted for whole-filespace / explicit-folder mounts); clients compare with the gateway's current `mount-roots` to offer "Reconnect to see new access"
}
```

**Reachability semantics.** The daemon observes every gateway request per filespace
(only transport failures and server-side errors — `network_error`, `gateway_error`, or a
non-engine error such as a URL-loading failure — count as failures; `not_found`, `conflict`,
`permission_denied` etc. mean the gateway answered and count as successes). With `now` the
status time: `offline` = a failure exists, it is newer than the last success (or there is no
success), and there has been no success in the last 30 s; `degraded` = both a failure and a
success within the last 30 s; otherwise `online`. `reachability` is omitted until the first
request has been observed. Object-store (presigned URL) transfers are not part of this
signal; a failing upload surfaces through `Transfer.error` / `recovery.list`.

**Storage telemetry.** `storage` is independent of gateway reachability. It contains optional `reachability` (`online`/`degraded`, absent when unobserved or older than 30 seconds), `lastSuccessAt`, `lastFailureAt`, `lastFailureReason`, and `requestDurationMs`, plus `requests`, `retries`, `failures`, `activeRequests`, `downloadBytesPerSecond`, and `uploadBytesPerSecond`. Durations include the entire object response body; they are not network ping/RTT. Rates aggregate successfully transferred ciphertext payload bytes in a rolling ten-second window across concurrent requests, excluding failed payloads and protocol overhead. Cache hits do not fabricate network samples. Counters cover this daemon's observation lifetime and are bounded to 256 filespaces. Cancellation retires activity without recording a storage failure. Conditional immutable-PUT collisions are normal responses but still require content verification. No signed URLs or object keys appear in these metrics. Storage failure makes overall health at least yellow; pending writes retain their independent durability state.

---

## 4. Methods — filespace / connection

| Method | Params | Result | Notes / retires |
|---|---|---|---|
| `filespace.list` | `{}` | `EngineFilespace[]` | what the engine currently knows about |
| `filespace.connect` | `{ filespace, rootPoint?, mountAt? }` | `EngineFilespace` | open the metadata client + (optional) mount; CLI `connectFilespace` |
| `filespace.disconnect` | `{ filespace, drain?: boolean }` | `EngineFilespace` | quiesce; if `drain`, flush write-back first; CLI `disconnectFilespace`, GUI `setConnectionState(.disconnected)` |
| `filespace.setConnectionState` | `{ filespace, state: "connected"\|"disconnected" }` | `EngineFilespace` | GUI `setConnectionState` (pause/resume sync) |

---

## 5. Methods — mount / status / cache / pin / transfers / sync

### 5.1 Mount

| Method | Params | Result | Retires |
|---|---|---|---|
| `mount` | `{ filespace, at?: string, rootPoint?: string }` | `EngineFilespace` (with `mountPath`) | CLI `mount`, `daemon` |
| `unmount` | `{ filespace, force?: boolean }` | `EngineFilespace` (with `mountPath:null`) | CLI `unmount` |

### 5.2 Status

| Method | Params | Result | Retires |
|---|---|---|---|
| `status` | `{ filespace? }` | `EngineStatus` (or `EngineStatus[]` if `filespace` omitted) | CLI `status`, GUI menu-bar |

### 5.3 Cache

| Method | Params | Result | Retires |
|---|---|---|---|
| `cache.info` | `{ filespace }` | `CacheInfo` | CLI `cacheInfo`, GUI `cacheSettings` |
| `cache.setSize` | `{ filespace, bytes: number }` | `CacheInfo` | CLI `cacheSetSize`, GUI `updateCacheSettings` |
| `cache.setLocation` | `{ filespace, path: string }` | `CacheInfo` | CLI `cacheSetLocation`, GUI `updateCacheSettings` |
| `cache.clear` | `{ filespace }` | `CacheInfo` | CLI `cache clear` (evicts everything evictable) |

`cache.setSize` shrinking below `usedBytes` triggers immediate eviction to the new
ceiling (respecting pins + min-free). If a pin would exceed the 80% headroom cap,
`cache.setSize` / `pin` returns `-32021 conflict` with `data:{reason:"headroom"}`.

### 5.4 Pin / prefetch / evict

| Method | Params | Result | Retires |
|---|---|---|---|
| `pin` | `{ filespace, path, recursive?: boolean }` | `PinState` | CLI `pin`, GUI `setPinned(true)` |
| `unpin` | `{ filespace, path, recursive?: boolean }` | `PinState` | CLI `unpin`, GUI `setPinned(false)` |
| `pin.list` | `{ filespace }` | `PinState[]` | CLI `pin list`, GUI Pinned Items view |
| `prefetch` | `{ filespace, path }` | `PrefetchAck` (`queuedBlocks`) | CLI `prefetch`/`prehydrate`, GUI `prefetch` |
| `evict` | `{ filespace, path }` | `EvictAck` | GUI `evict` (free space / one-off) |

`pin` persists intent and returns promptly for cold content. Recursive folder pins include all paginated descendants, reserve expected cache capacity before downloading, and follow later remote changes. `failureReason` reports headroom/network/permission failures while keeping the intent available for retry. Cache resizing retries pending pins. See [PINNING.md](PINNING.md) for lifecycle and byte-accounting semantics.

#### `pin.list` per-item byte accounting + cache-state (APPEND-ONLY — WS2 T2.1)

`pin.list` (and the `PinState` returned by `pin` / `unpin`) carries per-item byte
accounting and a materialization state so the GUI Pinned Items view can render
`cachedBytes`, `totalBytes`, and a cache-state per pinned path.
The fields are **appended** — existing fields (`path`, `pinned`, `recursive`,
`blocks`) are unchanged; the new fields are optional for back-compat.

```jsonc
// pin.list  { filespace } -> PinState[]   (one item:)
{
  "path": "projectA/timeline.prproj",  // existing
  "pinned": true,                       // existing
  "recursive": false,                   // existing
  "blocks": 128,                        // existing — count of resident blocks
  "cachedBytes": 67108864,              // APPENDED — UInt64, bytes resident locally now
  "totalBytes": 134217728,              // APPENDED — UInt64, full size the pin covers
  "cacheState": "pinning"               // APPENDED — "pinned" | "pinning"
}
```

- `cachedBytes` = Σ `len` over the pin's **resident** blocks (entries still present
  in the cache index).
- `totalBytes` = the full byte size the pin covers — captured at pin time (and grown
  as more blocks register under the pin). Never less than `cachedBytes`.
- `cacheState` — two states only:
  - `"pinned"`  — fully materialized & non-evictable (`cachedBytes == totalBytes`).
  - `"pinning"` — pin set but still materializing (`0 <= cachedBytes < totalBytes`),
    e.g. while blocks are being fetched, or after an integrity self-heal evicted a
    block of a pinned item.
- `pin.list` only ever returns pinned/pinning items: an unpinned or evicted path has
  no pin record, so it never appears in the list.
- `unpin` (and `evict`) drop the pin record — the path is no longer pinned. `unpin`
  reports the bytes the pin **was** holding with `pinned:false` and no `cacheState`;
  an idempotent unpin of an unpinned path returns `{ cachedBytes:0, totalBytes:0 }`
  with no `cacheState`.

### 5.5 Transfers

| Method | Params | Result | Retires |
|---|---|---|---|
| `transfers.current` | `{ filespace }` | `Transfer[]` | GUI `currentTransfers` |
| `transfers.pause` | `{ filespace }` | `{ paused: true }` | GUI `pauseTransfers` |
| `transfers.resume` | `{ filespace }` | `{ paused: false }` | GUI `resumeTransfers` |

Pause stops admitting background block downloads (explicit prefetch, pin
materialization and read-ahead), uploads, and new file-content commits. Requests
already admitted to the network may finish, including their transport retries;
pause does not abort them or undo a commit already sent. Reads requested by an
open application remain available and can promote a shared background download.
Local writes remain durably journaled while paused; a waiting flush still obeys
its timeout. Resume wakes queued work. Cancellation and disconnect release
paused waiters without discarding pending journal data. Pause is local to the
current filespace session, and is not a suspension of metadata/lease maintenance.

Pending-write admission is daemon-wide across all journal directories beneath the configured cache root. The default allowance is 10 GiB with a 1 GiB free-space reserve, separate from the downloaded-block cache. Configure byte counts with `--pending-write-limit` (`CLOUDFS_PENDING_WRITE_LIMIT`) and `--pending-write-reserve` (`CLOUDFS_PENDING_WRITE_RESERVE`). Zero is accepted; a zero allowance rejects new journal allocation. Existing journals above a reduced limit remain recoverable and may drain, but new allocation is rejected.

`cache.info` adds optional `pendingWriteUsedBytes`, `pendingWriteReservedBytes`, `pendingWriteLimitBytes`, and `pendingWriteFreeSpaceReserveBytes`, all daemon-wide. Capacity rejection returns `syncFailed` with `data.diskFull=true` and a `reason` of `pending_write_limit`, `free_space_reserve`, or `disk_full`; SMB maps it to `STATUS_DISK_FULL`. Previously acknowledged payloads remain intact. A rejected pre-head publication can retry after capacity is freed; an ambiguous write/fsync failure still requires journal verification on reconnect. This is admission control rather than an OS quota, so unrelated disk users can still cause ENOSPC after a successful probe.

### 5.6 Sync barriers

| Method | Params | Result | Retires |
|---|---|---|---|
| `sync.state` | `{ filespace, path }` | `SyncState` | CLI `syncState` (the `wait` poll loop) |
| `flush` | `{ filespace, path, wait?: boolean, timeoutMs?: number }` | `SyncState` | CLI `flush`; with `wait:true` it is the durability barrier `cloudfs wait` needs |

`flush` semantics:
- `wait:false` (default) — drain the staged Slices for `path` into the upload queue,
  fsync the journal, return the current `SyncState` immediately (`flush` command).
- `wait:true` — block until every upload under `path` is **durably committed to the
  bucket and CAS'd on the DO**, or until `timeoutMs` elapses → `-32050 sync_timeout`
  (CLI exit 50). An upload that fails terminally → `-32051 sync_failed` (exit 51).
  A render script can wait for remote durability before starting its next step. (The CLI may still implement `wait` as a `sync.state`
  poll loop as today, but `flush{wait:true}` is the efficient server-side barrier.)

---

## 6. Event stream

A client subscribes once per connection; the server streams JSON-RPC **notifications**
until the connection (or `events.unsubscribe`) closes. Backs the GUI
`transferUpdates`/`activityUpdates` `AsyncStream`s and the CLI `events`/`watch`
NDJSON output.

| Method | Params | Result |
|---|---|---|
| `events.subscribe` | `{ filespace?, kinds?: ("transfer"\|"activity"\|"cache"\|"mount")[] }` | `{ subscribed: true }` then a stream of notifications |
| `events.unsubscribe` | `{}` | `{ subscribed: false }` |

Notification methods + `params`:

```ts
// method: "transfer"  — drives GUI transferUpdates + Finder upload/download pie
{ filespace, transfer: Transfer }

// method: "activity"  — local + remote activity (remote sourced from gateway change feed)
{ filespace, event: { seq, type: "create"|"modify"|"delete"|"rename"|"lock"|"unlock"|"upload",
                      path, actor, ts } }   // shape == cli ChangeEvent

// method: "cache"     — size/usage/pinned changed (live menu-bar update)
{ filespace, cache: CacheInfo }

// method: "mount"     — mount/connection state changed
{ filespace, status: EngineStatus }
```

`activity` events fold together cloudfsd-local events (uploads draining, pins
completing) **and** remote events the engine pulls from the gateway change feed
(`GET …/changes`, keyset `since` cursor) — so the CLI `events` stream and the GUI
activity feed see one unified ordering. (Until the gateway exposes WebSocket
pub/sub — `backend/API.md §9` — the engine polls `…/changes` with the `anchor`
cursor and republishes deltas as `activity` notifications.)

---

## 7. Data-path methods (mount adapters only — NSXPC / C-FFI, not the CLI)

These are the `EngineClient` §1.3 RPCs the macOS appex / FUSE-T shim use; they are
**not** part of the CLI's JSON-RPC surface (the CLI never moves bytes — `backend/
API.md` preamble). Listed here so the one engine core is the single source of truth.
Over NSXPC these pass an **FD**; over UDS/FFI they pass an App-Group/temp **path**
(`CacheFileRef` carries either — client doc §1.2).

| Method | Params | Result | File Provider delegate |
|---|---|---|---|
| `lookup` | `{ id }` | `ItemMetadata` | `item(for:)` |
| `readContents` | `{ id, version }` | `CacheFileRef` (whole object) | `fetchContents` |
| `readRange` | `{ id, version, offset, length, alignment }` | `{ ref: CacheFileRef, retrievedRange: [off,len] }` | `fetchPartialContents` |
| `write` | `{ id?\|template, fields, contents: CacheFileRef?, baseVersion? }` | `ItemMetadata` | `create/modifyItem` |
| `delete` | `{ id, baseVersion, recursive }` | `{}` | `deleteItem` |
| `enumerate` | `{ container, page? }` | `{ items: ItemMetadata[], nextPage?: string }` | enumerator |
| `enumerateChanges` | `{ container, anchor }` | `{ updated, deleted, newAnchor, moreComing }` | `enumerateChanges` |
| `setContentPolicy` | `{ id, policy }` | `{}` | pin/evict policy |
| `requestDownload` | `{ id, range? }` | `PrefetchAck` | prefetch |
| `evict` | `{ id }` | `EvictAck` | free space |

`readRange` aligns `[offset,length)` out to **block boundaries (1 MiB)** and returns
the snapped `retrievedRange` (one block is the minimum honest unit — AES-GCM tag
verification needs a whole block; client doc §5.2).

---

## 8. Versioning of this contract

- The contract is **append-only** within a major version: new methods / new
  optional params may be added; existing shapes and error-code mappings do not
  change (the CLI exit codes are a public contract — `cli/src/exit-codes.ts`).
- A `system.version` method returns `{ engine: "<semver>", api: "<contract-version>" }`
  so the CLI/GUI can feature-detect.


### Stable links

`link.create` takes `{filespace, path}` where `path` is relative to this Mac's mounted projection and returns `{filespace, itemId}`. `link.resolve` takes `{filespace, itemId}` and returns `{filespace, path}` using the current authorized mounted projection. An empty returned path identifies that projection's direct root. A virtual multi-folder volume root uses an ordinary filespace link instead of an inode link.

Inode links survive renames and moves inside the accessible projection; each resolution rechecks gateway permissions and walks only to a currently authorized mount root. Folder-only recipients do not need access to its ancestors. Top-level granted folders retain their mounted aliases until remount, so another grant's revocation or a grant-root rename cannot make links disagree with the live Finder volume. Repeated `mount` is idempotent and retains that projection; changing the selected root or location requires unmount. Deleted/revoked items and items outside an explicitly selected subfolder mount return an error. Creating a link does not grant access or modify permissions. Native clients use `cloudfs://item/<filespace>/<inode>`; legacy path links remain supported.

## Read-only snapshot volumes

`snapshot.mount` takes `{filespace,snapshotId,at?,name?}` and returns
`{mountId,filespace,snapshotId,name,mountPath,status,readOnly:true}`. `filespace` is
the real source identity; `mountId` is the separate local volume identity.
`status` is `mounted`, `unmounted`, or `unavailable`. A scoped snapshot opens its
folder's children directly at the volume root. Repeating mount is idempotent;
changing its location requires eject first.

`snapshot.mounts` takes `{filespace?}` and returns those records after checking
the kernel mount table and current authorization. `snapshot.unmount` takes
`{mountId,force?}`; force defaults to false, so an open/busy volume reports an
error. Finder eject is reconciled and parent-filespace disconnect removes its
snapshot volumes. Revoked/deleted snapshots are detached and reported unavailable.
Transient connectivity errors preserve actual kernel state but reads fail closed.

Snapshot records also appear in `filespace.list` with optional `sourceFilespace`,
`snapshotId`, and `readOnly:true`. Generic `unmount` and `filespace.disconnect`
accept their `mountId`; `flush`/`sync.state` report no pending writes. This makes
normal Quit/Sign Out drain every volume. Crash remount intents retain the source
filespace, snapshot identity and exact owned SMB source. Pinning and live item
links use the real live filespace only; Finder actions exclude read-only records.

The kernel volume is mounted read-only and the data path independently denies
all mutations. File blocks and Mac named streams use the original inode's crypto
identity. Every read rechecks current access before serving cached bytes. Old
snapshots created before Mac stream capture are explicitly refused as mounted
volumes rather than silently losing resource forks; app browse remains available.


Crash-replayed uploads may wait for the previous process's editing lease to
expire. This bounded initial-acquisition wait lasts at most the requested lease
TTL plus five seconds (normally 65 seconds), excludes ordinary writable opens,
and never retries a locally lost lease implicitly. A flush's own timeout is not
extended; allow 90 seconds when explicitly waiting through fresh crash recovery.
The journal and original remote-version comparison remain unchanged.


### Offline copies

Pins now report optional `offlineReady`, `offlineExpiresAt` and `offlineFailureReason` independently of cache residency. Real authenticated gateways prepare an encrypted checkpoint only after a complete subtree walk, main-data and named-stream materialization, checksum verification, and unchanged authorized change-feed/visibility state. Checkpoints expire after 24 hours and remain bound to the gateway, account and filespace. The filespace key stays in the existing local key source (normally Keychain).

`mount` accepts optional `offlinePin`, the normalized pin path (empty string for a full projected-root pin). Eject the live volume first. This selects a frozen read-only volume; it does not pretend a partially pinned live namespace is complete. The native Pinned Items screen exposes the action when ready. The offline adapter performs no gateway/blob requests, reports missing versus corrupt content, rejects writes and keeps pending uploads paused. Reconnect and remount normally to edit. Explicit offline mounts are not automatically restored as writable mounts after a crash.

Offline access is a local device policy, not a renewed online token. A disconnected device cannot observe immediate revocation. Known online access loss/visibility changes invalidate saved checkpoints; expiry is enforced on each lookup/read. Checkpoint metadata is capped at 64 MiB and 100,000 items. Pinning without a ready checkpoint retains its existing cache-only meaning. Existing journal recovery remains independent of offline copies.
