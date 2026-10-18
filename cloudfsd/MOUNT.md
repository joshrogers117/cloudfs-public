# The mount: an in-daemon SMB2 server (CloudFSSMB)

cloudfsd serves each filespace as a native macOS volume by running a **userspace
SMB2 server on `127.0.0.1`** and mounting it with the **built-in `smbfs` client**
(`mount_smbfs`). No kext, no macFUSE, no third-party cask — the whole data path
stays in-process on the engine seam (`EngineDataPath`). This replaced an earlier
NFSv3-loopback backend (hard cutover); NFS and FUSE-T are gone.

## Why SMB (over the old NFSv3 loopback)

- **Live Finder updates** — SMB2 `CHANGE_NOTIFY` pushes directory changes, so a
  collaborator's edit appears without a manual refresh. NFSv3 had no equivalent.
- **Native xattrs / Apple metadata** — FinderInfo, resource forks, and
  `com.apple.*` xattrs ride SMB named streams and are stored natively, so no
  AppleDouble `._` sidecar files leak into the object store.
- **In-protocol byte-range locks** (advisory, single-client parity with the old
  `locallocks`).
- **Windows-ready** — SMB is the only loopback protocol that is also native on
  Windows, for an eventual Windows client.

## Modules

| Module | Role |
|---|---|
| `CloudFSMount` | the `MountBackend` protocol + a no-op `StubMountBackend` (headless/CI default; the daemon injects the real backend) |
| `CloudFSSMB` | the SMB2 server + `SMBLoopbackMountBackend` (the production mount) |

### CloudFSSMB layout

| File | Role |
|---|---|
| `SMB2Wire.swift` / `SMB2Types.swift` | little-endian wire codec, Direct-TCP framing, the 64-byte packet header, command/status constants |
| `LegacyCrypto.swift` / `NTLM.swift` / `SPNEGO.swift` | MD4 + RC4 + the NTLMv2 verifier and its GSS/DER wrapper (a synthetic per-mount credential) |
| `SMBServer.swift` | TCP listener (ephemeral loopback port), thread-per-connection, compound dispatch, the credit/MessageId ledger, `bridgeSync` to the async engine |
| `SMBState.swift` | per-connection session/tree/open state |
| `NodeTable.swift` | InodeID ↔ u64 file-id map + short-TTL metadata/listing caches |
| `HandlerConnect.swift` | NEGOTIATE (dialect **2.1**, CAP_LARGE_MTU, no leasing) / SESSION_SETUP (2-leg NTLMv2) / TREE_CONNECT |
| `HandlerData.swift` | CREATE (+ MxAc/AAPL contexts, all dispositions, named-stream opens), READ, WRITE, FLUSH, CLOSE, QUERY_DIRECTORY (with SMB wildcard matching), SET_INFO (truncate/rename/delete-on-close) |
| `HandlerInfo.swift` | QUERY_INFO — FILE + FILESYSTEM info classes, FileStreamInformation, `FILE_NAMED_STREAMS` |
| `Streams.swift` | xattr ↔ stream mapping (`AFP_Resource`, `AFP_AfpInfo`), `:stream:$DATA` path parsing |
| `HandlerLock.swift` | SMB2 LOCK — in-memory advisory byte-range lock table |
| `HandlerNotify.swift` | SMB2 CHANGE_NOTIFY (async STATUS_PENDING + off-thread completion) + CANCEL, with a per-directory poller over `enumerateChanges` and a local-mutation fast path |
| `SMBLoopbackMountBackend.swift` | mints the credential, ensures the `nsmb.conf` tuning, shells `mount_smbfs`, disables Spotlight on the volume |

## Client tuning (`~/Library/Preferences/nsmb.conf`, no root)

A `[127.0.0.1]`-scoped section enables AAPL, directory caching, change-notify,
and named streams for our loopback host only: `aapl_off=no, dir_cache_off=no,
file_ids_off=no, max_cached_per_dir=50000, minauth=ntlmv2, notify_off=no,
protocol_vers_map=2, signing_required=no, streams=yes`.

## Behavior notes

- **Auth**: a synthetic random NTLMv2 credential per mount (not guest — the guest
  flag disables signing and trips EAUTH on authenticated mounts).
- **Dialect 2.1** legitimizes multi-credit large-MTU I/O (1 MiB reads) on-spec.
- **Hard mount**: a slow cold read can wait while the engine fills its cache;
  authorization, locking and unrecoverable I/O failures still return errors.
  After a daemon crash, persisted-mount recovery checks the exact recorded
  CloudFS mount source before detaching a wedged volume and mounting again.
  That crash-recovery path is separate from normal user disconnect/reconnect.
- **Perf**: ~490–521 MB/s cold sequential read on loopback (multi-credit 1 MiB
  reads confirmed on the wire). See the `CLOUDFS_LIVE_MOUNT`-gated benchmark.

## Apple read failures and recovery (build 34)

An isolated macOS kernel test reproduced a full-length read with incorrect bytes
when one delayed SMB READ failed and later pipelined READs succeeded. Canonical
SMB ERROR framing alone did not prevent that result. Build 34 keeps engine I/O
parallel, but publishes standalone READ responses in arrival order per Apple
open handle. The first non-EOF failure latches that handle's error, discards later
prepared payloads and prevents subsequent successful responses on that handle.
Range authority is checked again after any publication wait, before returning
bytes. Other open handles have independent response ordering. EOF does not latch
an error, and Apple detection does not depend on optional directory optimizations.

Expired positive read permits can be retried within a bounded three-attempt
budget; an unusable permit never authorizes bytes. Real permission revocation,
lock conflicts, lost lease authority and exhausted retries remain errors. This
does not make all reads succeed or establish complete failure recovery.

macOS can retain an I/O error (`EIO`) in its vnode cache even after the application
closes and reopens the file with a fresh SMB handle. In both first- and later-fault
kernel tests, three immediate POSIX reopens still failed; remounting recovered
the exact full-file checksum. If a file keeps returning this error, save any
unsaved editing work to a safe location and close applications using the volume.
Finish and flush pending uploads, then use the app's normal **Disconnect** and
**Connect** actions to remount the filespace. Normal disconnect waits for durable
writes and refuses a busy mount. If flushing or disconnecting fails, preserve the
local journal and resolve that failure first; **never force-unmount a volume with
unsaved or pending writes** as a read-error workaround. Recheck the affected file
after reconnecting; remounting does not restore revoked permission or override a
real conflicting lock.

Current release qualification and known limits are summarized in
[Compatibility](../docs/COMPATIBILITY.md). A passing regression suite or one
successful live run does not establish that every application or failure
scenario recovers automatically.

## Testing

The daemon defaults to 32 simultaneous object uploads and 16 downloads per
filespace. These windows share bounded transfer pools across files; authorization
batching does not retain extra file payloads. Operators can set
`--upload-concurrency` / `CLOUDFS_UPLOAD_CONCURRENCY` and
`--download-concurrency` / `CLOUDFS_DOWNLOAD_CONCURRENCY` to integers from 1 to 64.
Older saved configurations use the current defaults. Resource-fork transfers
have a separate four-operation bound, described in [RESOURCE-FORKS.md](RESOURCE-FORKS.md).

The defaults were selected after verified 1 GiB transfers through an actual
Cloudflare gateway and a temporary Worker backed by R2. Upload throughput stopped
improving between 32 and 64, while cold reads plateaued around 16. That test
included an additional Worker hop and varied WAN latency; it does not predict
direct R2 S3 throughput on another connection. See
[Compatibility](../docs/COMPATIBILITY.md) for the current qualification scope.

- **In-process**: `CloudFSSMBTests` drives the real server over a loopback socket
  with a raw `SMBTestClient` against an in-memory engine — no kernel mount needed.
- **Live**: `LiveMountSmokeTests` (gated on `CLOUDFS_LIVE_MOUNT=1`) performs a
  real `mount_smbfs` and exercises browse / read / write / xattr round-trip /
  throughput. Set `CLOUDFS_LOG_SMB=1` (+ `CLOUDFS_SMB_LOGFILE`) for per-command
  wire logs.

## Basic metadata compatibility (schema 27)

`FileBasicInformation` now persists creation, access, modification and change times plus supported DOS attributes through the gateway. `QUERY_INFO`, directory entries, CREATE and CLOSE attribute responses carry these fields. Before an explicit metadata update, the native adapter waits up to 30 seconds for earlier content writes to publish, then submits a current metadata version and lease fence. It does not acknowledge a timestamp that a pending content publication would immediately overwrite. Offline/read-only mounts cannot mutate metadata.

Read-only, hidden, system, archive, temporary and not-content-indexed flags are supported. Normal clears stored flags; directory status remains structural. Read-only protects file bytes and named streams, overwrite/create replacement, and deletion at both SMB admission and backend publication, including direct API/CLI calls. The flag is not a permission grant: an authorized editor may clear it through a WRITE_ATTRIBUTES handle; a reader cannot. Directory read-only bits do not restrict child creation. Unsupported flags, security-descriptor changes, and handle-scoped `-1`/`-2` timestamp controls return `STATUS_NOT_SUPPORTED`. Zero timestamp fields leave existing values unchanged; malformed timestamps/buffers fail. Allocation shrink below EOF truncates bytes; physical preallocation is unsupported. This follows the distinction between explicit times and per-handle automatic-time controls in [MS-FSCC FileBasicInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50).

This is not full POSIX compatibility: hard links, general chmod/chown semantics, automatic atime policies and handle-scoped timestamp suppression remain future work. Tests cover the SMB wire path and actual macOS `touch` and `chflags hidden`, including remount, alongside existing file-copy, xattr, read and external-eject tests.

SMB handles now retain their requested access rights (including expanded generic
rights). READ, WRITE, EOF/allocation changes, basic metadata, rename and deletion
check the handle before reaching the engine. Append-only handles cannot overwrite
existing bytes. Backend ACLs still independently enforce every mutation.

Handle-scoped timestamp suppression needs a durable implementation: capture each
write/truncate/stream operation's automatic-time intent in the transfer staging
journal and carry it into manifest publication. A post-upload timestamp repair
would race another handle or survive a crash incorrectly, so it is deliberately
not used. Explicit timestamps remain supported. Hard links and general chmod/chown
still require separate inode/link and permission designs.

## Atomic namespace replacement

An SMB rename request that still has an existing replacement target drains local pending writes for both source and
replacement target, holds their mutation gates in stable inode order, and sends
one version-checked replacement operation. The filespace Durable Object checks
both inode identities/versions, both leases, source/parent/destination ACLs,
directory types and empty-directory constraints before a synchronous storage
transaction tombstones the target and renames the source. A rejected request or
SQL failure preserves both entries and reference counts. The old delete-then-
rename sequence could lose the destination when the second request failed.
Missing destination directories now fail instead of falling back to an in-place
rename. Nonrecursive deletion rejects nonempty directories; roots are protected.
Read-only file attributes also prevent replacement, deletion, recursive deletion
through a protected child, and snapshot overwrite until an authorized user clears
the attribute.

This transaction does not make every macOS POSIX replacement atomic. Apple's
SMB client can remove an existing destination before sending a separate source
rename ([Apple `smbfs_vnops.c`, lines 8742–8776](https://github.com/apple-oss-distributions/SMBClient/blob/99da2d9a4bbe17cde3cee382ad3edc16e25f5535/kernel/smbfs/smbfs_vnops.c#L8742-L8776)).
An isolated live two-client `os.replace` run observed `ENOENT` at the destination;
the writer trace shows target CREATE/SET_INFO/CLOSE followed by source
CREATE/SET_INFO/CLOSE. The target has already been deleted when CloudFS receives
that rename, so the backend replacement transaction cannot cover both requests.
Earlier checksum and final-content tests do not establish atomic cross-client
POSIX replacement. This remains an editing-app compatibility gap; deletion is
not delayed or hidden to disguise it. See
[Compatibility](../docs/COMPATIBILITY.md) for the current qualification scope.

Hard links and complete open-unlinked behavior remain unsupported. The current
`items` row combines an inode with its one parent/name. Correct hard links require
separate directory-entry and inode tables, shared inode IDs for all aliases, link
counts, and a durable open-handle lifetime after the last name is removed. Block
manifests, streams, leases and encryption must continue using the shared inode ID.
ACL traversal must evaluate the accessed directory entry, with an explicit policy
for aliases crossing differently authorized folders; choosing an arbitrary alias
would leak permissions. Snapshot capture/restore and change notifications must
version directory entries independently, and garbage collection must wait for
both link count and open leases to expire. This requires a versioned backend and
native protocol migration, not copies or a `link_target` shortcut.

General `chmod`/`chown` also remain unsupported: local macOS numeric user/group IDs
cannot safely replace CloudFS user identities and inherited ACLs. Supporting those
calls requires a documented identity/permission mapping enforced server-side;
accepting them only in the mount would falsely report security changes. Unicode
names are NFC-normalized, but SQLite's current `NOCASE` namespace index only folds
ASCII; a broader case-folding migration needs collision handling for existing
non-ASCII siblings before it can claim macOS-equivalent case-insensitive names.

macOS interoperability: [Apple smbfs](https://github.com/apple-oss-distributions/SMBClient/blob/main/kernel/smbfs/smbfs_vnops.c) sends all-zero basic information when clearing
the last DOS flag on an archived file. We interpret that as an attribute clear
only after AAPL negotiation, on a related compound SET_INFO using a freshly opened
WRITE_ATTRIBUTES|SYNCHRONIZE handle (optionally READ_ATTRIBUTES, no data rights), with another compound command following
and all four times zero. Standalone requests and other clients retain standard
zero-means-unchanged semantics. The editor's normal metadata ACL is still required.
This is covered by both a raw SMB regression and real `chflags uchg`/`nouchg`
across a kernel remount; NORMAL is never reported alongside other attributes.
