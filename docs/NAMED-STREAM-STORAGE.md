# Object-backed Mac named streams

Resource forks and general named streams use encrypted, immutable 1 MiB plaintext
chunks in the filespace's R2/S3 bucket. SQLite holds stream headers and chunk
references. This removes the inline database-row limit from resource forks without
loading a whole fork into memory or retransmitting it for each small write.
`AFP_AfpInfo` stays on the bounded inline path so directory listings can return
its encrypted FinderInfo envelope without additional object requests.

## Protocol

The additive routes are:

- `GET /v1/filespaces/:space/items/:inode/streams/:name/manifest?offset=N&length=N`
- `PUT /v1/filespaces/:space/items/:inode/streams/:name/manifest`
- `GET /v1/filespaces/:space/snapshots/:snapshot/items/:inode/streams/:name/manifest?offset=N&length=N`

A GET returns `format: 1`, `blockSize: 1048576`, `exists`, `legacy`, logical `size`,
stream `version`, and overlapping `blocks`. A block is
`{index, hash, length, objectKey}`. The byte range defaults to the first 16 MiB and
is limited to 16 MiB per request. Missing indices and bytes after a short chunk
are zeros. `exists: false` includes the current deletion-tombstone version;
only a never-created stream has version zero. Legacy inline streams return
`legacy: true` and no block references; their encrypted body remains available
through the original raw route.

PUT supplies `format`, `blockSize`, new logical `size`, `expectedVersion`, a
positive parent-inode lease `fence`, and up to 128 changed `blocks`. It is a delta:
unchanged chunks remain, chunks beyond the new size disappear, and a shrink
through an existing chunk requires its shortened replacement. A later grow
cannot expose previously truncated bytes. Migrating inline data requires every
remaining old chunk in the first delta. Replies return the new header with an
empty block array; subsequent reads request the needed range.

The stream version is independent of the main file's version. One synchronous
SQLite transaction publishes the delta, advances the change feed, adjusts object
references and saves an exact canonical delta digest. A lost response can be
retried without publishing twice; a different stale delta conflicts. Any failed
transaction preserves the prior stream and its object references.

Chunk uploads use ordinary presign requests with the parent inode as `itemId`.
Production publication requires verified checksum and ciphertext-length receipts
for the configured storage backend. The final commit checks current ACLs,
server-recorded upload provenance, immutable object identities, the parent lease
fence, and stream version again after storage verification. Cipher identity is
stream-specific and deterministic in the client; snapshot reads retain the
original inode/name identity.

## Compatibility and retention

The raw stream route retains its 1.5 MiB encrypted-body ceiling. Reading an
object-backed stream through that route returns `409 stream_uses_manifest`;
legacy PUT cannot replace an object-backed stream. This prevents an older client
from mistaking a large existing fork for an absent stream and discarding its
untouched bytes. Explicit DELETE removes the whole stream and retains a version
tombstone. Upgrade clients to use large resource forks.

New snapshots freeze headers and object references. Delta snapshot inheritance,
base-snapshot removal, restore and garbage collection account for stream chunks
alongside regular file chunks. Historical object reads use the existing
intersection of frozen ancestry and current permissions; revocation is enforced
before URLs are issued. Previously issued short-lived URLs retain their normal
expiry boundary. There is no live-stream fallback for a snapshot.

Overwritten chunks retain parent-inode ownership for recovery, like overwritten
regular file blocks. Automatic expiry is intentionally absent: deleting a live
inode drops its retained ownership, while snapshot references keep their own
objects alive. Storage use therefore includes historical chunks until their
owning data and snapshots are removed.

Coordinated backups export live and snapshot stream tables and inventory all
current, retained and frozen object keys. Restore validates stream references and
requires verified object receipts before metadata publication. Schema versions
22 and 23 introduce the normalized stream tables and exact retry digest.

## Verification

`backend/test/stream-manifest.test.ts` exercises sparse 64 MiB logical forks,
range reads, shrink/grow, CAS tombstones, exact retry, transaction rollback,
legacy protection, storage receipts, upload provenance, permission revocation,
snapshot restore/pruning, and backup restore with missing-payload rejection.
A 10,000-chunk fixture also verifies that changing one chunk reads fewer than
1,000 SQLite rows; the initial OR-based implementation read 40,013 rows.
Snapshot create and restore inject mid-write SQL failures to verify full rollback.
Real mounted large-fork and storage-throughput results are recorded separately
in the validation report; logical sparse fixtures are not throughput evidence.
