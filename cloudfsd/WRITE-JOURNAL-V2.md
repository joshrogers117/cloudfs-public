# Ordered writes and checkpoint/delta recovery

The write acknowledgement still means that the local journal crossed its real
disk durability barrier. A remote `flush(wait: true)` additionally waits for
object upload and the fenced, version-checked manifest commit. These are separate
guarantees.

## Journal format

Each staged inode has immutable payload files and an atomically replaced `meta`
file. The existing SHA-256 envelope surrounds its JSON payload. Version 2 adds
`journalFormat: 2` and a `wal` head:

| Field | Meaning |
| --- | --- |
| `checkpoint.file`, `length`, `sha256` | Immutable complete metadata map, including original base record/captured state, size, CAS base and truncate limit |
| `log` | Delta-log file paired with this checkpoint |
| `bytes` | Exact committed prefix length of that log |
| `sequence` | Number of committed frames after the checkpoint |
| `tip` | Last frame hash; checkpoint hash when there are no frames |

The head repeats file identity, CAS base, size, truncate limit and original-base
identity/captured state. Replay requires those values to match the reconstructed
checkpoint plus delta sequence. It never substitutes the latest remote base for
the captured original.

Each delta frame contains a 4-byte little-endian JSON length, the JSON payload,
and its 64-byte ASCII SHA-256. The payload contains its sequence, predecessor
hash, changed immutable block records, removed indices and file metadata. This
validates content and ordering against the committed head. These unkeyed
checksums detect damage; they do not authenticate a writer able to reseal the head. A checkpoint/log pair rotates after at
most 128 delta frames. Log prefixes are bounded to 16 MiB, individual deltas to
4 MiB and checkpoints to 256 MiB; invalid sizes fail before unbounded reads.
Metadata filenames must be single safe `map-…` / `delta-…` components, and reads
use `O_NOFOLLOW` and require regular files. A large delta triggers a checkpoint.

The head encodes `blocks: "cloudfs-journal-v2"` on disk. Its deliberately
incompatible type makes previous daemon versions reject the JSON before their
legacy whole-file fallback, even if a same-size `data` orphan remains after
interrupted cleanup. The new daemon still reads checksummed
full-map journals and migrates them on the next successful publication. Existing
unchecked legacy journals retain their prior fail-closed behavior.

## Publication and acknowledgement

1. Create new UUID payloads and any original-base snapshot with exclusive,
   no-follow 0600 file creation. Complete every short/interrupted write, explicitly
   `fsync` and close the file. No existing file or symlink is overwritten or
   unlinked on failure. A partial unpublished UUID file is only an orphan; it is
   never substituted for an acknowledged record.
2. Synchronize payload names. Append and synchronize a delta, or write and
   synchronize a new checkpoint/log pair and their directory entries.
3. Atomically replace and synchronize the tiny head, then synchronize its
   directory. The existing committed-entry marker remains durable.
4. Call `F_FULLFSYNC` on macOS, after all ordered writes/syncs above.
5. Install the verified in-memory map and collect obsolete generations. Only
   then may the engine return success and SMB send its acknowledgement.

The engine's per-inode mutation gate and journal actor retain mutation ordering.
Readers open immutable payload descriptors under the publication lock, then
read/hash outside it. A later unlink cannot invalidate a reader's open file.

Uncommitted bytes after the head's prefix are ignored at restart and truncated
before the next append. Missing, shortened or corrupt committed bytes fail
closed and preserve the journal. No committed-prefix scan stops silently at a
bad frame. A publication error poisons further publications in that live journal
instance: the head might already have changed, so continuing from a cached older
head could truncate committed state. Verified reopen is required. A remotely
committed entry whose cleanup fails is separately retired and cannot seed a new
CAS generation until cleanup succeeds.

Checkpoint compaction leaves the old head, log, checkpoint and required payloads
intact until the new full-sync succeeds. Cleanup failure can leave extra files;
it cannot make an acknowledged image depend on an already deleted generation.

## Sharing a barrier across SMB requests

Already-pipelined, consecutive standalone WRITEs may share one existing engine
transaction when they target the same handle, session, tree and flags, and their
offsets are contiguous. The batch is bounded to 8 MiB and 16 requests. Each packet
is validated independently; compounds, named streams, overlaps, flag changes,
different handles and controls end the batch. The next packet remains queued in
its original order. Earlier reads drain before this mutation; later READ, FLUSH,
CLOSE and teardown remain ordered behind it.

No new request is awaited to fill a batch. An already-started partial frame gets
up to 2 ms before the current batch proceeds, and its bytes are retained for the
next read. Thus a client with only one outstanding write or limited credits does
not wait for a successor it cannot send. Every original request receives its own
MessageId, credit response and original byte count only after the shared durable
transaction succeeds. A transaction failure produces no success responses. A
disconnect after durability can lose a response, but the local journal remains
replayable.

The real host diagnostic distinguishes workloads: the standard `cp` copy sent
one 1 MiB request at a time, while 8 MiB application writes produced queued SMB
requests before acknowledgements. Batching is therefore not credited with a gain
for the serial `cp` pattern. The repeatable benchmark keeps `cp` as its default
and labels larger application writes separately.

## Overlapping immutable object uploads

After eight distinct complete dirty blocks arrive in the newly extended region,
an acknowledged write may start PUTs while later writes continue. The region
begins at the original live committed extent, reduced only by an explicit
truncate. Ordinary edits inside that committed extent still coalesce. Kernel SMB
can deliver sequential application writes out of order; eligibility therefore
does not depend on each request matching the current logical end of the file.

This does not publish an intermediate file manifest. At most the configured
upload concurrency (default eight) retains a block payload globally; there is no
per-file payload queue. A set of pending dirty indices catches up skipped blocks
as slots become available, round-robin across eligible files. Only eight distinct
indices are needed to establish eligibility, and pending indices name actual
dirty blocks. No loop scans logical holes or an untouched sparse-file prefix.
Truncate clears eligibility and pending indices.

Catch-up selects, reads/hashes and attaches an image in one actor turn only while
its mutation gate is clear. A pending journal publication cannot attach newer
disk bytes to an older staged generation. These PUTs share the normal transfer
permit pool and recheck Pause after acquiring a permit.

A prepared object belongs to one immutable dirty-block image. An overwrite or
boundary trim replaces that image and cannot inherit its object reference.
Untouched images may retain their prepared result across later appends. The final
uploader reuses only a matching full-block result younger than 60 seconds;
otherwise it uses the normal upload path. Failed early PUTs also fall back to
that path. Restart reconstructs from the durable journal, never from speculative
object presence. The original CAS base, lease fence and complete-manifest commit
remain the sole remote publication boundary.

Waiting for a shared PUT does not occupy another permit. Cancellation removes
only the superseded manifest's waiter, so an unresponsive PUT cannot accumulate
old manifest tasks and dirty maps. The bounded underlying PUT may still finish
for a newer generation. Unused objects are unreferenced and cannot replace
committed content. Catch-up stops when the final manifest owner captures its
upload plan, avoiding duplicate work added after that snapshot.

## Verification scope

Fault tests cover all four publication boundaries, poisoned continuation,
restart, tail replacement, checkpoint rotation, full-map migration, failed
retirement, concurrent readers and original-base preservation. Independent tests
add corruption, bounds, path/symlink and cross-inode substitution checks. Socket
tests verify withheld acknowledgements, failure propagation, original response
counts, ordered CLOSE, partial-frame continuation and actual acknowledged bytes
replayed from a fresh real journal instance. These are fault-injection/restart
tests, not a physical power-cut certification. Gated early-upload tests cover
network overlap without intermediate publication, global bounds, exact reuse,
overwrite/truncate/regrowth, failed PUT fallback, queued Pause, cancellable
superseded waiters, and unchanged CAS/recovery guarantees.
