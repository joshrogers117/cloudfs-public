# Chunked resource forks and named streams

Resource forks use the same immutable encrypted object transport as ordinary data, with 1 MiB chunks. SMB reads and writes address a bounded range; extending a large fork or changing a few bytes does not fetch or replace the entire fork. The former 4 MiB SMB write limit is removed for resource forks. `AFP_AfpInfo` remains a small inline FinderInfo envelope for directory metadata compatibility.

## Durability and identity

A stream mutation obtains the parent inode's distributed writer lease, reads the current stream version, uploads only changed immutable chunks, then commits a sparse metadata delta with that version and fence. Successful return requires the gateway's object verification and durable manifest transaction. This path acknowledges remote durability; it does not use the main data fork's local write journal. A failed or interrupted operation before that confirmation does not report success. A commit whose reply is lost can have succeeded remotely, so callers must treat an error as an uncertain operation and retry or inspect the current stream; no old image is blindly replayed.

Chunk crypto reuses the authenticated block format with an independent identity: `stream-v1:` followed by SHA-256 of a domain marker and two length-prefixed UTF-8 components (original inode ID and exact stream name). Each block's index remains authenticated. This separates resource forks from the data fork and from legacy inline stream encryption. Decryption verifies ciphertext SHA-256, the encryption authentication tag, and plaintext length before exposing bytes. A failed read-modify-write never substitutes an empty stream for a corrupt or unavailable chunk.

Versions are stream-specific. Deletion preserves a versioned tombstone, preventing delete/recreate from accidentally accepting a stale version zero. The server accepts an exact retry by its persisted delta digest; a different stale delta conflicts. Snapshot reads address frozen stream manifests and authorize their keys against that snapshot rather than the live stream.

## Ranges, growth and truncation

Each request contains at most 8 MiB of application data and covers at most nine chunks. Object transfers share a four-permit pool within each filespace's stream store. A per-stream mutation gate serializes read-modify-write, replacement, truncate and delete operations across local handles. Different stream names remain independent.

Missing chunk rows represent zero-filled holes. A stored short chunk's remaining logical bytes are also zero, so distant sparse extension does not require rewriting its old tail. Shrinking rewrites a partial surviving boundary and removes all later chunks atomically; regrowth cannot resurrect discarded bytes. Sparse work iterates only the touched chunks, not every logical block in a large hole. Sizes are bounded by the gateway's exact JSON integer range, not by a small whole-blob limit.

Legacy inline streams remain readable. Their first ranged mutation migrates their bounded existing payload to chunked storage in the same version-checked transaction. Existing old clients receive an explicit incompatibility error for a migrated stream rather than seeing it as missing and overwriting it with an empty inline value. These are additive API endpoints; deployment must update the gateway before using the new daemon's chunked writes. An unavailable manifest endpoint or inaccessible inode fails before any upload or mutation: only a successful manifest with `exists: false` authorizes creation of an absent stream.

## SMB behavior and validation

Named-stream `SET_END_OF_FILE` and overwrite operations target the fork, leaving the carrier's data untouched. Standard/all-information queries report the stream's current size. Reads resolve current ranged metadata instead of trusting an old handle's EOF, so two handles observe committed growth and truncation. Lazy creation of a new `AFP_AfpInfo` still returns EOF before its first write.

Regression coverage includes a 72 MiB encrypted stream, a two-byte cross-chunk edit fetching/uploading exactly two chunks, a 1 TiB sparse hole, truncate/regrow zeroing, legacy migration, wrong stream crypto identity, corrupted ciphertext, failed PUT/CAS, held uploads without premature commit, concurrent local mutations, tombstone recreation, and frozen snapshot bytes after live edits/deletion. SMB wire tests cover crossing the old limit, two-handle EOF changes, and preservation of the main fork during stream truncate/overwrite.

Current release qualification and known resource-fork limitations are summarized
in [Compatibility](../docs/COMPATIBILITY.md). Results from a local test stack do
not establish provider-specific or WAN performance.
