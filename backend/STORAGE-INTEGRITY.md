# Storage integrity and commit validation

API v3 verifies immutable encrypted objects before publishing their manifests. Use the matching current Mac app; older upload transports are not a supported preview configuration.

## Publication contract

1. A block PUT is authorized for the live inode and principal. The signed URL includes mandatory `If-None-Match: *`; canonical ciphertext SHA-256 keys also include a signed `x-amz-checksum-sha256` header. An old URL cannot replace the object after it exists. Incorrect bytes are rejected by the object store.
2. A retry that gets 412 downloads the separately authorized `verificationUrl`. The daemon compares the complete ciphertext length and SHA-256 with the intended body before reusing it. A 412 by itself never means success. Deterministic encryption can safely reproduce an existing key.
3. A manifest is validated before any namespace mutation: ordered unique coordinates, contiguous safe offsets, positive lengths, consistent hash/key/length identities and bounded work. HTTP metadata bodies are limited to 16 MiB, and the defensive manifest count is 131,072 blocks. Larger manifests need a future incremental protocol; media PUT bytes do not cross this metadata request limit.
4. Current write/read provenance is checked before storage verification. Fresh objects are checked in batches of at most 128, with six concurrent object requests. HEAD must establish size and the exact stored SHA-256. Older objects lacking the stored checksum are streamed through SHA-256 once; ETags are not treated as content hashes. Every fresh verification consumes a rate-limit token.
5. A durable SQLite receipt binds storage endpoint/bucket/region/path style, key, hash, ciphertext size and logical size. Receipts are immutable, including when two verification requests overlap. Changing the storage destination requires verification again. Unchanged objects avoid another HEAD.
6. Publication rechecks live permissions, lease/fence, receipts and CAS, then changes the block map, reference counts and metadata inside `transactionSync`. Any exception rolls back the complete mutation. An exact retry with the immediately preceding CAS version returns the existing image/version without incrementing it again.

The object store is still trusted to implement conditional PUT, checksum validation, reads and durability correctly. The operator readiness probe tests the actual provider with tiny temporary objects: wrong-checksum rejection, successful correct upload, conditional retry refusal, checksum/size verification and exact readback. The release rehearsal exercised the strict path on R2. An unsupported provider fails the probe or upload rather than bypassing validation.

R2's checksum-type table must be read alongside its release notes: [2023-06-16](https://developers.cloudflare.com/r2/platform/release-notes/#2023-06-16) added SHA-256/SHA-1 checksums to S3 `PutObject`, while [2025-07-03](https://developers.cloudflare.com/r2/platform/release-notes/#2025-07-03) describes `FULL_OBJECT` support for multipart uploads. AWS explicitly scopes the corresponding SHA256 full-object/composite restriction to [multipart checksum aggregation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html). Taken together, these documents support our single-PUT SHA256 contract; the table is not evidence that single `PutObject` checksums are rejected. The SigV4 `UNSIGNED-PAYLOAD` marker does not validate bytes by itself: our separate checksum header is signed, and the object store must validate it against the uploaded body.

[R2 limits same-key writes to one per second](https://developers.cloudflare.com/r2/platform/limits/). Each probe PUT stage retries only HTTP 429, at most three attempts, delaying at least one second and honoring `Retry-After` up to a three-second delay cap. Throttling never counts as checksum rejection or overwrite refusal: the final statuses must still be exactly 400, 200 and 412. Corrupt and valid payloads use separate random keys; the final conditional retry deliberately reuses the valid key. Cleanup remains best-effort deletion of only those two exact probe keys.

Existing pre-v3 presigned URLs cannot be revoked by changing the Worker. Before relying on the new immutability guarantee during an upgrade, allow previously issued URLs to expire (the former maximum was 900 seconds) and retire old writers. External bucket credentials can still delete or replace objects; verification receipts are not continuous bucket monitoring or protection against an administrator modifying storage directly. A server-held SHA checksum proves the stored ciphertext identity, not that an untrusted client constructed a semantically valid encrypted file.

## Scaling changes

Namespace publication uses bounded JSON/SQL batches of 256 rather than statements per block. A regression measures fewer than 50 SQL statements for a 1,024-block replacement; the former loop used more than 4,096. Repeated hashes retain their exact reference multiplicity. Fresh upload claims/catalog entries are checked with a batched join, and repeated owner ACL decisions are reused only inside the current synchronous authorization turn.

Batch presigning now resolves/decrypts managed credentials once, shares a request-local signing-key cache, and bounds cryptographic fan-out. Object keys are percent-encoded as path data before URL construction, so encoded traversal, query, fragment and backslash characters cannot change the authorized resource.

Mutation and presign rate limits use separate persisted bucket keys. Previously both classes shared the principal key, so a metadata request could reduce an 8,192-token presign bucket to the smaller mutation capacity immediately before object verification. A real 1 GiB transfer exposed the resulting 429 and unnecessary manifest retry. The fix isolates the classes without raising their limits; a regression covers mixed metadata and large verification requests.

Verification adds one object-store HEAD per newly verified block, or a streamed GET for older objects without a stored checksum. Receipts and provenance catalogs persist until filespace purge and therefore grow with distinct uploaded objects. Local object-store benchmarks do not establish WAN throughput.

## Regression coverage

The source repository includes storage commit, credential and object-verification tests. They cover missing objects, invalid manifests, conditional retries, ciphertext checksums, immutable receipts, provider errors, concurrent verification and transaction rollback. Native immutable-upload tests cover required signed headers, verified 412 reuse, and rejection of corrupted or truncated existing ciphertext. See [Compatibility](../docs/COMPATIBILITY.md) for release qualification.

The metadata-fixture test environment explicitly uses `STORAGE_VERIFY_UPLOADS=0`; runtime defaults to verification enabled. Production configuration rejects this bypass and the readiness doctor reports it as a failure. The real MinIO validation uses strict verification.

Multipart coordinator rows are not S3 multipart completion proof. They preserve an upload's identity, exact part geometry and retry progress, but do not implement the bucket multipart API. Strict production mode refuses legacy completion with `409 legacy_multipart_unverified`; the desktop uses the verified block protocol. Metadata-only completion remains available solely under the explicit fixture bypass.

## References checked

- [Cloudflare SQLite transactions](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/): rollback and output-gate behavior.
- [R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/): conditional operations, HEAD and checksum support.
- [R2 presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/): signed headers and bearer URL lifetime.
