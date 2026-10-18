# Independent encrypted backup and recovery

This operator tool backs up metadata, application secrets, referenced encrypted data blocks, retained recovery blocks, snapshot blocks, and audit objects to an independent local archive. Filespace snapshots remain useful for recovering older files, but they are not an independent copy of the server databases, encryption keys, or bucket.

Use a separate storage device or backup destination for the resulting directory. Keep the recovery key on a different protected device or in a password manager. Losing that key makes the archive unreadable. Keeping only the key without the archive is also insufficient.

## Safety boundaries

- Backup requires a deployment in `BACKUP_MODE=export` and an explicit list of every organization. The server checks the known directory inventory and freezes the included metadata authorities while it exports them. The organization list is an operator declaration: an unregistered organization that cannot be discovered must be included explicitly.
- Restore requires a fresh deployment in `BACKUP_MODE=restore`. All local archive members are authenticated and checksummed before the tool sends its first target request. The target separately checks pristine metadata, schema compatibility, fresh authentication keys, complete object receipts, and referenced-object coverage before promotion.
- Existing destination objects are created conditionally. A retry may reuse an existing object only after the server verifies its exact length and SHA-256. Unequal bytes are never replaced. Use fresh data and audit buckets; pristine databases alone do not prove that a bucket is empty.
- The original `STORAGE_ENC_KEY` must survive. The tool generates fresh authentication-signing and bootstrap secrets for the target. Restored sessions and access tokens are revoked by the server, and scheduled jobs remain disabled. Storage is remapped to the target's configured default rather than archived endpoints or credentials.
- Creation never overwrites an existing archive or recovery-key file. A partial archive without `manifest.enc` is incomplete and cannot be restored. The final encrypted manifest is published only after a complete verification pass and filesystem synchronization.

No command below deploys to Cloudflare automatically. Keep normal client traffic stopped during maintenance. Removing maintenance mode before a completed restore is unsafe; a partial restore must remain isolated.

## Prepare private inputs

Use Node.js 22.12 or later. Put the configuration and secret files in a private directory and set their permissions to `0600`. The tool reads JSON as data; it never executes a shell configuration. Do not put secret values on the command line.

Example private configuration:

```json
{
  "source": { "origin": "https://files.example.net" },
  "sourceSecretsFile": "./source-secrets.json",
  "organizations": ["your-organization-id"],
  "target": { "origin": "https://recovery.example.net" },
  "targetStorageSecretsFile": "./target-storage-secrets.json",
  "targetSecretsFile": "./new-target-secrets.json"
}
```

`sourceSecretsFile` is the protected deployment secrets JSON, including `STORAGE_ENC_KEY`, `AUTH_SIGNING_SECRET` and `BOOTSTRAP_SECRET`. The source server returns their fingerprints; the tool refuses a secret file from another deployment. Other application secrets are encrypted in the archive as well. The bootstrap credential normally comes from this file; `source.bootstrapSecret` may be supplied in the private configuration when needed.

`targetStorageSecretsFile` contains the fresh target's `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY`, plus any explicitly selected replacement application secrets. The secret preparation step drops old `S3_*` credentials and deployment-wide `SIGNUP_INVITE_TOKENS`, preserves the original storage encryption key, and generates fresh authentication/bootstrap values. Do not copy old signup capabilities into the target's deployment variables either; issue new invitations after recovery. Other source application dependencies, such as OIDC and email provider credentials, are retained unless explicitly replaced in the target input. Review whether those dependencies should remain valid for the recovered deployment. Configure the fresh target's bucket names, endpoints and audit binding separately using the deployment configuration.

Relative secret-file paths resolve against the configuration file's directory. HTTPS is required. Isolated local testing may set `"allowInsecureLocalhost": true`; this permits only HTTP loopback endpoints, not arbitrary insecure hosts.

## Create and verify

First deploy the source with `BACKUP_MODE=export`. Existing in-flight uploads should be flushed before maintenance. Then run:

```sh
node scripts/backup.mjs create \
  --config /private/operator/backup-config.json \
  --archive /Volumes/IndependentBackup/cloudfs-2026-10-09 \
  --key-file /private/recovery-keys/cloudfs-2026-10-09.json

node scripts/backup.mjs verify \
  --archive /Volumes/IndependentBackup/cloudfs-2026-10-09 \
  --key-file /private/recovery-keys/cloudfs-2026-10-09.json
```

Both destination paths must be new. The parent directories must already exist. The recovery key must be outside the archive directory. The default object-transfer concurrency is four; `--concurrency 1` through `--concurrency 8` are supported.

Creation exports bounded typed metadata pages and streams object bytes through encryption directly to disk. It compares every supplied object size/checksum and independently checks content-addressed block hashes. Audit indexes and segments are included alongside file data. Presigned URLs are used only for the current transfer and are not saved as archive authority.

On success the source holds are released; remove `BACKUP_MODE` through the normal deployment workflow to reopen service. On an ordinary failure the tool attempts to abort the source session. A killed process or unavailable server may leave persistent maintenance holds. Inspect them with:

```sh
node scripts/backup.mjs status --config /private/operator/backup-config.json
```

Status prints only the maintenance mode, session ID, phase, organization/target counts and completion flags. It omits fingerprints, organization names and catalog contents. To release an abandoned source export, first stop any running backup process, then use the same configuration and organization declaration:

```sh
node scripts/backup.mjs abort --config /private/operator/backup-config.json
```

Abort uses the current server-reported source session ID, refuses a different organization scope, and never cancels a restore. Repeating it after a completed or aborted source session is harmless. It releases source holds without changing local archive files; source maintenance mode remains set until the operator removes it. A partial archive cannot resume creation: preserve it if investigating a failure and use new archive/key paths for another attempt. The archive is successful only when its committed manifest verifies; do not infer success from downloaded files alone.

## Prepare the fresh target

This step verifies the archive and writes a new protected secrets file without contacting or changing a target:

```sh
node scripts/backup.mjs restore \
  --config /private/operator/backup-config.json \
  --archive /Volumes/IndependentBackup/cloudfs-2026-10-09 \
  --key-file /private/recovery-keys/cloudfs-2026-10-09.json \
  --prepare-secrets /private/operator/new-target-secrets.json
```

It refuses to overwrite an existing file or write plaintext target secrets inside the archive. Deploy a **new** Worker with fresh Durable Object namespaces and fresh data/audit buckets, `BACKUP_MODE=restore`, the generated secrets, and the target storage configuration. Do not complete first-admin setup on that target. Set `targetSecretsFile` and `target.origin` to this deployment. Keep the source deployment and archive intact throughout recovery.

## Restore and resume

```sh
node scripts/backup.mjs restore \
  --config /private/operator/backup-config.json \
  --archive /Volumes/IndependentBackup/cloudfs-2026-10-09 \
  --key-file /private/recovery-keys/cloudfs-2026-10-09.json
```

The tool verifies the whole local archive first, registers the complete expected object inventory in bounded pages, imports exact typed metadata pages, and streams the original ciphertext bytes to the target. The server must verify every remote object before accepting completion. Audit recovery also rechecks the index, every referenced segment and its sequence/hash chain, and the join into recent database events and the persistent tail checkpoint. Missing segments or a broken history prevent promotion. The archive's authenticated ID and per-target page indexes are stable: rerunning this exact command resumes the same restore session. An interrupted commit or hold-release phase resumes finalization without replaying already-promoted metadata.

The command does not remove maintenance mode. Inspect target progress with:

```sh
node scripts/backup.mjs status --config /private/operator/backup-config.json --mode target
```

After a successful server completion, run deployment readiness checks. Keep the recovered deployment on its fresh recovery origin, separate from the client-facing origin. Remove `BACKUP_MODE` there through the deployment workflow so the administrator can sign in, inspect the restored organization/filespace inventory, check ordinary access permissions, and validate representative file and snapshot reads. These normal application checks cannot run while `BACKUP_MODE` is set because maintenance intentionally closes those APIs. Only after those checks pass should client traffic move to the recovered service. Users must sign in again; old sessions and tokens do not regain access. Re-enable schedules deliberately after validating the recovered service.

Operator failures show only recognized safe error codes and a suggested next step. For example, `restore_requires_empty_target` requires another fresh target, and `restore_encryption_key_mismatch` requires the prepared original storage key. Unknown upstream bodies, signed URLs and credential values are never printed. Preserve the archive and recovery key when a command fails; an HTTP success from an intermediate page is not a completed restore.

## Archive format and limits

Each member uses AES-256-GCM with a fresh 96-bit nonce. Authenticated data binds the archive ID and exact generated filename. Member names contain a monotonically increasing sequence and random UUID; original object keys and metadata names appear only inside the encrypted index. Per-member records contain the plaintext size/SHA-256 and encrypted-envelope size/SHA-256. The final encrypted manifest authenticates the source generation, target schema/catalog, organization declaration, key fingerprints, expected inventories and streaming index checksum.

The recovery key is a randomly generated 256-bit key written separately with exclusive creation and mode `0600`. The archive is not password-derived. Metadata JSON is bounded to 16 MiB per page, encrypted members to 5 GiB, and the index to ten million entries within the same 5 GiB member bound. The server coordinator additionally limits the catalog to 1 MiB, 512 metadata targets and 100 declared organizations; directory, organization, authentication and filespace authorities each count as targets. The current restore API limits each encrypted data block to 64 MiB and each audit object to 8 MiB; ordinary large files consist of many small encrypted blocks. Object contents are streamed in bounded chunks; the tool does not load the whole archive or object inventory into memory. Metadata preserves lossless integer strings, text, real values, nulls and base64-encoded SQL BLOBs.

Allow roughly twice the restored metadata database size per Durable Object during promotion, plus space for indexes, receipts and SQLite transaction overhead: staging and promoted rows coexist until promotion finishes. This is database headroom, in addition to the independent archive and destination buckets; it does not duplicate every media object inside SQLite. A restore near the platform's database-size limit may need a different recovery design and is not proven safe merely because the source fit within that limit.

Final audit validation deeply checks every archived event in resumable batches of at most eight archive segments and four metadata pages per request. The server saves its cursor before returning HTTP 202; the operator tool continues until promotion completes. A restart repeats at most the unfinished batch, and the archive index digest is pinned across batches. Database promotion still runs atomically within each authority. Histories and metadata databases near platform limits remain unproven; validate a representative recovery before relying on them operationally. A failed or interrupted restore must remain in maintenance and be resumed with the same archive, not treated as complete.

SQL pages consume small, complete cursor batches before returning; a page-size
boundary cannot leave a staging-table query open and block promotion. The Node
operator also acquires each HTTP response's read lock before awaiting archive
file creation. This prevents response garbage collection from turning an unread
download into an empty stream. Expected size/hash checks and independent archive
verification remain mandatory; neither fix relaxes verification or buffers whole
objects in memory.

The format is version 1 and accepts only its declared schema. It contains no executable SQL or extraction paths. Symlinked members, altered tags, missing/truncated members, incorrect page digests and incomplete manifests fail validation. Independent verification proves the saved bytes and catalog are intact; recovery still depends on compatible server schema/code and storage credentials capable of reading/writing the configured buckets.
