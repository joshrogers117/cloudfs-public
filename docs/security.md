# Security architecture

This describes the shipped preview's trust boundaries. It is not an independent security certification. Report vulnerabilities through [the private reporting channel](../SECURITY.md).

## Accounts and sessions

The Worker authenticates browser requests and native/CLI tokens before forwarding operations to the relevant Durable Object authority. Password records use salted scrypt. Optional TOTP, WebAuthn and configured OIDC sign-in are implemented; enabling a method requires its own setup and verification.

Browser sessions are server-side and revocable. State-changing browser requests require the session's CSRF protection. The native app uses a browser approval handoff and revocable device credentials; it does not collect the user's web password. Service tokens support scoped automation. A user signing in successfully does not automatically receive filespace access.

First-owner setup requires a randomly generated bootstrap secret and closes after bootstrap. The protected deployment profile retains the secret for operator operations; never distribute it to teammates or put it in a URL. Invitation and reset links are bearer capabilities: treat the full URL as a secret.

## Authorization

Organization and filespace authorities enforce membership, roles and folder permissions. Administrative settings require server-side authorization on their APIs, even when called outside the browser. File operations, snapshots, signed URLs and delegated access must pass the applicable permission checks.

Normal users may manage their own connection/cache and perform file operations permitted by their grants. Organization membership does not by itself grant file access. Revocation prevents future authorized operations; it cannot recall plaintext already copied by an authorized user or immediately invalidate a previously issued object-store URL.

## Storage and keys

Clients encrypt content before uploading immutable, content-addressed blocks. Upload receipts are checked before metadata commits refer to them. Reads use scoped, expiring signed storage URLs; clients verify and decrypt blocks into the filesystem read path. Metadata and filenames remain visible to the server operator.

The Worker stores filespace master keys and configured provider credentials sealed under `STORAGE_ENC_KEY`. The deployment operator can recover these values. This is client-side encryption with administrator-controlled keys, not zero-knowledge encryption. Protect both the Cloudflare account and the local deployment secrets file. Encryption does not replace access control, backup or endpoint security.

The Mac keeps authenticated credentials in Keychain and encrypted blocks in its local cache. Pending writes and recovery state must be preserved until remote durability is confirmed. Local operating-system account compromise is outside the protection supplied by an application-level cache.

## Coordination and recovery

Distributed write leases and open-file references reduce conflicting edits and preserve inode lifetime across rename/replacement. They are filesystem consistency controls, not substitutes for authorization. An application that ignores or uses different locking semantics still needs compatibility testing.

Snapshots retain historical blocks and metadata subject to permissions. Audit records are hash-chained and archived to R2. An operator who can delete the authorities, buckets and keys can destroy this history. Do not describe snapshots or an audit bucket as independently immutable disaster recovery.

The [backup tool](BACKUP-RESTORE.md) exports authenticated encrypted archives during maintenance. Recovery requires the archive, separate recovery key, compatible source/schema and new infrastructure. Restoration revokes old sessions, preserves the original storage encryption key and requires deliberate re-enabling of schedules.

## Deployment boundaries

The supported installer runs locally on the administrator's computer. It accepts a short-lived provisioning token, creates bucket-scoped storage credentials and saves application secrets in a protected named profile. The provisioning token is not saved. The browser wizard configures the application after infrastructure deployment; it does not request account-wide Cloudflare credentials.

Use HTTPS and the same public origin for the console and API. Do not deploy local development secret templates. Before releasing a fork, review its default configuration, allowed origins, signing identity, app groups and Keychain access.

## Limits

No independent penetration test, general application compatibility certification or zero-data-loss guarantee is claimed. A compromised operator or Mac, exposed recovery material, provider outage, or deletion of all replicas can defeat recovery. See [compatibility](COMPATIBILITY.md) for tested environments and [operations](SERVER-OPERATIONS.md) for troubleshooting and safe upgrades.
