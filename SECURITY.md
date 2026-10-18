# Security policy

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/joshrogers117/cloudfs-public/security/advisories/new). A GitHub account is required. Do not put exploitable security details, credentials, recovery keys or customer data in a public issue.

Include the affected version, reproduction steps, expected and observed behavior, and a minimal example using disposable data. Redact access tokens, signed download URLs, invitation/reset links, setup secrets and deployment configuration. We do not need your production encryption keys to investigate a report.

This project is a public preview. Security fixes target the latest preview; there is no guaranteed response time or support commitment for older releases. Review release notes and back up before upgrading.

## Trust and data protection

Files are encrypted on the client before upload. Filespace master keys and console-managed provider secrets are sealed under the server's `STORAGE_ENC_KEY`. Deployment-default provider credentials are stored as Cloudflare Worker secrets. The server operator can access those keys and must be trusted. CloudFS does not provide zero-knowledge protection from a malicious operator or a fully compromised client.

Authorization is enforced by the server, including CLI requests. Hiding an administrative control is not an authorization boundary. Browser sessions and native device sessions can be revoked; signed storage URLs remain usable until their short expiry.

Snapshots retain historical versions within the same deployment. They do not replace an independent backup and cannot protect against an operator deleting the deployment and all storage. Follow [backup and recovery](docs/BACKUP-RESTORE.md) and protect the separate recovery key.

## Operator responsibilities

- Use HTTPS, restrict Cloudflare administration and revoke temporary provisioning tokens after installation.
- Keep the deployment profile and secrets private. Never regenerate `STORAGE_ENC_KEY` during an update: existing sealed keys and data may become unrecoverable.
- Restrict storage credentials to their intended buckets. Keep them out of apps, source repositories and support reports.
- Protect the Mac, its Keychain and pending-write data. Wait for uploads to finish before uninstalling or clearing state.
- Test access controls, email delivery and recovery with disposable data before inviting a real team.

See the [security architecture](docs/security.md), [operations guide](docs/SERVER-OPERATIONS.md) and [preview limitations](docs/COMPATIBILITY.md).
