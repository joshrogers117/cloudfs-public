# CloudFS

A self-hosted streaming filesystem for Mac teams. The server runs in your Cloudflare account; the Mac app presents files in Finder and downloads encrypted blocks into a local cache as you use them.

**Public preview.** Start with copies of files and test your editing applications before relying on it for production work. See [tested workflows and limitations](docs/COMPATIBILITY.md).

## Install

Download the **CloudFS Server** package and **CloudFS for Mac** DMG from [Releases](https://github.com/joshrogers117/cloudfs-public/releases). Each release includes SHA-256 checksums.

- **Administrators:** follow [Install CloudFS](INSTALL.md) to deploy a new server, create the first account and invite teammates.
- **Teammates:** open your invitation, create your account, install the Mac app and sign in through your browser. You do not need Cloudflare credentials or a setup secret.

The administrator needs Workers Paid, R2, Node.js 22.12+, and a temporary Cloudflare provisioning token. Email delivery also needs an approved sender domain. The guided terminal installer creates the infrastructure and opens browser setup. There is no browser-only infrastructure installer in this preview.

## What it does

- Finder volumes with demand-driven reads, encrypted local caching, folder pins and bounded write-back.
- Browser-to-app sign-in, revocable device sessions, user/group access and server-enforced administrative permissions.
- Distributed write leases, open-file tracking and remote change notifications.
- Read-only snapshot volumes, selective file recovery and independent encrypted server backups.
- A browser console for accounts, filespaces, storage, activity and administration.
- A CLI for automation using the same authorization rules as the app.

The default deployment uses Cloudflare R2. Existing S3-compatible storage can be configured separately; compatibility and costs depend on that provider. You pay your infrastructure provider directly.

## How it works

The Swift engine exposes a loopback SMB server through macOS's built-in filesystem client. No third-party filesystem driver or kernel extension is required. The app manages connections and settings; Finder browses the files.

Cloudflare Workers and Durable Objects hold accounts, file metadata, permissions, locks and snapshots. Encrypted file blocks travel directly between the Mac and object storage using short-lived signed URLs. The Worker controls access and distributes filespace keys sealed with the deployment encryption key. **This is not zero-knowledge storage:** the server operator is trusted.

| Component | Purpose |
| --- | --- |
| `backend/` | Worker gateway and Durable Object authorities |
| `web/` | Setup, sign-in and administration console |
| `cloudfsd/` | Native filesystem engine, cache and transfers |
| `client-app/` | Mac app and Finder integration |
| `cli/` | Command-line client |
| `scripts/` | Installation, deployment, backup and release tools |

## Documentation

- [Installation and first-time setup](INSTALL.md)
- [Advanced self-hosting](docs/SELF-HOSTING.md)
- [Operations, upgrades and troubleshooting](docs/SERVER-OPERATIONS.md)
- [Independent backup and recovery](docs/BACKUP-RESTORE.md)
- [Compatibility and release qualification](docs/COMPATIBILITY.md)
- [Build from source](docs/BUILD.md) and [contributing](CONTRIBUTING.md)
- [HTTP API](backend/API.md), [engine control API](cloudfsd/CONTROL-API.md) and [mount architecture](cloudfsd/MOUNT.md)
- [Security model](docs/security.md) and [private vulnerability reporting](SECURITY.md)
- [Release process](docs/PUBLISHING.md)

Report reproducible problems through [GitHub Issues](https://github.com/joshrogers117/cloudfs-public/issues). Remove credentials and private file/account details from reports. Security issues belong in the private channel described in [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0 or later](LICENSE). See [NOTICE](NOTICE) for attribution; release packages include third-party dependency notices.
