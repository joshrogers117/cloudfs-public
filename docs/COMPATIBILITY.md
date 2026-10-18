# Preview compatibility and qualification

This preview ships Mac app **0.1.36, build 47**. It is intended for a controlled trial with copies of files. The test results below do not establish full compatibility with every editing application or network environment.

## Platform coverage

| Area | Declared support or implementation | Release rehearsal coverage |
| --- | --- | --- |
| Mac app | Universal Apple Silicon/Intel binary; deployment target macOS 14+ | macOS 27.0.1 on an Apple Silicon Mac and macOS VM. Intel and macOS 14 are not qualified. |
| Installation | Signed, notarized app and DMG; manual drag to Applications | VM install, browser sign-in and update to build 47. The latest VM run retained prior macOS approvals; it was not a repeat of every clean-OS approval prompt. |
| Server | Cloudflare Workers Paid, SQLite Durable Objects, R2 | Fresh isolated deployment and recovery in an existing account. First-account billing and independent-account policies were not tested. |
| Other object stores | Configurable S3-compatible backend | Provider-specific behavior requires a separate qualification. Default R2 path is the release baseline. |

## Workflows exercised

- Guided installer from an extracted release package: resource creation, scoped storage credentials, deployment readiness, first owner and update/resume paths.
- Team invitation, normal-user sign-in, browser-to-app handoff and file access. Restricted administrative operations were rejected server-side.
- Upload with remote durability confirmation, download/checksum comparison, cold and warm cache reads, reconnect/remount and native app update.
- Host/VM file replacement, open-file lifetime and distributed locking regression checks against the live backend.
- Read-only snapshot mount, historical file copy-out and copy/restore into the current filespace, while preserving the snapshot.
- Independent encrypted backup, verification and restoration into a fresh isolated server. The final release rehearsal verified API metadata and encrypted object recovery; it did not prove every restored file through a native editing app.

Automated script, backend, console, CLI and native suites supplement these checks. Live tests are opt-in and are not implied by a green unit suite. No sustained WAN throughput or large-team concurrency guarantee is published.

## Known limitations

- Remote replacement may change a file's SMB presentation identity; its presentation epoch does not persist across remounts. Successful finite replacement tests do not prove POSIX atomicity at every instant.
- POSIX `fcntl` record locks return `ENOTSUP` on the tested macOS SMB mount. `flock` and exclusive SMBFS byte ranges were tested; blocking waits, fairness and general shared-lock application behavior remain unqualified.
- Some SMB resource-fork operations that combine open/create/truncate return `ENOTSUP`. Test apps that rely on extended Mac file behavior before using real projects.
- A snapshot created on another device may require **View → Refresh** before it appears in an already-open snapshot list.
- Email can land in Junk. Verify delivery with the actual sender domain and recipient providers; a successful send request is not proof of inbox placement.
- Mac updates are manual. Finish uploads, quit the app, replace it in Applications and restart the Mac to load the new background engine.
- General editing-app, Intel, older macOS and separate physical-network compatibility remain unqualified. Host and VM tests do not substitute for a second physical Mac on another network.
- The installer requires a terminal on macOS or Linux. A browser-only infrastructure installer and bundled native setup assistant are not provided.
- Snapshots share the deployment's failure domain. Independent backup needs a maintenance window and separately protected recovery material.

## Trial acceptance

Follow [Install CloudFS](../INSTALL.md), then test a normal user on your actual Mac, network and editing application. Check a file's bytes after upload, a cold download and remount; exercise concurrent access and your app's save/replace behavior; recover a file from a snapshot; and rehearse independent backup restoration before relying on it.

If a check fails, preserve pending writes and diagnostics, stop using irreplaceable data, and follow [troubleshooting](SERVER-OPERATIONS.md). Report the app/server version, macOS version, exact operation and a disposable reproduction through the project's issue tracker.
