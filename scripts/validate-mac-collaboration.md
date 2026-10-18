# Two-Mac filesystem validation

`validate-mac-collaboration.pl` runs with macOS's bundled Perl on the host and disposable VM. It uses the existing `validate-mac-locks.c` binary on each Mac. Both clients must already be signed in and have Edit 1 mounted, and the VM must use the normal-user account. This harness does not install software, sign in, remount, clear caches, or change app configuration.

All fixture writes go into a new `multi-mac-RUN_ID` directory under `~/cloudfs/edit1/cloudfs-editor-validation-20261015`. The host path is under the current user’s home directory (for example, `/Users/your-user/cloudfs/edit1/cloudfs-editor-validation-20261015`); the guest uses the same filespace directory under its own home. It refuses other roots, existing host run directories, and a second guest invocation for a run. No fixture is deleted afterward. It requires both clients to start with no pending writes because daemon `flush` is filespace-wide.

An optional host-only mode targets a separately launched, signed release daemon. Supply **both** `--host-mount` and `--host-control-socket`. The mount must be exactly `/private/tmp/cloudfs-collaboration-SUFFIX/mount`, with a suffix of 6–64 letters, digits, underscores or hyphens, and the socket must be `control.sock` or `d.sock` in that same directory. Launch orchestration must create a unique private directory and verify the release daemon's signature before starting it. The harness requires a current-user-owned private parent and socket, canonical paths without symlinks, an actual SMB mount, and daemon status reporting `filespace=edit1`, `connection=connected`, and that exact mount path. It still allows only the fixed `cloudfs-editor-validation-20261015` child. Guest overrides, `/tmp` aliases, cross-directory sockets, and the installed app's socket are rejected.

The harness does not create this daemon, read host credentials, mount anything, or change the owner's app state. Reports identify `isolated-signed-release-daemon`, disclose that signature verification belongs to launch orchestration, and set `installedNativeAppRestorationVerified` to false. Passing this mode verifies that isolated daemon against the normal-user guest; it does not establish that the installed native app recovered from a Keychain prompt or completed sign-in.

Build the arm64 helper on the host, then use the existing Developer ID signing process and copy the script and signed helper to the guest through the approved test folder. The guest does not need a compiler, Python, or any credential argument. Choose an executable helper location available on each Mac.

```sh
clang -std=c11 -Wall -Wextra -Werror -O2 \
  scripts/validate-mac-locks.c -o /tmp/validate-mac-locks
/usr/bin/perl -c scripts/validate-mac-collaboration.pl
/usr/bin/perl scripts/validate-mac-collaboration.pl --self-test
/usr/bin/perl scripts/validate-mac-collaboration.pl --plan
```

Run these concurrently, replacing `run01` with a fresh common ID and substituting the actual script/helper locations on the guest. Either role can start first, but start the second within the 120-second default timeout. Increase `--timeout` to at most 600 seconds if required. Keep both test sessions otherwise idle while checking cache counters.

Host:

```sh
/usr/bin/perl ./validate-mac-collaboration.pl \
  --role host --helper /tmp/validate-mac-locks --run-id run01
```

Guest:

```sh
/usr/bin/perl ./validate-mac-collaboration.pl \
  --role guest --helper /absolute/path/validate-mac-locks --run-id run01 \
  --gateway-url https://gateway.example.invalid
```

Optional isolated host, after launch orchestration has verified and mounted the signed daemon at these exact paths (the guest command stays unchanged):

```sh
/usr/bin/perl scripts/validate-mac-collaboration.pl \
  --role host --helper /tmp/validate-mac-locks --run-id isolated01 \
  --host-mount /private/tmp/cloudfs-collaboration-ABC123/mount \
  --host-control-socket /private/tmp/cloudfs-collaboration-ABC123/d.sock
```

Substitute the real unique directory. `--plan` with these options performs only lexical validation and shows the selected target; a live invocation additionally validates filesystem ownership, permissions, socket type, mount inventory, and the daemon's status.

The default replacement test remains strict: any missing target fails. After preserving a failed strict report, the host may use **`--diagnose-posix-replace-gap`** in a fresh run to measure a known POSIX delete/rename gap and continue to the completion-marker visibility check. This option is host-only and independent of isolated-host mode. The guest receives the mode in the host's readiness marker for reporting; its writes and rename operation stay unchanged. Use `--timeout 180` on both roles so the guest can wait for the diagnostic observation window. That window is always capped at 180 seconds from its original start, including blocked filesystem calls; missing samples never reset the deadline.

Diagnostic mode tolerates only errno `ENOENT` captured directly from opening `atomic.bin`. It records `missingOpenCount`, first/last missing epoch timestamps, and `maxObservedGapMs`. The gap duration is a sampled interval from the first failed open through the next complete successful read, not an exact measurement of namespace absence. Read/close errors, other open errors, short contents, and unexpected checksums remain fatal. Every completed target read must have both the full expected length and the old or new SHA-256. Completion requires another complete new-content read together with a decoded done marker identifying the exact run and the guest role, within the bounded window.

The diagnostic check is always `limited`, even when it observes zero missing opens. Successful diagnostic reports and their combined summary explicitly set `strictAtomicity: false` and `result: PASS_WITH_LIMITATIONS`; they do not establish atomic replacement. Retain the original strict failure alongside diagnostic evidence. Example additional host options: `--diagnose-posix-replace-gap --timeout 180`. Do not pass the diagnostic flag to the guest.

The script emits JSON progress lines to stdout. Do not redirect them into the new run directory before the host creates it. The host writes `summary.json`, and each role writes `host.report.json` or `guest.report.json`, under the run directory. Helper JSON lines and stderr are retained there. A failure exits 1, records the failed check when possible, and releases only that script's child lock holders. A successful run exits 0; `summary.json` can still be `PASS_WITH_LIMITATIONS`. Preserve that distinction in reports.

Before writing a successful combined summary, the host validates the returned guest terminal report: exact run ID and guest role, a passing terminal result, no error, and a nonempty set of only passing or explicitly limited checks. A late failure report cannot be accepted merely because its marker appeared between polling checks.

Marker waits report their start, state changes, periodic observations, and elapsed time on success. Diagnostics distinguish absent paths, stat/read errors, nonregular files, empty or invalid JSON, and a mismatched run ID without printing marker contents. The timeout also bounds a blocked filesystem call. Waits intentionally do not enumerate directories or remount, so a stale negative lookup remains a visible failure.

Coverage:

- Exclusive Apple `ByteRangeLockPB2` holders on both Macs, overlapping denial probes, disjoint exclusive probes, release, and reacquisition. POSIX `fcntl` returning `ENOTSUP` is recorded as a limitation; this kernel harness does not test shared-range coexistence.
- Host upload checksum on the guest, repeated guest read with no extra object-store requests, a guest overwrite visible through the warmed host mount, and a preserved lock-test file checksum.
- Guest POSIX replacement while the host repeatedly opens and reads the target. In the default strict mode each read must return the complete old or complete new contents; missing paths, read errors, or partial checksums fail. The optional diagnostic mode measures only target-open `ENOENT` as a limitation, retains all content-integrity requirements, and separately requires the validated completion marker. Neither sampled mode proves every possible interleaving.
- One successful normal metadata GET, then six admin GET requests that must return 403. The guest reads its existing daemon token file and passes the header to curl through stdin. Pass the deployment gateway origin with `--gateway-url https://gateway.example.invalid` (or `CLOUDFS_TEST_GATEWAY_URL`); the guest role has no baked-in service endpoint. No token appears in argv, URLs, reports, or response-body files. These are read-only probes; admin mutation endpoints and local CLI commands are outside this script's scope.

An `open_failed` helper result is never a passed byte-range-lock assertion. Expected sharing/open conflicts are reported as `limited` while a remote holder exists. The current conservative whole-inode writer lease can prevent writable opens and disjoint range operations before or during F_SETLK. Therefore this harness does not establish concurrent disjoint-writer support or isolate range locks as the cause of every denial. It also does not test blocking F_SETLKW waiters, fairness, retained open handles after replacement/unlink, hard links, application updates, or remounts.

Local `--self-test` checks result classification, bounded waits, telemetry settling, isolated path scope, status matching, terminal peer-report validation, host-only diagnostic scope, target-read classification, guest completion identity, and sampled-gap accounting without filesystem/network operations. These checks do not establish live backend or multi-Mac correctness; both roles must actually complete for that evidence.
