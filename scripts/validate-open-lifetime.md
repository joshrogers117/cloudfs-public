# Open-file lifetime validation

`validate-open-lifetime.py` exercises backend atomic replacement, server open-handle retention, and two isolated local SMB clients. It writes only uniquely named `cflife-*` files under the supplied disposable test folder. On failure it leaves remote evidence for inspection; after success it deletes only this run's prefixed files. The local run directory and daemon logs remain private under the state directory.

The replacement itself is one backend `PATCH /items/:id` carrying `replace`. Client A writes the old file; client B opens it and reads a 4 KiB prefix before replacement. B has an 8 MiB block cache and 8 MiB read-ahead budget. After replacement, the script closes its synthetic API retention handle, reads the full 12 MiB new pathname through B to pressure that cache, then reads a 64 KiB tail from B's already-open old descriptor. It checks that B's object-storage request counter increases during the tail read and that both mounted paths show the replacement. This tests backend rename-overwrite and native open-file behavior; it does not exercise macOS `smbfs`'s POSIX `rename(2)` request sequence, which may still issue delete and rename as separate operations.

For disposable VMs without Python, [validate-vm-open-lifetime.pl](validate-vm-open-lifetime.pl) provides a Perl-core participant for host-driven replacement. It creates an isolated run folder and two 8 MiB payloads, emits a readiness JSON object with exact relative source/target paths and hashes, waits for the host API to move `vm-replacement.bin` over `vm-source.bin`, tests the held old descriptor, then clears cache while unmounted and checks cold and warm remount behavior. It also writes and flushes `vm-after-edit.bin` after the host replacement. Pass `--report-url http://10.x.x.x:PORT/vm-report` to post readiness and final JSON to a host-only collector.

## Inputs

- A disposable, existing writable filespace and folder. `--folder-id` is the backend item ID; `--folder-relative` is that same folder's path below both client mount roots (default `.`).
- A built executable `cloudfsd`.
- A private state directory with mode `0700`, containing `a/token` and `b/token`, each mode `0600`. Tokens must be valid bearer JWTs with read and write access to the test folder. The script reads them from disk and supplies them to curl through stdin configuration; it does not put tokens in command arguments, environment variables, logs, or output.
- Optionally, a private text key file (`0600`) accepted by `cloudfsd --key-file`, plus its organization claim (`--key-org`). The harness binds it to the supplied gateway and filespace.
- macOS with `/usr/bin/curl`, Python 3, and permission to mount and unmount SMB filesystems.

For example, with the state directory and fixture already prepared:

```sh
chmod 700 /tmp/cloudfs-lifetime37
chmod 600 /tmp/cloudfs-lifetime37/a/token /tmp/cloudfs-lifetime37/b/token
scripts/validate-open-lifetime.py \
  --gateway https://gateway.example \
  --filespace FILESPACE_ID \
  --folder-id BACKEND_FOLDER_ID \
  --folder-relative path/to/test-folder \
  --daemon /absolute/path/to/cloudfsd \
  --state-dir /tmp/cloudfs-lifetime37
```

Add `--key-file /private/path/to/key --key-org your-org` for an encrypted filespace. The command starts two daemons with separate caches, control sockets, and mounts under the state directory. It contacts the supplied gateway, creates synthetic files, and performs backend API mutations. Run it only against the disposable fixture. A successful result prints a private `report.json` path; a failure prints a redacted error and leaves its local evidence directory and any uniquely prefixed remote files for review.

The API portion also checks cross-client share-mode denial/allowance, batch renewal and close, and bounded TTL expiry. ACL revocation is skipped because the runner intentionally does not accept a workspace-admin credential. The test uses private service tokens and does not modify grants.
