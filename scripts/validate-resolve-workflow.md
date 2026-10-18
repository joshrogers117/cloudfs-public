# Resolve workflow validation

Run `validate-resolve-workflow.py` through ResolvePython while Resolve is open with no existing editing project. It creates uniquely named validation projects, imports the fixture MOV, edits three cuts, exports/reopens a project, and renders 288 frames to the mounted fixture. Before declaring success, it flushes and requires the selected filespace to remain connected at the fixture's parent mount with zero pending uploads and bytes. It saves JSON evidence and does not delete the resulting projects or files. The default control socket remains `~/Library/Application Support/cloudfs/d.sock`.

An optional `--control-socket` selects an already running isolated host daemon. This mode requires all of the following before it calls the Resolve API:

- `--filespace edit1` and the exact root `/private/tmp/cloudfs-collaboration-SUFFIX/mount/cloudfs-editor-validation-20261015`.
- The socket `/private/tmp/cloudfs-collaboration-SUFFIX/control.sock` or `d.sock` in the same unique directory. The suffix is 6–64 letters, digits, underscores or hyphens.
- A canonical, current-user-owned private parent and Unix socket, with no symlinks in the mount or fixture path.
- Daemon status identifying the exact connected Edit 1 mount, zero pending writes, and a matching SMB mount in the OS mount inventory.

Launch orchestration must independently verify the signed release daemon and create the private directory, cache, control socket and mount. This script does not launch a daemon, mount/unmount, read credentials, change owner app configuration, or restore the installed native app. Evidence labels the target `isolated-signed-release-daemon`, records its engine version, and explicitly sets `installedNativeAppRestorationVerified` to false. Signature verification is not inferred from socket status.

For an already prepared isolated mount, pass these arguments to the existing ResolvePython invocation, substituting the real unique directory and a new evidence output:

```text
scripts/validate-resolve-workflow.py
--root /private/tmp/cloudfs-collaboration-ABC123/mount/cloudfs-editor-validation-20261015
--control-socket /private/tmp/cloudfs-collaboration-ABC123/d.sock
--output /absolute/local/evidence/resolve-isolated.json
```

The root must already contain `CloudFS-Test-1080p.mov`. Only the established fixture is used for media/project/render writes. The local evidence file must not already exist. Running without `--control-socket` retains the existing root and app-socket behavior.

Guard checks need neither Resolve nor credentials:

```sh
python3 scripts/validate-resolve-workflow.py --self-test
python3 -m py_compile scripts/validate-resolve-workflow.py
```

Self-tests perform only lexical scope and status checks. They do not contact a socket or prove that a live workflow passed. Use Python with assertions enabled; optimized `-O` execution is refused.
