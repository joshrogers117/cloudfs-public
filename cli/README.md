# cloudfs CLI

`cloudfs` is the command-line client for the cloud-fs gateway and local daemon. Use it
for filespace administration, namespace operations, snapshots, share links, and scripts
that coordinate with a mounted client.

## Build and run

```sh
cd cli
npm ci
npm test
npm run build
node dist/main.js --help
```

For development, `npm run cloudfs -- --help` runs the TypeScript entry point directly.
That command uses Node's built-in type stripping and requires Node.js 22.12.0 or later.

## Connection and authentication

Set `CLOUDFS_GATEWAY_URL` to the gateway origin and provide a bearer token. Interactive
OIDC login is available with `cloudfs auth login --sso` when the gateway has an identity
provider configured.

```sh
export CLOUDFS_GATEWAY_URL=https://gateway.example
cloudfs auth login --sso
cloudfs auth status

# For automation, prefer a protected token file over a command-line token.
cloudfs --token-file /run/secrets/cloudfs-token filespace list
```

Token resolution order is `--token`, `--token-file` or `CLOUDFS_TOKEN_FILE`,
`CLOUDFS_TOKEN`, then the token saved by SSO login. The default saved-token directory is
`$XDG_CONFIG_HOME/cloudfs` when `XDG_CONFIG_HOME` is set, otherwise
`~/.config/cloudfs`; set `CLOUDFS_CONFIG_DIR` to override it. The token file is created
with owner-only permissions where supported.

The CLI does not silently select demo data. To use the in-memory mock explicitly, pass
`--mock` or set `CLOUDFS_MOCK=1`. Mock mode is for local development and does not contact
the gateway. When no mock is selected, `CLOUDFS_GATEWAY_URL` (or the compatibility alias
`CLOUDFS_GATEWAY`) is required.

## Global options and environment

| Option or variable | Purpose |
|---|---|
| `--json` | Emit JSON output. |
| `--output table\|json\|yaml` | Select output format; default is `table`. |
| `-q, --quiet` | Suppress human-readable output. |
| `--token <value>` | Supply a bearer token. Prefer `--token-file` for automation. |
| `--token-file <path>` | Read a bearer token from a file. |
| `--filespace <id>` | Set the default filespace. |
| `--mock` | Use the in-memory mock gateway explicitly. |
| `CLOUDFS_GATEWAY_URL` | Gateway origin; `CLOUDFS_GATEWAY` is also accepted. |
| `CLOUDFS_TOKEN`, `CLOUDFS_TOKEN_FILE` | Token value or token-file path. |
| `CLOUDFS_FILESPACE` | Default filespace when one is not passed. |
| `CLOUDFS_CONFIG_DIR` | Directory for the saved SSO token. |
| `CLOUDFS_DAEMON_SOCKET` | Override the local daemon control socket. |
| `CLOUDFS_MOCK=1` | Select mock mode; `CLOUDFS_MOCK_AUTHED=1` marks the mock authenticated. |
| `CLOUDFS_REQUEST_TIMEOUT_MS` | Per-request timeout in milliseconds; default `30000`, `0` disables it. |
| `CLOUDFS_MAX_RETRIES` | Retry count for transient errors on idempotent requests; default `3`, `0` disables retries. |

The CLI uses the local daemon for cache, pin, mount, flush, wait, and event operations when
its control socket is available. Set `CLOUDFS_DAEMON_SOCKET` to select a specific socket.
Gateway operations use the HTTP API described in [the gateway API reference](../backend/API.md).

## Commands

Run `cloudfs --help` or `cloudfs <command> --help` for flags and argument details.

```text
auth login|logout|status
filespace list|status|create|connect|disconnect
mount|unmount|daemon
cache info|set-size|set-location|pin|unpin|pin-list|prefetch
ls|stat|tree
share link create|list|revoke
users list|create|remove
groups list|create|add-member|remove-member
permissions grant|revoke|list
invite create|list|revoke
snapshot list|create|restore
flush|wait
activity|events
version
```

An explicit filespace argument takes precedence; otherwise commands use `--filespace` and
then `CLOUDFS_FILESPACE` where the command supports a filespace.

`cloudfs events` streams newline-delimited JSON events. `cloudfs activity` returns a
bounded recent activity list. `cloudfs flush` requests a write-back flush, and `cloudfs
wait` waits for the daemon to report that a path is synchronized. These local operations
require a running daemon.

## Output and exit status

`--json` returns an `{ "ok": true, "data": ... }` success envelope or an
`{ "ok": false, "error": ... }` error envelope for non-streaming commands. The `events`
stream is NDJSON. Exit codes are defined in `cloudfs version`; callers should handle
unknown nonzero codes as command failures.
