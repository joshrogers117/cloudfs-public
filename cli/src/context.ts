// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Runtime context shared by all commands: resolved global flags, the chosen
 * GatewayClient, and output options. Commander stashes one of these per run.
 */
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { GatewayClient } from "./gateway/client.js";
import { MockGatewayClient } from "./gateway/mock.js";
import { HttpGatewayClient } from "./gateway/http.js";
import { EngineClient } from "./engine/client.js";
import { loadToken } from "./auth/token-store.js";
import type { OutputFormat, OutputOptions } from "./output.js";

export interface GlobalOptions {
  output: OutputFormat;
  json: boolean;
  quiet: boolean;
  token?: string;
  /** Path to a file whose contents are the bearer token (audit B16: keeps it off argv/ps). */
  tokenFile?: string;
  filespace?: string;
  /** When set, force the in-memory mock (default until HttpGatewayClient ships). */
  mock?: boolean;
}

export interface Context {
  client: GatewayClient;
  output: OutputOptions;
  global: GlobalOptions;
  /** Resolve the target filespace from --filespace, env, or arg; throws if unset. */
  filespace(explicit?: string): string;
  /** Build a gateway client bound to a specific token (used right after SSO login). */
  clientForToken(token: string): GatewayClient;
}

/** The configured gateway origin, or null if none is set. */
export function resolveGatewayUrl(): string | null {
  return process.env.CLOUDFS_GATEWAY_URL ?? process.env.CLOUDFS_GATEWAY ?? null;
}

/**
 * Resolve the active bearer token. Precedence:
 *   `--token` > `--token-file`/`CLOUDFS_TOKEN_FILE` > `CLOUDFS_TOKEN` env > the
 *   persisted token store (written by SSO login).
 *
 * Audit B16: `--token <value>` on argv leaks the secret into `ps`/shell history. A
 * `--token-file` (or `CLOUDFS_TOKEN_FILE`) keeps it off the command line; the file's
 * trimmed contents are the token. `--token` still works for convenience but the file
 * path is the recommended non-leaking option.
 */
function resolveToken(global: GlobalOptions): string | undefined {
  if (global.token) return global.token;
  const file = global.tokenFile ?? process.env.CLOUDFS_TOKEN_FILE;
  if (file) {
    const raw = readFileSync(file, "utf8").trim();
    if (raw) return raw;
  }
  return process.env.CLOUDFS_TOKEN ?? loadToken() ?? undefined;
}

/** True when the mock gateway was EXPLICITLY requested (--mock or CLOUDFS_MOCK=1). */
function mockRequested(global?: GlobalOptions): boolean {
  return !!global?.mock || process.env.CLOUDFS_MOCK === "1" || process.env.CLOUDFS_MOCK === "true";
}

/**
 * Build the REMOTE transport for the given token.
 *
 * Audit B11 (silent-mock trap): the CLI used to fall back to the in-memory MOCK whenever
 * the gateway URL was missing/misspelled — so a real SSO login completed and then every
 * command silently ran against FAKE data (`flush` returned inSync:true, exit 0). The mock
 * is now selected ONLY when explicitly requested (--mock / CLOUDFS_MOCK=1). Otherwise:
 *   - a gateway URL (CLOUDFS_GATEWAY_URL OR the legacy CLOUDFS_GATEWAY) is REQUIRED;
 *   - if a token is set but no URL → throw "no gateway configured" (the most plausible
 *     misconfig — a token persisted but the URL wrong/absent — fails LOUDLY, exit ≠ 0).
 */
function makeGatewayClient(token: string | undefined, global?: GlobalOptions): GatewayClient {
  // Unify the env-var name: CLOUDFS_GATEWAY_URL is canonical, CLOUDFS_GATEWAY is the legacy
  // alias other clients use (the audit flagged the inconsistency). Accept either.
  const gatewayUrl = process.env.CLOUDFS_GATEWAY_URL ?? process.env.CLOUDFS_GATEWAY;

  if (mockRequested(global)) {
    process.stderr.write("[cloudfs] [mock gateway — no real backend; offline mock data]\n");
    return new MockGatewayClient({
      authenticated: !!token || process.env.CLOUDFS_MOCK_AUTHED === "1",
      token,
      gateway: gatewayUrl ?? "https://gateway.cloudfs.local",
    });
  }

  if (!gatewayUrl) {
    throw new NoGatewayConfiguredError(!!token);
  }
  // A URL is set → the real HTTP client. A missing token surfaces as a clear auth error from
  // HttpGatewayClient (it needs a JWS with an `org` claim) rather than a silent mock — which is
  // exactly the loud-failure behavior B11 wants.
  return new HttpGatewayClient({ baseUrl: gatewayUrl, token: token ?? "" });
}

/** Thrown when no gateway URL is configured and the mock was not explicitly requested. */
export class NoGatewayConfiguredError extends Error {
  constructor(hasToken: boolean) {
    super(
      hasToken
        ? "no gateway configured: a token is set but CLOUDFS_GATEWAY_URL (or CLOUDFS_GATEWAY) is empty. Set the gateway URL, or pass --mock for offline mock data."
        : "no gateway configured: set CLOUDFS_GATEWAY_URL (or CLOUDFS_GATEWAY) to your gateway origin, or pass --mock for offline mock data.",
    );
    this.name = "NoGatewayConfiguredError";
  }
}

/**
 * Build a Context from resolved global flags.
 *
 * The GatewayClient seam is selected by ONE switch here:
 *   - if `CLOUDFS_GATEWAY_URL` is set AND a token is present (`--token` /
 *     `CLOUDFS_TOKEN`), use the real {@link HttpGatewayClient} against that
 *     origin (backend/API.md);
 *   - otherwise fall back to the deterministic, offline {@link MockGatewayClient}.
 * A test/explicit `clientOverride` always wins.
 *
 * For the mock, `CLOUDFS_TOKEN`/`--token` presence flips it into an
 * authenticated state so token-auth flows work end-to-end offline.
 */
export function buildContext(global: GlobalOptions, clientOverride?: GatewayClient): Context {
  const token = resolveToken(global);

  // If the cloudfsd control socket is available, wrap the gateway client in the
  // EngineClient so LOCAL commands (cache/pin/mount/flush/wait/events) hit the
  // daemon over UDS JSON-RPC; everything else delegates to the gateway client.
  const socketPath = resolveDaemonSocket();
  const wrapWithEngine = (gw: GatewayClient): GatewayClient =>
    socketPath ? new EngineClient({ socketPath, gateway: gw }) : gw;

  const client = clientOverride ?? wrapWithEngine(makeGatewayClient(token, global));

  const output: OutputOptions = {
    format: global.json ? "json" : global.output,
    quiet: global.quiet,
  };

  return {
    client,
    output,
    global,
    filespace(explicit?: string): string {
      const fs = explicit ?? global.filespace ?? process.env.CLOUDFS_FILESPACE;
      if (!fs) {
        // Use a plain Error → commander/usage path; callers may also pass explicitly.
        throw new FilespaceRequiredError();
      }
      return fs;
    },
    clientForToken(t: string): GatewayClient {
      // A test override stands in for everything; otherwise build a fresh client
      // bound to the freshly-minted token (used right after SSO login).
      return clientOverride ?? makeGatewayClient(t, global);
    },
  };
}

export class FilespaceRequiredError extends Error {
  constructor() {
    super("no filespace selected — pass <filespace>, --filespace, or set CLOUDFS_FILESPACE");
    this.name = "FilespaceRequiredError";
  }
}

/**
 * Resolve the cloudfsd control-socket path, or `null` if no daemon is configured
 * or running (in which case local commands stay on the Mock/gateway client).
 *
 * Selection order (CONTROL-API.md §1.1):
 *   1. `CLOUDFS_DAEMON_SOCKET` — explicit override; honoured even if the file is
 *      not yet present (connect will surface ENGINE_UNAVAILABLE if truly absent).
 *   2. The default per-OS path, but ONLY if the socket file actually exists, so a
 *      machine with no daemon transparently uses the offline default.
 */
function resolveDaemonSocket(): string | null {
  const explicit = process.env.CLOUDFS_DAEMON_SOCKET;
  if (explicit) return explicit;

  const xdg = process.env.XDG_RUNTIME_DIR;
  const defaultPath =
    process.platform === "darwin"
      ? join(homedir(), "Library", "Application Support", "cloudfs", "cloudfsd.sock")
      : join(xdg ?? "/run/user/0", "cloudfsd.sock");

  return existsSync(defaultPath) ? defaultPath : null;
}
