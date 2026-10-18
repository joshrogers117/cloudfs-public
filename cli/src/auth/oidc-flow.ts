// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Interactive OIDC (SSO) login for the CLI — the loopback (PKCE-style) browser
 * flow standard for native/CLI apps.
 *
 * Flow (backend/src/oidc-INTEGRATION.md):
 *   1. Start a temporary HTTP listener on 127.0.0.1:<ephemeral>.
 *   2. Open `<gateway>/v1/auth/oidc/start?return_to=http://127.0.0.1:<port>/callback`
 *      in the user's browser (print the URL if no browser is available).
 *   3. The gateway 302s to the IdP; after auth the gateway's `/callback` mints a
 *      cloud-fs SESSION token and delivers it back to our loopback `return_to`
 *      as `?token=<jws>` (or `#token=` / a JSON body the page posts to us).
 *   4. We capture the token, ack the browser ("you can close this tab"), and
 *      return it to the caller, which stores it via the token store.
 *
 * LIVE PREREQ: a real OIDC IdP must be configured on the gateway
 * (OIDC_ISSUER / CLIENT_ID / CLIENT_SECRET / REDIRECT_URI — see the integration
 * guide). With no IdP configured the gateway's `/start` returns an error; this
 * module is validated against an in-process fake gateway in the tests.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { CliError, ExitCode } from "../exit-codes.js";

export interface OidcFlowOptions {
  /** Gateway base URL (e.g. https://gw.cloudfs.example). */
  gatewayUrl: string;
  /** Where to print user-facing instructions. Defaults to stderr. */
  log?: (line: string) => void;
  /** Open a URL in the browser. Defaults to the OS opener; return false if none. */
  openBrowser?: (url: string) => boolean | Promise<boolean>;
  /** Bind host for the loopback listener. Default 127.0.0.1. */
  host?: string;
  /** Max time to wait for the callback (ms). Default 120_000. */
  timeoutMs?: number;
  /** Test seam: force a specific port (0 = ephemeral). */
  port?: number;
}

export interface OidcFlowResult {
  token: string;
}

/** Run the loopback OIDC login and resolve with the minted session token. */
export async function runOidcLogin(opts: OidcFlowOptions): Promise<OidcFlowResult> {
  const host = opts.host ?? "127.0.0.1";
  const log = opts.log ?? ((l: string) => process.stderr.write(l + "\n"));
  const timeoutMs = opts.timeoutMs ?? 120_000;

  const { server, port } = await listen(host, opts.port ?? 0);
  const redirectUri = `http://${host}:${port}/callback`;

  const startUrl = new URL(opts.gatewayUrl.replace(/\/+$/, "") + "/v1/auth/oidc/start");
  startUrl.searchParams.set("return_to", redirectUri);

  const tokenPromise = waitForCallback(server, timeoutMs);

  // Best-effort browser open; always print the URL so a headless user can copy it.
  const opener = opts.openBrowser ?? defaultOpenBrowser;
  let opened = false;
  try {
    opened = await opener(startUrl.toString());
  } catch {
    opened = false;
  }
  log("");
  log("To sign in, open this URL in your browser:");
  log(`  ${startUrl.toString()}`);
  log(opened ? "(opened it for you — complete the login there, then return here)" : "(no browser detected — copy the URL above)");
  log("");
  log("Waiting for the sign-in to complete…");

  try {
    const token = await tokenPromise;
    return { token };
  } finally {
    server.close();
  }
}

/** Bind the loopback HTTP listener and report the chosen port. */
function listen(host: string, port: number): Promise<{ server: Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address();
      if (addr && typeof addr === "object") resolve({ server, port: addr.port });
      else reject(new CliError("failed to bind loopback listener for SSO", ExitCode.GENERIC));
    });
  });
}

/**
 * Resolve with the token the gateway delivers to our loopback `/callback`.
 * Accepts the token from the `token` query param (the gateway 302s here with
 * `?token=`), or a `{ token }` JSON body (POST), or `error`/`error_description`.
 */
function waitForCallback(server: Server, timeoutMs: number): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new CliError("timed out waiting for SSO login to complete", ExitCode.AUTH_FAILED));
    }, timeoutMs);

    const onRequest = async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (!url.pathname.startsWith("/callback")) {
        res.writeHead(404).end("not found");
        return;
      }

      let token = url.searchParams.get("token") ?? undefined;
      const err = url.searchParams.get("error") ?? undefined;
      let errDesc = url.searchParams.get("error_description") ?? undefined;

      // Also accept a JSON body POST (the gateway callback returns {token,...}).
      if (!token && !err && req.method === "POST") {
        const body = await readBody(req);
        try {
          const parsed = JSON.parse(body) as { token?: string; error?: string; reason?: string };
          token = parsed.token;
          if (parsed.error) errDesc = parsed.reason ?? parsed.error;
        } catch {
          /* not JSON */
        }
      }

      if (token) {
        respondHtml(res, 200, "Signed in. You can close this tab and return to the terminal.");
        cleanup();
        resolve(token);
        return;
      }

      respondHtml(res, 400, `Sign-in failed: ${errDesc ?? err ?? "no token returned"}.`);
      cleanup();
      reject(new CliError(`SSO callback returned no token${errDesc ? `: ${errDesc}` : ""}`, ExitCode.AUTH_FAILED));
    };

    function cleanup(): void {
      clearTimeout(timer);
      server.off("request", onRequest);
    }
    server.on("request", (req, res) => void onRequest(req, res));
  });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", () => resolve(data));
  });
}

function respondHtml(res: ServerResponse, status: number, message: string): void {
  const html = `<!doctype html><meta charset="utf-8"><title>cloudfs</title><body style="font-family:system-ui;padding:3rem"><h2>${message}</h2></body>`;
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" }).end(html);
}

/** OS browser opener; returns false if no opener is available. */
function defaultOpenBrowser(url: string): boolean {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
    return true;
  } catch {
    return false;
  }
}
