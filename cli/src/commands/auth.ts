// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import { type Context, resolveGatewayUrl } from "../context.js";
import { CliError, ExitCode } from "../exit-codes.js";
import { runOidcLogin } from "../auth/oidc-flow.js";
import { clearToken, saveToken, tokenPath } from "../auth/token-store.js";

/** `cloudfs auth login|logout|status` — service-account token + interactive SSO. */
export function registerAuth(program: Command, ctx: () => Context): void {
  const auth = program.command("auth").description("authentication & service-account tokens");

  auth
    .command("login")
    .description("authenticate: --sso for the interactive OIDC browser flow, or --token for non-interactive")
    .option("--token <token>", "service-account token (or set CLOUDFS_TOKEN)")
    .option("--sso", "interactive OIDC (SSO) login via the browser")
    .action(async (opts: { token?: string; sso?: boolean }, cmd) => {
      const c = ctx();

      if (opts.sso) {
        // Interactive OIDC: loopback browser flow against the gateway, then
        // persist the minted session token so later commands authenticate.
        const gatewayUrl = resolveGatewayUrl();
        if (!gatewayUrl) {
          throw new CliError(
            "SSO login needs a gateway URL — set CLOUDFS_GATEWAY_URL (or CLOUDFS_GATEWAY) to your gateway origin",
            ExitCode.USAGE,
          );
        }
        const { token } = await runOidcLogin({ gatewayUrl });
        saveToken(token);
        // Confirm the stored token authenticates (decodes claims / probes health).
        const status = await c.clientForToken(token).authStatus();
        cmd.result = {
          data: { ...status, tokenStored: tokenPath() },
          summary: `Logged in as ${status.principal ?? "(unknown)"} via SSO. Token saved to ${tokenPath()}.`,
        };
        return;
      }

      // FINDING 1: resolve the token from the SUBCOMMAND flag first, then the global
      // flag / env. The default `c.client` was built in buildContext from the GLOBAL
      // token only, so a `--token` passed to *this* subcommand never reached it (and
      // with no global token that client is a MOCK that "succeeds" without validating).
      // Build a client bound to the RESOLVED token (mirrors the `--sso` branch's
      // clientForToken pattern) so login() validates THIS token against the gateway.
      const token = opts.token ?? c.global.token ?? process.env.CLOUDFS_TOKEN;
      if (!token) {
        throw new CliError(
          "no token provided — pass --token <token> or set CLOUDFS_TOKEN (or use --sso)",
          ExitCode.AUTH_FAILED,
        );
      }
      const status = await c.clientForToken(token).login({ token, sso: false });
      // Persist ONLY after a real validation succeeds, so a bad token never lands in
      // the token store unverified.
      saveToken(token);
      cmd.result = { data: status, summary: `Logged in as ${status.principal} (${status.kind}) on ${status.org}` };
    });

  auth
    .command("logout")
    .description("clear the local session / token")
    .action(async (_opts, cmd) => {
      await ctx().client.logout();
      clearToken();
      cmd.result = { data: { loggedOut: true }, summary: "Logged out (cleared stored token)." };
    });

  auth
    .command("status")
    .alias("whoami")
    .description("show current authentication status")
    .action(async (_opts, cmd) => {
      const c = ctx();
      const status = await c.client.authStatus();
      if (!status.authenticated) {
        cmd.exitCodeOverride = ExitCode.NOT_AUTHENTICATED;
        cmd.result = { data: status, summary: "Not authenticated." };
        return;
      }
      cmd.result = { data: status, summary: `Authenticated as ${status.principal} (${status.kind}).` };
    });
}
