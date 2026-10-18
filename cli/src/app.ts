// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Program assembly + the action runner. Kept separate from `main.ts` so tests
 * can build a program with an injected GatewayClient and capture output.
 */
import { Command } from "commander";
import { buildContext, FilespaceRequiredError, type Context, type GlobalOptions } from "./context.js";
import { CliError, ExitCode } from "./exit-codes.js";
import type { GatewayClient } from "./gateway/client.js";
import { printError, printResult, type OutputOptions } from "./output.js";
import { CLI_VERSION } from "./commands/version.js";

import { registerAuth } from "./commands/auth.js";
import { registerFilespace } from "./commands/filespace.js";
import { registerMount } from "./commands/mount.js";
import { registerCache } from "./commands/cache.js";
import { registerNamespace } from "./commands/namespace.js";
import { registerShare } from "./commands/share.js";
import { registerAdmin } from "./commands/admin.js";
import { registerInvite } from "./commands/invite.js";
import { registerSnapshot } from "./commands/snapshot.js";
import { registerSync } from "./commands/sync.js";
import { registerEvents } from "./commands/events.js";
import { registerDaemon } from "./commands/daemon.js";
import { registerVersion } from "./commands/version.js";

/**
 * The PROGRAM-LEVEL (global) options, with whether each consumes a value. Used to hoist
 * a global flag that a user typed AFTER the subcommand (e.g. `cloudfs filespace list
 * --json`) to the front of argv, where commander expects program options. Without this,
 * `enablePositionalOptions()` makes commander reject a trailing `--json` as an unknown
 * option (exit 2) — a papercut for anyone who naturally appends `--json`/`--filespace`.
 * Keep this in EXACT sync with the `program.option(...)` declarations below.
 */
const GLOBAL_OPTION_SPEC: Record<string, { takesValue: boolean }> = {
  "--json": { takesValue: false },
  "--output": { takesValue: true },
  "-q": { takesValue: false },
  "--quiet": { takesValue: false },
  "--token-file": { takesValue: true },
  "--filespace": { takesValue: true },
  "--mock": { takesValue: false },
  // NB: `--token` is intentionally NOT hoisted — `auth login` defines its OWN `--token`
  // (with identical bearer-token semantics), and stealing it to the program level would
  // empty the subcommand's `opts.token`. The global `--token` before the subcommand still
  // works, and `auth login --token X` is handled by the subcommand option directly.
};

/**
 * Move recognized global option tokens from anywhere in argv to the FRONT, preserving
 * order otherwise. `--opt=value` is hoisted as a single token; `--opt value` hoists both.
 * Everything after a literal `--` is left untouched (POSIX end-of-options). Unknown
 * options are left in place so commander still reports a genuine typo.
 */
export function hoistGlobalFlags(argv: string[]): string[] {
  const globals: string[] = [];
  const rest: string[] = [];
  let passthrough = false;
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (passthrough) {
      rest.push(tok);
      continue;
    }
    if (tok === "--") {
      passthrough = true;
      rest.push(tok);
      continue;
    }
    const eq = tok.indexOf("=");
    const name = tok.startsWith("--") && eq > 0 ? tok.slice(0, eq) : tok;
    const spec = GLOBAL_OPTION_SPEC[name];
    if (spec) {
      globals.push(tok);
      // `--opt value` (separate value token, no `=`): hoist the value too.
      if (spec.takesValue && eq < 0 && i + 1 < argv.length) {
        globals.push(argv[++i]);
      }
    } else {
      rest.push(tok);
    }
  }
  return [...globals, ...rest];
}

/** Result an action stashes on its command for the runner to render. */
export interface ActionResult {
  data: unknown;
  table?: Record<string, unknown>[] | Record<string, unknown>;
  summary?: string;
  /** Set by streaming commands that already wrote their own output. */
  alreadyPrinted?: boolean;
}

// Augment commander's Command with the fields our actions set.
declare module "commander" {
  interface Command {
    result?: ActionResult;
    exitCodeOverride?: number;
  }
}

export interface BuildOptions {
  /** Inject a client (tests). When omitted, the mock is used per buildContext. */
  client?: GatewayClient;
  /** Capture output instead of writing to stdout/stderr (tests). */
  capture?: { stdout: string[]; stderr: string[] };
  /** Called by the runner with the final exit code instead of process.exit (tests). */
  onExit?: (code: number) => void;
}

/**
 * Build the full `cloudfs` Command tree. Returns the program plus a `run`
 * helper that parses argv, executes, renders, and resolves with the exit code.
 */
export function buildProgram(opts: BuildOptions = {}): {
  program: Command;
  run: (argv: string[]) => Promise<number>;
} {
  const program = new Command();

  program
    .name("cloudfs")
    .description("cloud-fs CLI — scriptable control of filespaces, cache, permissions, snapshots & sync.")
    .version(CLI_VERSION, "-v, --version", "print version")
    .option("--json", "machine-readable JSON output (overrides --output)", false)
    .option("--output <format>", "output format: table | json | yaml", "table")
    .option("-q, --quiet", "suppress human output (for cron); errors still go to stderr", false)
    .option("--token <token>", "service-account token (or set CLOUDFS_TOKEN). Prefer --token-file to keep it off ps.")
    .option("--token-file <path>", "read the bearer token from a file (or set CLOUDFS_TOKEN_FILE) — keeps it off argv/ps")
    .option("--filespace <id>", "target filespace (or set CLOUDFS_FILESPACE)")
    .option("--mock", "use the in-memory mock gateway (offline; NO real backend)", false)
    .enablePositionalOptions();

  // Resolve global flags into a Context, lazily (so per-command flags merge).
  let cachedCtx: Context | undefined;
  function ctx(): Context {
    if (cachedCtx) return cachedCtx;
    const g = program.opts<GlobalOptions>();
    const global: GlobalOptions = {
      output: (g.output as OutputOptions["format"]) ?? "table",
      json: !!g.json,
      quiet: !!g.quiet,
      token: g.token,
      tokenFile: g.tokenFile,
      filespace: g.filespace,
      mock: !!g.mock,
    };
    cachedCtx = buildContext(global, opts.client);
    if (opts.capture) {
      cachedCtx.output.stdout = (s) => opts.capture!.stdout.push(s);
      cachedCtx.output.stderr = (s) => opts.capture!.stderr.push(s);
    }
    return cachedCtx;
  }

  // Register every command group.
  registerAuth(program, ctx);
  registerFilespace(program, ctx);
  registerMount(program, ctx);
  registerCache(program, ctx);
  registerNamespace(program, ctx);
  registerShare(program, ctx);
  registerAdmin(program, ctx);
  registerInvite(program, ctx);
  registerSnapshot(program, ctx);
  registerSync(program, ctx);
  registerEvents(program, ctx);
  registerDaemon(program, ctx);
  registerVersion(program, ctx);

  // Make commander throw instead of calling process.exit, so we control codes.
  // Also suppress commander's automatic stderr writes for parse errors so our
  // error handler is the single source of error output (`--json` stays JSON).
  // Help/version text (written via writeOut) is left untouched.
  function patch(c: Command): void {
    c.exitOverride();
    c.configureOutput({ writeErr: () => {} });
    c.commands.forEach(patch);
  }
  patch(program);

  // Capture which command's action ran so the runner can render its result.
  // Registered once at build time (not per-run) to avoid stacking hooks.
  // Held in an object so TS doesn't narrow it to `undefined` across the await.
  const state: { executed?: Command } = {};
  program.hook("postAction", (_thisCmd, actionCmd: Command) => {
    state.executed = actionCmd;
  });

  async function run(argv: string[]): Promise<number> {
    cachedCtx = undefined;
    state.executed = undefined;
    try {
      // Accept global flags placed AFTER the subcommand (e.g. `filespace list --json`)
      // by hoisting them to the front, where commander's positional-options mode expects
      // program options.
      await program.parseAsync(hoistGlobalFlags(argv), { from: "user" });
    } catch (e: unknown) {
      return handleError(e, ctx().output, opts);
    }

    // Render the result the action stashed.
    const ran = state.executed as (Command & { result?: ActionResult; exitCodeOverride?: number }) | undefined;
    const result = ran?.result;
    if (result) {
      const out = ctx().output;
      if (!result.alreadyPrinted) {
        printResult({ data: result.data, table: result.table, summary: result.summary }, out);
      }
      const code = ran?.exitCodeOverride ?? ExitCode.OK;
      opts.onExit?.(code);
      return code;
    }

    opts.onExit?.(ExitCode.OK);
    return ExitCode.OK;
  }

  return { program, run };
}

function handleError(e: unknown, out: OutputOptions, opts: BuildOptions): number {
  // commander's own errors (help shown, version, bad usage).
  if (isCommanderError(e)) {
    const ce = e as { code: string; exitCode: number; message: string };
    // Help/version output already printed by commander to stdout; succeed.
    if (ce.code === "commander.helpDisplayed" || ce.code === "commander.version" || ce.code === "commander.help") {
      opts.onExit?.(ExitCode.OK);
      return ExitCode.OK;
    }
    // Usage errors (unknown command/option, missing arg). Commander prefixes
    // its messages with "error: "; strip it so printError adds exactly one.
    const code = ExitCode.USAGE;
    const message = (ce.message || "usage error").replace(/^error:\s*/i, "");
    printError(message, code, out);
    opts.onExit?.(code);
    return code;
  }

  if (e instanceof FilespaceRequiredError) {
    printError(e.message, ExitCode.USAGE, out);
    opts.onExit?.(ExitCode.USAGE);
    return ExitCode.USAGE;
  }

  if (e instanceof CliError) {
    printError(e.message, e.code, out, e.detail);
    opts.onExit?.(e.code);
    return e.code;
  }

  const msg = e instanceof Error ? e.message : String(e);
  printError(msg, ExitCode.GENERIC, out);
  opts.onExit?.(ExitCode.GENERIC);
  return ExitCode.GENERIC;
}

function isCommanderError(e: unknown): boolean {
  return !!e && typeof e === "object" && "code" in e && typeof (e as { code: unknown }).code === "string" && String((e as { code: string }).code).startsWith("commander.");
}
