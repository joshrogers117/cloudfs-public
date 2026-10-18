// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Output rendering. Every command produces a structured result object and hands
 * it here; the global `--output` (json|table|yaml) and `--quiet` flags decide how
 * it is rendered. This keeps `--json` shape stable and decoupled from commands.
 */

export type OutputFormat = "json" | "table" | "yaml";

export interface OutputOptions {
  format: OutputFormat;
  quiet: boolean;
  /** Stream to write to. Injectable for tests. */
  stdout?: (s: string) => void;
  stderr?: (s: string) => void;
}

/**
 * The envelope every successful command returns. `data` is the payload;
 * `table` is an optional pre-shaped view for human/table output (a list of rows
 * or a flat record). When `table` is omitted, table mode falls back to `data`.
 */
export interface CommandResult {
  /** Stable machine payload — this is exactly what `--json` prints under `.data`. */
  data: unknown;
  /** Optional human-friendly rows for table/plain output. */
  table?: Record<string, unknown>[] | Record<string, unknown>;
  /** Optional one-line human summary printed in non-json, non-quiet mode. */
  summary?: string;
}

function out(opts: OutputOptions): (s: string) => void {
  return opts.stdout ?? ((s: string) => process.stdout.write(s + "\n"));
}
function err(opts: OutputOptions): (s: string) => void {
  return opts.stderr ?? ((s: string) => process.stderr.write(s + "\n"));
}

/** Minimal, dependency-free YAML emitter for flat-ish data (sufficient for CLI output). */
function toYaml(value: unknown, indent = 0): string {
  const pad = "  ".repeat(indent);
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return scalarYaml(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return value
      .map((v) => {
        if (v !== null && typeof v === "object") {
          const block = toYaml(v, indent + 1).replace(new RegExp(`^${"  ".repeat(indent + 1)}`), "");
          return `${pad}- ${block}`;
        }
        return `${pad}- ${scalarYaml(v)}`;
      })
      .join("\n");
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return "{}";
  return entries
    .map(([k, v]) => {
      if (v !== null && typeof v === "object" && Object.keys(v).length > 0) {
        return `${pad}${k}:\n${toYaml(v, indent + 1)}`;
      }
      return `${pad}${k}: ${scalarYaml(v)}`;
    })
    .join("\n");
}
function scalarYaml(v: unknown): string {
  if (typeof v === "string") return /[:#\n]|^\s|\s$/.test(v) ? JSON.stringify(v) : v;
  return String(v);
}

/** Render a simple aligned table from an array of row objects. */
function renderTable(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "(no rows)";
  const cols = Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
  const widths = cols.map((c) =>
    Math.max(c.length, ...rows.map((r) => String(r[c] ?? "").length)),
  );
  const header = cols.map((c, i) => c.toUpperCase().padEnd(widths[i])).join("  ");
  const body = rows
    .map((r) => cols.map((c, i) => String(r[c] ?? "").padEnd(widths[i])).join("  "))
    .join("\n");
  return `${header}\n${body}`;
}

/** Render a flat record as `key: value` lines. */
function renderRecord(rec: Record<string, unknown>): string {
  return Object.entries(rec)
    .map(([k, v]) => `${k}: ${v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : v}`)
    .join("\n");
}

/** Print a successful command result according to the chosen format. */
export function printResult(result: CommandResult, opts: OutputOptions): void {
  const write = out(opts);
  if (opts.format === "json") {
    write(JSON.stringify({ ok: true, data: result.data }, null, 2));
    return;
  }
  if (opts.quiet) {
    // In quiet mode emit nothing but the bare essential (or nothing at all).
    return;
  }
  if (opts.format === "yaml") {
    write(toYaml(result.data));
    return;
  }
  // table (default human format)
  const view = result.table ?? result.data;
  if (Array.isArray(view)) {
    write(renderTable(view as Record<string, unknown>[]));
  } else if (view && typeof view === "object") {
    write(renderRecord(view as Record<string, unknown>));
  } else if (view !== undefined) {
    write(String(view));
  }
  if (result.summary) write(result.summary);
}

/** Print an error according to the chosen format. */
export function printError(
  message: string,
  code: number,
  opts: OutputOptions,
  detail?: Record<string, unknown>,
): void {
  if (opts.format === "json") {
    out(opts)(JSON.stringify({ ok: false, error: { message, code, ...(detail ? { detail } : {}) } }, null, 2));
  } else {
    err(opts)(`error: ${message}`);
  }
}

/** Emit a single NDJSON line (used by event/activity streaming). */
export function printNdjson(obj: unknown, opts: OutputOptions): void {
  out(opts)(JSON.stringify(obj));
}
