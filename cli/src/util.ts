// SPDX-License-Identifier: AGPL-3.0-or-later
/** Small formatting/parsing helpers shared across commands. */
import { CliError, ExitCode } from "./exit-codes.js";

const UNITS: Record<string, number> = {
  b: 1,
  k: 1024,
  kb: 1024,
  kib: 1024,
  m: 1024 ** 2,
  mb: 1024 ** 2,
  mib: 1024 ** 2,
  g: 1024 ** 3,
  gb: 1024 ** 3,
  gib: 1024 ** 3,
  t: 1024 ** 4,
  tb: 1024 ** 4,
  tib: 1024 ** 4,
};

/** Parse a human size string ("256GiB", "10TB", "1024") into bytes. */
export function parseSize(input: string): number {
  const m = /^([\d.]+)\s*([a-zA-Z]*)$/.exec(input.trim());
  if (!m) throw new CliError(`invalid size: ${input}`, ExitCode.USAGE);
  const value = Number(m[1]);
  const unit = (m[2] || "b").toLowerCase();
  if (!Number.isFinite(value) || !(unit in UNITS)) throw new CliError(`invalid size: ${input}`, ExitCode.USAGE);
  return Math.round(value * UNITS[unit]);
}

/**
 * FINDING 9: parse a numeric CLI flag, throwing a USAGE error (not silently
 * yielding NaN) on bad input. NaN flags previously busy-looped / hammered (a NaN
 * `--timeout` meant no deadline, a NaN `--interval` a zero-delay poll, a NaN
 * `--depth` an unbounded tree walk).
 *
 * `opts.min` (default 0 — i.e. allow 0) sets the inclusive lower bound;
 * `opts.positive` requires a strictly-positive value (> 0). `opts.integer`
 * additionally requires a whole number.
 */
export function parseNumberFlag(
  flag: string,
  value: string,
  opts: { min?: number; positive?: boolean; integer?: boolean } = {},
): number {
  const n = Number(value);
  if (!Number.isFinite(n)) throw new CliError(`invalid ${flag}: ${value} (expected a number)`, ExitCode.USAGE);
  if (opts.integer && !Number.isInteger(n)) throw new CliError(`invalid ${flag}: ${value} (expected a whole number)`, ExitCode.USAGE);
  if (opts.positive && !(n > 0)) throw new CliError(`invalid ${flag}: ${value} (expected a value > 0)`, ExitCode.USAGE);
  const min = opts.min ?? 0;
  if (n < min) throw new CliError(`invalid ${flag}: ${value} (expected >= ${min})`, ExitCode.USAGE);
  return n;
}

/** Convenience: a strictly-positive integer flag (depth/limit/interval/expiry). */
export function parsePositiveInt(flag: string, value: string): number {
  return parseNumberFlag(flag, value, { positive: true, integer: true });
}

/**
 * B27: validate a value against an allow-listed enum, returning it narrowed. A value
 * outside the set is a USAGE error with the allowed choices — fail fast and explicit
 * rather than letting an invalid enum coerce silently downstream (e.g. a bad grant level
 * collapsing to "read", or a bad share kind defaulting to "guest").
 */
export function requireEnum<const T extends readonly string[]>(
  flag: string,
  value: string,
  choices: T,
): T[number] {
  if ((choices as readonly string[]).includes(value)) return value as T[number];
  throw new CliError(`invalid ${flag} "${value}" — expected one of: ${choices.join(", ")}`, ExitCode.USAGE);
}

/** Format bytes as a human string for table output. */
export function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const v = bytes / 1024 ** i;
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}
