#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * `cloudfs` entrypoint. Thin: build the program, run argv, exit with the
 * returned (stable) code. All logic lives in app.ts and the command modules.
 */
import { buildProgram } from "./app.js";

const { run } = buildProgram();

/**
 * Exit with `code`, but only after stdout/stderr have flushed. The local-engine
 * transport (EngineClient) keeps a live Unix-domain socket open, which holds the
 * Node event loop alive after a one-shot command — so without an explicit exit
 * the process would hang. We force the exit, but drain the output streams first
 * so piped/redirected output is never truncated.
 */
function exitAfterFlush(code: number): void {
  process.exitCode = code;
  let pending = 0;
  const done = (): void => {
    if (pending === 0) process.exit(code);
  };
  for (const stream of [process.stdout, process.stderr]) {
    // `write("")` callback fires once the stream's buffer is flushed.
    pending++;
    stream.write("", () => {
      pending--;
      done();
    });
  }
  done();
  // Safety net: never hang indefinitely if a stream never drains.
  setTimeout(() => process.exit(code), 2000).unref();
}

run(process.argv.slice(2))
  .then((code) => {
    exitAfterFlush(code);
  })
  .catch((e) => {
    // Last-resort guard; the runner normally handles all errors itself.
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
    exitAfterFlush(1);
  });
