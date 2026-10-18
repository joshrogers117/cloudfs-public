// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A fake cloudfsd: a real Unix-domain-socket server speaking newline-delimited
 * JSON-RPC 2.0 (CONTROL-API.md §1). Using a REAL `node:net` UDS server exercises
 * the EngineClient's actual connector + line framing end-to-end (no transport
 * stubbing). Handlers are keyed by method; a handler returns a result, throws an
 * `RpcError` to emit an error object, or pushes notifications via the context.
 */
import { createServer, type Server, type Socket } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface RpcError {
  code: number;
  message: string;
  data?: Record<string, unknown>;
}

export interface HandlerContext {
  /** Push a server→client notification (event-stream) to this connection. */
  notify(method: string, params: unknown): void;
  /** The raw incoming request params. */
  params: any;
}

export type MethodHandler = (ctx: HandlerContext) => unknown;

export interface RecordedCall {
  method: string;
  params: any;
  id: number | string;
}

export interface FakeDaemon {
  socketPath: string;
  calls: RecordedCall[];
  close(): Promise<void>;
}

export function rpcError(code: number, message: string, data?: Record<string, unknown>): RpcError {
  const e = new Error(message) as Error & RpcError;
  e.code = code;
  e.message = message;
  e.data = data;
  return e;
}

/** Start a fake daemon listening on a fresh temp UDS path. */
export async function startFakeDaemon(handlers: Record<string, MethodHandler>): Promise<FakeDaemon> {
  const dir = mkdtempSync(join(tmpdir(), "cfsd-"));
  const socketPath = join(dir, "cloudfsd.sock");
  const calls: RecordedCall[] = [];
  const open = new Set<Socket>();

  const server: Server = createServer((socket: Socket) => {
    socket.setEncoding("utf8");
    open.add(socket);
    socket.on("close", () => open.delete(socket));
    let buf = "";

    const write = (obj: unknown) => socket.write(JSON.stringify(obj) + "\n");

    socket.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let req: { id: number | string; method: string; params?: any };
        try {
          req = JSON.parse(line);
        } catch {
          continue;
        }
        calls.push({ method: req.method, params: req.params, id: req.id });
        const handler = handlers[req.method];
        if (!handler) {
          write({ jsonrpc: "2.0", id: req.id, error: { code: -32601, message: "method not found" } });
          continue;
        }
        const ctx: HandlerContext = {
          notify: (method, params) => write({ jsonrpc: "2.0", method, params }),
          params: req.params ?? {},
        };
        try {
          const result = handler(ctx);
          if (result !== undefined) write({ jsonrpc: "2.0", id: req.id, result });
          else write({ jsonrpc: "2.0", id: req.id, result: {} });
        } catch (e) {
          const err = e as RpcError;
          write({ jsonrpc: "2.0", id: req.id, error: { code: err.code, message: err.message, data: err.data } });
        }
      }
    });
    socket.on("error", () => {
      /* client closed; ignore */
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });

  return {
    socketPath,
    calls,
    close: () =>
      new Promise<void>((resolve) => {
        // Destroy any lingering client connections so server.close() resolves
        // even if an EngineClient left its socket open (error-path tests).
        for (const s of open) s.destroy();
        open.clear();
        server.close(() => resolve());
      }),
  };
}
