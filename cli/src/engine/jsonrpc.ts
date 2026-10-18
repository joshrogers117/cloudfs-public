// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Newline-delimited JSON-RPC 2.0 over a Unix-domain socket — the wire transport
 * for talking to `cloudfsd` (CONTROL-API.md §1). One JSON object per line,
 * UTF-8, `\n`-terminated. Filesystem permissions on the 0600 socket ARE the auth
 * for the local channel; there is no bearer token on this channel.
 *
 * This module is transport-only: it frames requests, correlates responses by
 * `id`, surfaces server→client notifications (the event stream), and turns a
 * socket-connect failure into the CLI's ENGINE_UNAVAILABLE (exit 42) — a
 * *transport* condition, never a JSON-RPC error on the wire (CONTROL-API.md §1).
 */
import { connect, type Socket } from "node:net";
import { CliError, ExitCode } from "../exit-codes.js";
import { mapEngineError, type RpcErrorObject } from "./errors.js";

export interface RpcNotification {
  method: string;
  params: unknown;
}

/** Injection seam so tests can supply a fake `net.connect`. */
export type Connector = (path: string) => Socket;

export interface RpcConnectionOptions {
  socketPath: string;
  /** Per-request timeout in ms (0 disables). Default 30s. */
  requestTimeoutMs?: number;
  /** Test seam; defaults to node:net connect. */
  connector?: Connector;
}

/**
 * A single connection to the daemon. Owns one socket, decodes the line stream,
 * matches responses to pending requests, and routes notifications to a queue
 * that `notifications()` drains as an async iterable.
 */
export class RpcConnection {
  private readonly socketPath: string;
  private readonly requestTimeoutMs: number;
  private readonly connector: Connector;

  private socket: Socket | null = null;
  private connected: Promise<void> | null = null;
  private nextId = 1;
  private buf = "";
  private closed = false;
  private fatal: Error | null = null;

  private readonly pending = new Map<
    number | string,
    { resolve: (v: unknown) => void; reject: (e: unknown) => void; timer?: NodeJS.Timeout }
  >();

  // Notification fan-out: a simple push queue with backpressure-free buffering.
  private notifyQueue: RpcNotification[] = [];
  private notifyWaiters: ((n: IteratorResult<RpcNotification>) => void)[] = [];

  constructor(opts: RpcConnectionOptions) {
    this.socketPath = opts.socketPath;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 30_000;
    this.connector = opts.connector ?? ((p) => connect(p));
  }

  /** Lazily connect. A connect failure becomes ENGINE_UNAVAILABLE (exit 42). */
  private ensureConnected(): Promise<void> {
    if (this.connected) return this.connected;
    this.connected = new Promise<void>((resolve, reject) => {
      let settled = false;
      let sock: Socket;
      try {
        sock = this.connector(this.socketPath);
      } catch (e) {
        reject(this.unavailable(e));
        return;
      }
      this.socket = sock;
      sock.setEncoding("utf8");

      sock.on("connect", () => {
        settled = true;
        resolve();
      });
      sock.on("ready", () => {
        if (!settled) {
          settled = true;
          resolve();
        }
      });
      sock.on("data", (chunk: string) => this.onData(chunk));
      sock.on("error", (e: Error) => {
        if (!settled) {
          settled = true;
          reject(this.unavailable(e));
        } else {
          this.failAll(e);
        }
      });
      sock.on("close", () => {
        if (!this.closed) this.failAll(this.fatal ?? new Error("engine connection closed"));
      });
    });
    return this.connected;
  }

  private unavailable(e: unknown): CliError {
    const msg = e instanceof Error ? e.message : String(e);
    return new CliError(`cannot reach cloudfsd at ${this.socketPath}: ${msg}`, ExitCode.ENGINE_UNAVAILABLE, {
      socket: this.socketPath,
    });
  }

  private onData(chunk: string): void {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;
      this.dispatchLine(line);
    }
  }

  private dispatchLine(line: string): void {
    let msg: {
      id?: number | string;
      result?: unknown;
      error?: RpcErrorObject;
      method?: string;
      params?: unknown;
    };
    try {
      msg = JSON.parse(line);
    } catch {
      return; // ignore unparseable lines defensively
    }

    // Notification (no id, has method) → event stream.
    if (msg.id === undefined && typeof msg.method === "string") {
      this.pushNotification({ method: msg.method, params: msg.params });
      return;
    }

    if (msg.id === undefined) return;
    const waiter = this.pending.get(msg.id);
    if (!waiter) return;
    this.pending.delete(msg.id);
    if (waiter.timer) clearTimeout(waiter.timer);
    if (msg.error) {
      waiter.reject(mapEngineError(msg.error));
    } else {
      waiter.resolve(msg.result);
    }
  }

  private pushNotification(n: RpcNotification): void {
    const waiter = this.notifyWaiters.shift();
    if (waiter) waiter({ value: n, done: false });
    else this.notifyQueue.push(n);
  }

  private failAll(e: Error): void {
    this.fatal = e;
    for (const [, p] of this.pending) {
      if (p.timer) clearTimeout(p.timer);
      p.reject(e);
    }
    this.pending.clear();
    // End the notification iterable.
    const waiters = this.notifyWaiters.splice(0);
    for (const w of waiters) w({ value: undefined, done: true });
  }

  /** Issue a JSON-RPC request and await its result (or a mapped CliError). */
  async call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    await this.ensureConnected();
    if (this.fatal) throw this.fatal;
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";

    return new Promise<T>((resolve, reject) => {
      const entry: { resolve: (v: unknown) => void; reject: (e: unknown) => void; timer?: NodeJS.Timeout } = {
        resolve: (v) => resolve(v as T),
        reject,
      };
      if (this.requestTimeoutMs > 0) {
        entry.timer = setTimeout(() => {
          this.pending.delete(id);
          reject(new CliError(`engine request timed out: ${method}`, ExitCode.ENGINE_UNAVAILABLE, { method }));
        }, this.requestTimeoutMs);
      }
      this.pending.set(id, entry);
      this.socket!.write(payload, (err) => {
        if (err) {
          this.pending.delete(id);
          if (entry.timer) clearTimeout(entry.timer);
          reject(this.unavailable(err));
        }
      });
    });
  }

  /**
   * Drain server→client notifications as an async iterable. Ends when the
   * connection closes (or `signal` aborts). Subscribe via `events.subscribe`
   * first, then iterate this.
   */
  async *notifications(signal?: AbortSignal): AsyncIterable<RpcNotification> {
    if (signal) {
      if (signal.aborted) return;
      signal.addEventListener("abort", () => this.close(), { once: true });
    }
    for (;;) {
      if (this.notifyQueue.length > 0) {
        yield this.notifyQueue.shift()!;
        continue;
      }
      if (this.closed || this.fatal) return;
      const next = await new Promise<IteratorResult<RpcNotification>>((res) => {
        this.notifyWaiters.push(res);
      });
      if (next.done) return;
      yield next.value;
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.socket?.end();
      this.socket?.destroy();
    } catch {
      /* ignore */
    }
    const waiters = this.notifyWaiters.splice(0);
    for (const w of waiters) w({ value: undefined, done: true });
  }
}
