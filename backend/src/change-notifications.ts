// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Principal } from './permissions';

type Attachment = { version: 1; principal: Principal; expiresAt: number; sent: string | null; acknowledged: string | null };

/** Hints contain no names, object keys, counts or ACL details. The authorized
 * HTTP feed is the sole replay source. One unacknowledged hint bounds buffering;
 * attachments preserve that state across hibernation. Credentials are never
 * placed in attachments, URLs or messages. */
export class ChangeNotifications {
  constructor(private readonly ctx: DurableObjectState,
    private readonly stamp: () => string,
    private readonly canRead: (principal: Principal) => boolean) {}

  accept(principal: Principal, expiresAt: number): Response {
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now() || !this.canRead(principal)) {
      return Response.json({ error: 'forbidden' }, { status: 403 });
    }
    // Bound aggregate fanout and per-identity connections as well as each queue.
    const sockets = this.ctx.getWebSockets();
    if (sockets.length >= 512 || sockets.filter(ws => this.attachment(ws)?.principal.id === principal.id).length >= 8) {
      return Response.json({ error: 'subscription_limit' }, { status: 429 });
    }
    const pair = new WebSocketPair();
    const server = pair[1];
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ version: 1, principal,
      expiresAt: Math.min(expiresAt, Date.now() + 30_000), sent: null, acknowledged: null } satisfies Attachment);
    this.send(server);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }
  private attachment(ws: WebSocket): Attachment | null {
    const value: unknown = ws.deserializeAttachment();
    if (!value || typeof value !== 'object' || !('version' in value) || value.version !== 1) return null;
    return value as Attachment;
  }
  private send(ws: WebSocket): void {
    try {
      const state = this.attachment(ws);
      if (!state || state.expiresAt <= Date.now() || !this.canRead(state.principal)) {
        ws.close(1008, 'Refresh authorization'); return;
      }
      const current = this.stamp();
      if (state.sent !== state.acknowledged || current === state.acknowledged) return;
      state.sent = current;
      ws.serializeAttachment(state);
      ws.send('{"type":"invalidate"}');
    } catch { try { ws.close(1011, 'Reconnect for replay'); } catch {} }
  }
  broadcast(): void { for (const ws of this.ctx.getWebSockets()) this.send(ws); }
  message(ws: WebSocket, message: string | ArrayBuffer): void {
    if (message !== 'ack' && message !== 'check') { ws.close(1008, 'Unsupported message'); return; }
    const state = this.attachment(ws);
    if (!state) { ws.close(1008, 'Refresh authorization'); return; }
    if (message === 'ack') { state.acknowledged = state.sent; ws.serializeAttachment(state); }
    this.send(ws);
  }
  close(ws: WebSocket, code: number): void { try { ws.close(code); } catch {} }
}
