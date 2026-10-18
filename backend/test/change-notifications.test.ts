// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, SELF, runInDurableObject, abortAllDurableObjects } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import type { Env } from '../src/env';
const bindings = env as Env;
import { mintToken } from '../src/security/auth';

async function fixture() {
  const orgId = `notify-${crypto.randomUUID()}`, space = 'space';
  const org = bindings.ORG_DO.getByName(orgId);
  const user = await org.createUser({ orgId, email: `${orgId}@example.test`, displayName: 'Notify', role: 'admin' });
  const token = await mintToken(bindings.AUTH_SIGNING_SECRET, { sub: user.id, orgId, type: 'session', scopes: ['fs:read','fs:write'], ttlSeconds: 300 });
  const headers = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  return { stub: bindings.FILESPACE.getByName(`${orgId}::${space}`), headers,
    url: `https://gw.local/v1/filespaces/${space}`, user };
}
function nextMessage(ws: WebSocket): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { ws.removeEventListener('message', received); reject(new Error('hint timeout')); }, 2000);
    function received(event: MessageEvent) { clearTimeout(timer); ws.removeEventListener('message', received); resolve(String(event.data)); }
    ws.addEventListener('message', received);
  });
}
describe('durable change subscriptions', () => {
  it('requires authentication and an upgrade', async () => {
    const f = await fixture();
    expect((await SELF.fetch(f.url + '/changes/subscribe', { headers: { Upgrade: 'websocket' } })).status).toBe(401);
    expect((await SELF.fetch(f.url + '/changes/subscribe', { headers: f.headers })).status).toBe(426);
  });
  it('replays committed changes and coalesces hints until acknowledgement', async () => {
    const f = await fixture();
    const response = await SELF.fetch(f.url + '/changes/subscribe', { headers: { ...f.headers, Upgrade: 'websocket' } });
    expect(response.status).toBe(101);
    const ws = response.webSocket!;
    const first = nextMessage(ws); ws.accept();
    expect(JSON.parse(await first)).toEqual({ type: 'invalidate' });
    const before = await (await SELF.fetch(f.url + '/changes', { headers: f.headers })).json<{anchor:number}>();
    const created = await SELF.fetch(f.url + '/items', { method: 'POST', headers: f.headers,
      body: JSON.stringify({ parent: 'root', name: 'new', isDir: false, size: 0 }) });
    expect(created.status).toBe(201);
    const next = nextMessage(ws); ws.send('ack');
    expect(JSON.parse(await next)).toEqual({ type: 'invalidate' });
    const replay = await (await SELF.fetch(f.url + `/changes?since=${before.anchor}`, { headers: f.headers })).json<{items: {name:string}[]}>();
    expect(replay.items.map(item => item.name)).toContain('new');
    await runInDurableObject(f.stub, async (_instance, state) => {
      const attachment = state.getWebSockets()[0].deserializeAttachment();
      expect(attachment.version).toBe(1);
      expect(attachment.sent).not.toBe(attachment.acknowledged);
      expect(JSON.stringify(attachment)).not.toContain(f.headers.Authorization);
    });
    ws.close();
  });
  it('changes visibility when an unchanged subtree becomes readable or grants expire', async () => {
    const f = await fixture();
    const principal = { type: 'user' as const, id: 'reader', groupIds: [] };
    const before = await f.stub.changesSinceFor(principal, 0);
    await f.stub.grantAccess({ spaceId: 'space', inodeId: 'root', principalType: 'user', principalId: 'reader', level: 'read' }, f.user.id);
    const after = await f.stub.changesSinceFor(principal, before.anchor);
    expect(after.anchor).toBe(before.anchor);
    expect(after.items).toHaveLength(0);
    expect(after.visibility).not.toBe(before.visibility);
    expect((await f.stub.listPageFor(principal, 'root')).items.length).toBeGreaterThan(0);
    await f.stub.revokeAccess('root', 'user', 'reader');
    const revoked = await f.stub.changesSinceFor(principal, after.anchor);
    expect(revoked.visibility).not.toBe(after.visibility);
    expect(revoked.items).toHaveLength(0);
  });
  it('closes an expired attachment and replays after an authority restart', async () => {
    const f = await fixture();
    const response = await SELF.fetch(f.url + '/changes/subscribe', { headers: { ...f.headers, Upgrade: 'websocket' } });
    const ws = response.webSocket!;
    const first = nextMessage(ws); ws.accept(); await first;
    const before = await f.stub.changesSince(0);
    await runInDurableObject(f.stub, async (_instance, state) => {
      const server = state.getWebSockets()[0];
      const attachment = server.deserializeAttachment();
      attachment.expiresAt = Date.now() - 1;
      server.serializeAttachment(attachment);
    });
    const closed = new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('expiry did not close socket')), 2000);
      ws.addEventListener('close', event => { clearTimeout(timer); resolve(event.code); }, { once: true });
    });
    ws.send('check'); expect(await closed).toBe(1008);
    const created = await SELF.fetch(f.url + '/items', { method: 'POST', headers: f.headers,
      body: JSON.stringify({ parent: 'root', name: 'after-disconnect', size: 0 }) });
    expect(created.status).toBe(201);
    await abortAllDurableObjects();
    const replay = await bindings.FILESPACE.get(f.stub.id).changesSinceFor({ type: 'user', id: f.user.id, orgRole: 'admin' }, before.anchor);
    expect(replay.items.map(item => item.name)).toContain('after-disconnect');
    expect(replay.visibility).toBeTruthy();
  });

});
