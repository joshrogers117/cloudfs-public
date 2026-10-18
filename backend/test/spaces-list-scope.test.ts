// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { seedOwnerFixture } from './setup-fixture';
import { mintToken, filespaceDoName, type Scope } from '../src/security/auth';

const e = env as Env;
const origin = 'https://gw.local';
const scopes: Scope[] = ['fs:read', 'fs:write', 'fs:lock'];
const hdr = (token: string) => ({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' });
const STORAGE_FIELDS = ['storageEndpoint', 'storageBucket', 'storageRegion', 'storageCredentialRef', 'storageForcePathStyle', 'bucketName', 'bucketProvider', 'keyPrefix'];

async function fixture() {
  const orgId = `lst-${crypto.randomUUID().slice(0, 8)}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  for (const spaceId of ['alpha', 'beta']) {
    const r = await SELF.fetch(`${origin}/v1/orgs/${orgId}/spaces`, {
      method: 'POST', headers: hdr(owner.token),
      body: JSON.stringify({ spaceId, name: spaceId, bucketProvider: 'r2', bucketName: 'bkt', keyPrefix: '', storageEndpoint: 'https://s3.example.test', storageBucket: 'bkt', storageRegion: 'auto', storageCredentialRef: 'ref1' }),
    });
    expect(r.status).toBe(201);
  }
  const member = await org.createUser({ orgId, email: `m@${orgId}.test`, displayName: 'M', role: 'standard' });
  const token = await mintToken(e.AUTH_SIGNING_SECRET, { sub: member.id, type: 'session', orgId, scopes, ttlSeconds: 900 });
  const fsOf = (id: string) => e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, id)));
  const list = async (t: string) => (await (await SELF.fetch(`${origin}/v1/orgs/${orgId}/spaces`, { headers: hdr(t) })).json()) as any[];
  return { orgId, org, owner, member, token, fsOf, list };
}

describe('GET /v1/orgs/:org/spaces is access-scoped', () => {
  it('standard member sees only granted spaces, with no storage fields; admin sees all with fields', async () => {
    const f = await fixture();
    expect(await f.list(f.token)).toEqual([]);
    await f.fsOf('alpha').grantAccess({ spaceId: 'alpha', inodeId: 'root', principalType: 'user', principalId: f.member.id, level: 'read' }, f.owner.userId);
    const mine = await f.list(f.token);
    expect(mine.map((s) => s.id)).toEqual(['alpha']);
    for (const k of STORAGE_FIELDS) expect(mine[0]).not.toHaveProperty(k);
    expect(mine[0].role).toBe('standard');
    const all = await f.list(f.owner.token);
    expect(all.map((s) => s.id).sort()).toEqual(['alpha', 'beta']);
    expect(all[0].storageEndpoint).toBe('https://s3.example.test');
    expect(all[0].role).toBe('owner');
  });

  it('group grants make a space visible; revoking removes it; admin grant reports folder_admin', async () => {
    const f = await fixture();
    const group = await f.org.createGroup({ orgId: f.orgId, name: 'Eds' });
    await f.org.addGroupMember(group.id, f.member.id);
    await f.fsOf('beta').grantAccess({ spaceId: 'beta', inodeId: 'root', principalType: 'group', principalId: group.id, level: 'edit' }, f.owner.userId);
    expect((await f.list(f.token)).map((s) => s.id)).toEqual(['beta']);
    await f.fsOf('beta').revokeAccess('root', 'group', group.id);
    expect(await f.list(f.token)).toEqual([]);
    await f.fsOf('alpha').grantAccess({ spaceId: 'alpha', inodeId: 'root', principalType: 'user', principalId: f.member.id, level: 'admin' }, f.owner.userId);
    expect((await f.list(f.token))[0].role).toBe('folder_admin');
    await f.fsOf('alpha').revokeAccess('root', 'user', f.member.id);
    expect(await f.list(f.token)).toEqual([]);
  });

  it('reports usedBytes as the sum of live file sizes', async () => {
    const f = await fixture();
    const fs = f.fsOf('alpha');
    const before = (await f.list(f.owner.token)).find((s) => s.id === 'alpha');
    const base = before.usedBytes as number;
    expect(typeof base).toBe('number');
    const r: any = await fs.createItem('root', 'a.bin', false, 1234);
    await fs.createItem('root', 'b.bin', false, 66);
    const after = (await f.list(f.owner.token)).find((s) => s.id === 'alpha');
    expect(after.usedBytes).toBe(base + 1300);
    expect(r.item).toBeTruthy();
    await fs.grantAccess({ spaceId: 'alpha', inodeId: 'root', principalType: 'user', principalId: f.member.id, level: 'read' }, f.owner.userId);
    expect((await f.list(f.token))[0].usedBytes).toBe(base + 1300);
  });

  it('seeds default daily/weekly snapshot schedules on create and lets an admin edit retention + enable', async () => {
    const f = await fixture();
    const url = `${origin}/v1/filespaces/alpha/schedules`;
    const got = (await (await SELF.fetch(url, { headers: hdr(f.owner.token) })).json()) as { schedules: any[] };
    const byId = Object.fromEntries(got.schedules.map((x) => [x.id, x]));
    expect(byId['default-daily']).toMatchObject({ tier: 'daily', intervalMs: 86_400_000, retain: 7, enabled: true, scope: 'root' });
    expect(byId['default-weekly']).toMatchObject({ tier: 'weekly', intervalMs: 604_800_000, retain: 4, enabled: true });
    const patch = (id: string, body: unknown) => SELF.fetch(`${url}/${id}`, { method: 'PATCH', headers: hdr(f.owner.token), body: JSON.stringify(body) });
    expect((await patch('default-daily', { retain: 14 })).status).toBe(200);
    expect((await patch('default-weekly', { enabled: false })).status).toBe(200);
    expect((await patch('default-daily', { retain: -1 })).status).toBe(400);
    expect((await patch('nope', { retain: 3 })).status).toBe(404);
    const after = (await (await SELF.fetch(url, { headers: hdr(f.owner.token) })).json()) as { schedules: any[] };
    const a = Object.fromEntries(after.schedules.map((x) => [x.id, x]));
    expect(a['default-daily']).toMatchObject({ retain: 14, enabled: true });
    expect(a['default-weekly']).toMatchObject({ retain: 4, enabled: false });
    // a standard member cannot read or edit schedules
    expect((await SELF.fetch(url, { headers: hdr(f.token) })).status).toBe(403);
  });
});

describe('spaces list: folder-scoped members and degradation flags', () => {
  it('a member scoped to a sub-folder gets no usedBytes; a root-read member does; no degradation headers normally', async () => {
    const f = await fixture();
    const fs = f.fsOf('alpha');
    const folder: any = (await fs.createItem('root', 'Sub', true, 0));
    await fs.grantAccess({ spaceId: 'alpha', inodeId: folder.item.id, principalType: 'user', principalId: f.member.id, level: 'read' }, f.owner.userId);
    const res = await SELF.fetch(`${origin}/v1/orgs/${f.orgId}/spaces`, { headers: hdr(f.token) });
    const list = (await res.json()) as any[];
    expect(list.map((s) => s.id)).toEqual(['alpha']);
    expect(list[0]).not.toHaveProperty('usedBytes');
    expect(res.headers.get('x-cloudfs-spaces-truncated')).toBeNull();
    expect(res.headers.get('x-cloudfs-spaces-partial')).toBeNull();
    await fs.grantAccess({ spaceId: 'alpha', inodeId: 'root', principalType: 'user', principalId: f.member.id, level: 'read' }, f.owner.userId);
    expect(typeof (await f.list(f.token))[0].usedBytes).toBe('number');
  });
});
