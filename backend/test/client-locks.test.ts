// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { filespaceDoName, mintToken } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';

async function fixture() {
  const orgId = `locks-${crypto.randomUUID()}`;
  const owner = await seedOwnerFixture(orgId);
  const e = env as Env;
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, 'team')));
  const created = await fs.createItem('root', 'project.mov', false, 0);
  if (!('item' in created)) throw new Error('fixture creation failed');
  const item = created.item;
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const member = await org.createUser({orgId,email:`member@${orgId}.test`,displayName:'Member',role:'standard'});
  await fs.grantAccess({spaceId:'team',inodeId:'root',principalType:'user',principalId:member.id,level:'edit'},owner.userId);
  const memberToken = await mintToken(e.AUTH_SIGNING_SECRET,{sub:member.id,type:'session',orgId,scopes:['fs:read','fs:write','fs:lock'],ttlSeconds:900});
  const a = crypto.randomUUID();
  const b = crypto.randomUUID();
  const request = (client: string | undefined, method: string, path: string, body?: unknown, token = owner.token) => SELF.fetch(`https://gw.local/v1/filespaces/team${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(client === undefined ? {} : { 'X-CloudFS-Client-ID': client }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const acquire = async (client: string) => (await request(client, 'POST', '/locks', { path: item.id, ttlMs: 60_000 })).json() as Promise<{ granted: boolean; fence: number; heldBy?: string }>;
  return { item, a, b, request, acquire, fs, owner, member, memberToken, orgId };
}

describe('independent Mac lease ownership', () => {
  it('isolates two clients of one account and gates every destructive inode mutation', async () => {
    const f = await fixture();
    const lease = await f.acquire(f.a);
    expect(lease.granted).toBe(true);
    expect((await f.acquire(f.b)).granted).toBe(false);
    const status = await (await f.request(f.b, 'GET', `/locks?path=${f.item.id}`)).json() as Record<string, unknown>;
    expect(status.fence).toBeUndefined();
    for (const client of [f.b, undefined]) {
      expect((await f.request(client, 'PUT', `/blocks?item=${f.item.id}`, { blocks: [], expectedVersion: f.item.version, fence: lease.fence })).status).toBe(409);
      expect((await f.request(client, 'DELETE', `/items/${f.item.id}`)).status).toBe(409);
      expect((await f.request(client, 'PATCH', `/items/${f.item.id}`, { name: 'clobbered.mov' })).status).toBe(409);
      expect((await f.request(client, 'PUT', `/items/${f.item.id}/streams/AFP_Resource`, 'clobber')).status).toBe(409);
      expect((await f.request(client, 'DELETE', `/items/${f.item.id}/streams/AFP_Resource`)).status).toBe(409);
    }
    expect((await f.request(f.a.toUpperCase(), 'PUT', `/blocks?item=${f.item.id}`, { blocks: [], expectedVersion: f.item.version, fence: lease.fence })).status).toBe(200);
  });

  it('a delayed close cannot release a newer lease of the same client', async () => {
    const f = await fixture();
    const first = await f.acquire(f.a);
    const release = (fence: number) => f.request(f.a, 'DELETE', `/locks?path=${f.item.id}&fence=${fence}`);
    expect(await (await release(first.fence)).json()).toEqual({ released: true });
    const second = await f.acquire(f.a);
    expect(second.fence).toBeGreaterThan(first.fence);
    expect(await (await release(first.fence)).json()).toEqual({ released: false, reason: 'fence-stale' });
    expect((await f.acquire(f.b)).granted).toBe(false);
    expect((await f.request(f.a, 'PUT', `/blocks?item=${f.item.id}`, { blocks: [], fence: first.fence })).status).toBe(409);
    expect(await (await release(second.fence)).json()).toEqual({ released: true });
    expect((await f.acquire(f.b)).granted).toBe(true);
  });

  it('keeps API leases advisory by default and rejects a purpose change on reacquire or renew', async () => {
    const f = await fixture();
    const lease = await f.acquire(f.a);
    expect(lease.granted).toBe(true);
    const promote = await f.request(f.a, 'POST', '/locks', { path: f.item.id, ttlMs: 60_000, purpose: 'publication' });
    expect(promote.status).toBe(200);
    expect(await promote.json()).toMatchObject({ granted: false, reason: 'purpose-mismatch' });
    const status = await (await f.request(f.a, 'GET', `/locks?path=${f.item.id}`)).json() as Record<string, unknown>;
    expect(status.purpose).toBe('advisory');
    expect((await f.request(f.a, 'POST', '/locks', { path: f.item.id, renew: true, fence: lease.fence, purpose: 'publication' })).status).toBe(400);
  });

  it('optionally returns the current enriched item with a publication fence without requiring an open handle', async () => {
    const f = await fixture();
    const item = await f.fs.getItem(f.item.id);
    if (!item) throw new Error('fixture item disappeared');
    expect(await f.fs.putStreamFor({type:'user',id:f.owner.userId,orgRole:'owner'},item.id,'AFP_Resource',new Uint8Array([1,2,3]),3,f.owner.userId)).toEqual({size:3});

    // Recovery can acquire a publication lease outside SMB, so no client identity
    // or open-handles row is required for this opt-in lock response.
    const response = await f.request(undefined,'POST','/locks',{path:item.id,purpose:'publication',includeItem:true});
    expect(response.status).toBe(200);
    const lease = await response.json() as Record<string,any>;
    expect(lease).toMatchObject({granted:true,mode:'exclusive',purpose:'publication',path:item.id});
    expect(lease.fence).toEqual(expect.any(Number));
    expect(lease.item).toMatchObject({id:item.id,name:item.name,contentVersion:item.contentVersion,version:item.version,rsrcForkSize:3});
    expect(lease.item).not.toHaveProperty('metadataVersion');
    expect(await runInDurableObject(f.fs,(_instance,state) => Number(state.storage.sql.exec('SELECT COUNT(*) AS n FROM open_handles WHERE inode_id=?',item.id).one().n))).toBe(0);
  });

  it('does not add item metadata to legacy responses or denied/conflicting publication acquisitions', async () => {
    const f = await fixture();
    const legacy = await f.request(f.a,'POST','/locks',{path:f.item.id,purpose:'publication'});
    expect(legacy.status).toBe(200);
    expect(await legacy.json()).not.toHaveProperty('item');
    const conflict = await f.request(f.b,'POST','/locks',{path:f.item.id,purpose:'publication',includeItem:true});
    expect(conflict.status).toBe(200);
    const conflictBody = await conflict.json() as Record<string,unknown>;
    expect(conflictBody).toMatchObject({granted:false,reason:'held-by-other'});
    expect(conflictBody).not.toHaveProperty('item');
    for (const body of [
      {path:f.item.id,includeItem:true},
      {path:f.item.id,purpose:'advisory',includeItem:true},
      {path:f.item.id,purpose:'publication',mode:'shared',includeItem:true},
      {path:f.item.id,purpose:'publication',renew:true,fence:1,includeItem:true},
      {path:f.item.id,purpose:'publication',includeItem:'yes'},
    ]) expect((await f.request(f.b,'POST','/locks',body)).status).toBe(400);
  });

  it('requires all read/write/lock scopes for the item fast path and returns read-only attributes unchanged', async () => {
    const f = await fixture();
    const readLockToken = await mintToken((env as Env).AUTH_SIGNING_SECRET,{sub:f.owner.userId,type:'session',orgId:f.orgId,scopes:['fs:read','fs:lock'],ttlSeconds:900});
    const changed = await f.fs.setBasicInfoFor({type:'user',id:f.owner.userId,orgRole:'owner'},f.item.id,
      {fileAttributes:1,expectedVersion:f.item.version},f.owner.userId);
    if (!('item' in changed)) throw new Error('failed to set DOS read-only attribute');
    const denied = await f.request(f.a,'POST','/locks',{path:f.item.id,purpose:'publication',includeItem:true},readLockToken);
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({error:'forbidden_scope'});
    const lockStatus = await (await f.request(f.a,'GET',`/locks?path=${f.item.id}`)).json() as Record<string,unknown>;
    expect(lockStatus.granted).toBe(false);
    const response = await f.request(f.a,'POST','/locks',{path:f.item.id,purpose:'publication',includeItem:true});
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({granted:true,purpose:'publication',item:{id:f.item.id,fileAttributes:1}});
  });

  it('rechecks current read/write ACL inside the item-returning DO operation and withholds metadata on revocation', async () => {
    const f = await fixture();
    await f.fs.revokeAccess('root','user',f.member.id);
    const result = await f.fs.acquirePublicationLockWithItemFor(
      {type:'user',id:f.member.id,orgRole:'standard'},f.item.id,`${f.member.id}::client:${f.a.toLowerCase()}`,60_000);
    expect(result).toMatchObject({granted:false,reason:'forbidden'});
    expect(result).not.toHaveProperty('item');
    const http = await f.request(f.a,'POST','/locks',{path:f.item.id,purpose:'publication',includeItem:true},f.memberToken);
    expect(http.status).toBe(403);
    expect(await http.json()).not.toHaveProperty('item');
  });

  it('rejects malformed client identities and lease parameters before storage', async () => {
    const f = await fixture();
    expect((await f.request('not-a-uuid', 'GET', `/items/${f.item.id}`)).status).toBe(400);
    for (const extra of [{ ttlMs: -1 }, { ttlMs: '60000' }, { mode: 'invalid' }, { renew: true }, { fence: -1 }]) {
      expect((await f.request(f.a, 'POST', '/locks', { path: f.item.id, ...extra })).status).toBe(400);
    }
    expect((await f.request(f.a, 'DELETE', `/locks?path=${f.item.id}&fence=NaN`)).status).toBe(400);
    expect((await f.acquire(f.a)).granted).toBe(true);
  });
});
