// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import type { FilespaceDO } from '../src/filespace-do';
function itemOf(result: Awaited<ReturnType<FilespaceDO['createItem']>>) {
  if (!('item' in result)) throw new Error('fixture item creation failed');
  return result.item;
}
import { seedOwnerFixture } from './setup-fixture';
import { mintToken, filespaceDoName, type Scope } from '../src/security/auth';
import { authStoresFor } from '../src/auth-stores';
import { createBrowserSession } from '../src/security/auth-session';
const e = env as Env;
const origin = 'https://gw.local';
const scopes: Scope[] = ['fs:read', 'fs:write', 'fs:lock'];
const headers = (token: string) => ({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' });

async function fixture() {
  const orgId = `folder-${crypto.randomUUID().slice(0,8)}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const spaceId = 'shared';
  const create = await SELF.fetch(`${origin}/v1/orgs/${orgId}/spaces`, { method:'POST', headers:headers(owner.token), body:JSON.stringify({spaceId,name:'Team',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''}) });
  expect(create.status).toBe(201);
  const member = await org.createUser({orgId,email:`member@${orgId}.test`,displayName:'Member',role:'standard'});
  const token = await mintToken(e.AUTH_SIGNING_SECRET, {sub:member.id,type:'session',orgId,scopes,ttlSeconds:900});
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId,spaceId)));
  const parent = itemOf(await fs.createItem('root','Private parent',true,0));
  const folder = itemOf(await fs.createItem(parent.id,'Shared folder',true,0));
  const file = itemOf(await fs.createItem(folder.id,'clip.mov',false,0));
  const privateFile = itemOf(await fs.createItem(parent.id,'Secret.mov',false,0));
  const base = `${origin}/v1/filespaces/${spaceId}`;
  const grant = async (inodeId: string, extra = {}) => fs.grantAccess({spaceId,inodeId,principalType:'user',principalId:member.id,level:'read',...extra},owner.userId);
  return {orgId,org,owner,member,token,fs,parent,folder,file,privateFile,base,grant};
}

describe('folder-only collaboration', () => {
  it('a newly paired device retrieves the key and its explicit subtree without ancestor access', async () => {
    const f = await fixture();
    await f.grant(f.folder.id,{mountAsRoot:true});
    const stores = authStoresFor(e,f.orgId);
    const account = await stores.accounts.createAccount({orgId:f.orgId,userId:f.member.id,email:f.member.email,displayName:'Member',role:'standard',emailVerified:true});
    const session = await createBrowserSession(stores.sessions,{accountId:account.id,userId:f.member.id,orgId:f.orgId,scopes});
    const verifier = 'V'.repeat(43);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier)));
    const challenge = btoa(String.fromCharCode(...digest)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    const approved = await SELF.fetch(`${origin}/v1/auth/device/approve`,{method:'POST',headers:{'content-type':'application/json',cookie:`cfs_session=${f.orgId}.${session.id}`,'X-CFS-CSRF':session.csrfToken},body:JSON.stringify({state:'S'.repeat(43),codeChallenge:challenge,codeChallengeMethod:'S256',deviceName:'New teammate Mac'})});
    expect(approved.status).toBe(201);
    const {code} = await approved.json() as {code:string};
    const exchanged = await SELF.fetch(`${origin}/v1/auth/device/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code,codeVerifier:verifier})});
    expect(exchanged.status).toBe(200);
    const {accessToken} = await exchanged.json() as {accessToken:string};
    const minted = await SELF.fetch(`${origin}/v1/auth/device/daemon-token`,{method:'POST',headers:headers(accessToken),body:'{}'});
    expect(minted.status).toBe(201);
    const {token} = await minted.json() as {token:string};
    const auth = headers(token);
    expect((await SELF.fetch(`${f.base}/key`,{headers:auth})).status).toBe(200);
    expect(await (await SELF.fetch(`${f.base}/mount-roots`,{headers:auth})).json()).toEqual({roots:[{id:f.folder.id,name:'Shared folder',mountAsRoot:true}]});
    expect((await SELF.fetch(`${f.base}/items/${f.parent.id}`,{headers:auth})).status).toBe(404);
    expect((await SELF.fetch(`${f.base}/items/${f.privateFile.id}`,{headers:auth})).status).toBe(404);
    const presign = await SELF.fetch(`${f.base}/presign`,{method:'POST',headers:auth,body:JSON.stringify({key:`blocks/${f.orgId}::shared/private-object`,method:'GET',inodeId:f.privateFile.id})});
    expect(presign.status).toBe(403);
    expect((await SELF.fetch(`${f.base}/items/${f.file.id}`,{headers:auth})).status).toBe(200);
  });

  it('rejects absent, expired and deleted-inode grants for key retrieval', async () => {
    for (const kind of ['none','expired','deleted']) {
      const f = await fixture();
      if (kind === 'expired') await f.grant(f.folder.id,{expiresAt:Date.now()-1000});
      if (kind === 'deleted') {
        await f.grant(f.folder.id);
        // This fixture contains a child; deleting the granted subtree must be explicit.
        const deleted = await SELF.fetch(`${f.base}/items/${f.folder.id}?recursive=true`,{method:'DELETE',headers:headers(f.owner.token)});
        expect(deleted.status).toBe(200);
      }
      expect((await SELF.fetch(`${f.base}/key`,{headers:headers(f.token)})).status).toBe(403);
      expect(await (await SELF.fetch(`${f.base}/mount-roots`,{headers:headers(f.token)})).json()).toEqual({roots:[]});
    }
  });

  it('returns separate roots for disjoint folders and honors group grants', async () => {
    const f = await fixture();
    await f.grant(f.folder.id);
    const another = itemOf(await f.fs.createItem('root','Another share',true,0));
    const group = await f.org.createGroup({orgId:f.orgId,name:'Editors'});
    await f.org.addGroupMember(group.id,f.member.id);
    await f.fs.grantAccess({spaceId:'shared',inodeId:another.id,principalType:'group',principalId:group.id,level:'read'},f.owner.userId);
    const roots = await (await SELF.fetch(`${f.base}/mount-roots`,{headers:headers(f.token)})).json() as {roots:{id:string}[]};
    expect(roots.roots.map(root=>root.id).sort()).toEqual([f.folder.id,another.id].sort());
    expect((await SELF.fetch(`${f.base}/key`,{headers:headers(f.token)})).status).toBe(200);
  });

  it('writable-open preflight requires both an edit ACL and explicit write scope', async () => {
    const f = await fixture();
    const endpoint = `${f.base}/items/${f.file.id}/access`;
    expect((await SELF.fetch(endpoint,{headers:headers(f.token)})).status).toBe(404);
    await f.grant(f.folder.id);
    const read = await SELF.fetch(endpoint,{headers:headers(f.token)});
    expect(read.headers.get('cache-control')).toBe('no-store');
    expect(await read.json()).toEqual({read:true,write:false});
    await f.grant(f.folder.id,{level:'edit'});
    expect(await (await SELF.fetch(endpoint,{headers:headers(f.token)})).json()).toEqual({read:true,write:true});
    const limited = await mintToken(e.AUTH_SIGNING_SECRET,{sub:f.member.id,type:'session',orgId:f.orgId,scopes:['fs:read'],ttlSeconds:900});
    expect(await (await SELF.fetch(endpoint,{headers:headers(limited)})).json()).toEqual({read:true,write:false});
    expect((await SELF.fetch(`${f.base}/items/${f.privateFile.id}/access`,{headers:headers(f.token)})).status).toBe(404);
    await f.fs.revokeAccess(f.folder.id,'user',f.member.id);
    expect((await SELF.fetch(endpoint,{headers:headers(f.token)})).status).toBe(404);
  });

  it('read-only root grants cannot change or delete resource forks even with fs:write token scope', async () => {
    const f = await fixture();
    await f.grant('root');
    const path = `${f.base}/items/${f.file.id}/streams/AFP_Resource`;
    const original = new Uint8Array([1,2,3,4]);
    expect((await SELF.fetch(path,{method:'PUT',headers:headers(f.owner.token),body:original})).status).toBe(200);
    expect((await SELF.fetch(path,{method:'PUT',headers:headers(f.token),body:new Uint8Array([9])})).status).toBe(403);
    expect((await SELF.fetch(path,{method:'DELETE',headers:headers(f.token)})).status).toBe(403);
    const after = await SELF.fetch(path,{headers:headers(f.token)});
    expect(Array.from(new Uint8Array(await after.arrayBuffer()))).toEqual(Array.from(original));
    await f.grant(f.folder.id,{level:'edit'});
    expect((await SELF.fetch(path,{method:'PUT',headers:headers(f.token),body:new Uint8Array([8])})).status).toBe(200);
  });

  it('new block uploads require an editable item for folder-scoped users, including batch requests', async () => {
    const f = await fixture();
    await f.grant(f.folder.id);
    const key = `blocks/${f.orgId}::shared/new-ciphertext`;
    const post = (suffix: string, body: unknown) => SELF.fetch(`${f.base}/presign${suffix}`, { method: 'POST', headers: headers(f.token), body: JSON.stringify(body) });
    expect((await post('', { key, method: 'PUT' })).status).toBe(403);
    expect((await post('', { key, method: 'PUT', itemId: f.file.id })).status).toBe(403);
    const denied = await (await post('/batch', { keys: [{ key, method: 'PUT' }, { key, method: 'PUT', itemId: f.file.id }] })).json() as { urls: { error?: string }[] };
    expect(denied.urls.map(row => row.error)).toEqual(['item_required', 'forbidden']);
    await f.grant(f.folder.id, { level: 'edit' });
    expect((await post('', { key, method: 'PUT', itemId: f.file.id })).status).toBe(200);
    const allowed = await (await post('/batch', { keys: [{ key, method: 'PUT', itemId: f.file.id }] })).json() as { urls: { url?: string }[] };
    expect(allowed.urls[0].url).toBeTruthy();
  });
});
