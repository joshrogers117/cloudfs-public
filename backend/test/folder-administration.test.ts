// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import type { FilespaceDO } from '../src/filespace-do';
import { migrate, SCHEMA_VERSION } from '../src/metadata/schema';
import { restorePreV30LocksTable } from './metadata-schema-fixtures';
import { seedOwnerFixture } from './setup-fixture';
import { mintToken, filespaceDoName, type Scope } from '../src/security/auth';
const e = env as Env;
const origin = 'https://gw.local';
const scopes: Scope[] = ['fs:read', 'fs:write', 'fs:lock', 'snapshot:read'];
const headers = (token: string) => ({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' });
const itemOf = (r: Awaited<ReturnType<FilespaceDO['createItem']>>) => { if (!('item' in r)) throw Error('fixture'); return r.item; };
async function fixture() {
  const orgId = `delegated-${crypto.randomUUID()}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  await org.registerSpace({orgId,spaceId:'space',name:'Shared',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''});
  const user = async (name:string,role:'standard'|'admin'='standard') => org.createUser({orgId,email:`${name}@example.test`,displayName:name,role});
  const admin = await user('Folder admin'), member = await user('Member'), global = await user('Global','admin');
  const token = await mintToken(e.AUTH_SIGNING_SECRET,{sub:admin.id,type:'session',orgId,scopes,ttlSeconds:900});
  const memberToken = await mintToken(e.AUTH_SIGNING_SECRET,{sub:member.id,type:'session',orgId,scopes,ttlSeconds:900});
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId,'space')));
  const parent = itemOf(await fs.createItem('root','Private parent',true,0));
  const folder = itemOf(await fs.createItem(parent.id,'Delegated',true,0));
  const child = itemOf(await fs.createItem(folder.id,'Child',true,0));
  const sibling = itemOf(await fs.createItem(parent.id,'Private sibling',true,0));
  const base = `${origin}/v1/filespaces/space`;
  const request = (token:string,method:string,path:string,body?:unknown) => SELF.fetch(`${base}${path}`,{method,headers:headers(token),body:body ? JSON.stringify(body) : undefined});
  const set = (token:string,inodeId:string,principalId=member.id,extra={}) => request(token,'POST','/grants',{inodeId,principalType:'user',principalId,level:'read',...extra});
  const remove = (token:string,inodeId:string,principalId=member.id,principalType='user') => request(token,'DELETE',`/grants?${new URLSearchParams({inodeId,principalId,principalType})}`);
  expect((await set(owner.token,folder.id,admin.id,{level:'admin',mountAsRoot:true})).status).toBe(201);
  return {orgId,org,owner,admin,member,global,token,memberToken,fs,parent,folder,child,sibling,request,set,remove,base};
}

describe('delegated folder administration', () => {
  it('repairs earlier v17/v19 databases without the retirement table while preserving every existing grant', async () => {
    for (const previousVersion of [17,19]) {
      const f=await fixture();
      expect((await f.set(f.token,f.child.id)).status).toBe(201);
      await runInDurableObject(f.fs,(_instance,state)=> {
        const sql=state.storage.sql;
        const before=sql.exec('SELECT * FROM grants ORDER BY id;').toArray();
        restorePreV30LocksTable(sql);
        sql.exec('DROP TABLE revoked_acl_principals;');
        if (previousVersion===17) sql.exec('DROP TABLE disabled_acl_authorities;');
        else sql.exec('INSERT INTO disabled_acl_authorities VALUES (?);','already-disabled');
        sql.exec('DELETE FROM _schema_migrations WHERE id>?;',previousVersion);
        expect(Number(sql.exec('SELECT MAX(id) AS v FROM _schema_migrations;').one().v)).toBe(previousVersion);
        migrate(sql);
        migrate(sql); // repair itself is idempotent
        expect(Number(sql.exec('SELECT MAX(id) AS v FROM _schema_migrations;').one().v)).toBe(SCHEMA_VERSION);
        expect(sql.exec('SELECT * FROM grants ORDER BY id;').toArray()).toEqual(before);
        expect(sql.exec('SELECT * FROM revoked_acl_principals;').toArray()).toEqual([]);
        if (previousVersion===19) expect(sql.exec('SELECT principal_id FROM disabled_acl_authorities;').toArray())
          .toEqual([{principal_id:'already-disabled'}]);
      });
      expect((await f.request(f.token,'GET','/access-management')).status).toBe(200);
      expect((await f.set(f.token,f.child.id,f.member.id,{level:'edit'})).status).toBe(201);
      expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'write')).allow).toBe(true);
      await f.org.setUserStatus(f.admin.id,'suspended');
      expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    }
  });
  it('standard human sessions can manage only their subtree and receive explicit UI capabilities', async () => {
    const f=await fixture();
    expect((await f.set(f.token,f.child.id,f.member.id,{level:'edit'})).status).toBe(201);
    const data=await (await f.request(f.token,'GET','/access-management')).json() as any;
    expect(data.canManageAccess).toBe(true); expect(data.canDelegateAdmin).toBe(false); expect(data.canManageWorkspace).toBe(false);
    expect(data.roots).toEqual([{inodeId:f.folder.id,name:'Delegated',path:'/Delegated'}]);
    expect(data.grants.find((g:any)=>g.principalId===f.member.id)).toMatchObject({inodePath:'/Delegated/Child',canModify:true,level:'edit'});
    expect(data.grants.find((g:any)=>g.principalId===f.admin.id).canModify).toBe(false);
    expect(data.members.some((u:any)=>u.id===f.owner.userId||u.id===f.global.id)).toBe(false);
    expect(JSON.stringify(data)).not.toContain('Private parent');
    expect(JSON.stringify(data)).not.toContain('Private sibling');
    expect((await f.set(f.token,f.child.id)).status).toBe(201); // lowering replaces edit
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'write')).allow).toBe(false);
    expect((await f.remove(f.token,f.child.id)).status).toBe(200);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
  });
  it('denies ancestors, siblings, protected grants, self changes, further admins, unknown and cross-org principals', async () => {
    const f=await fixture();
    for (const id of ['root',f.parent.id,f.sibling.id]) {
      expect((await f.set(f.token,id)).status).toBe(403);
      expect((await f.request(f.token,'GET',`/grants?inodeId=${id}`)).status).toBe(403);
    }
    expect((await f.set(f.token,f.child.id,f.member.id,{level:'admin'})).status).toBe(403);
    expect((await f.remove(f.token,f.folder.id,f.admin.id)).status).toBe(403);
    expect((await f.set(f.token,f.child.id,f.global.id)).status).toBe(403);
    expect((await f.set(f.token,f.child.id,'unknown')).status).toBe(400);
    expect((await f.set(f.token,f.child.id,f.member.id,{level:'owner'})).status).toBe(400);
    expect((await f.set(f.owner.token,f.child.id)).status).toBe(201);
    expect((await f.remove(f.token,f.child.id)).status).toBe(403);
    expect((await f.set(f.token,f.child.id,f.member.id,{level:'edit'})).status).toBe(403);
    const other=await e.ORG_DO.get(e.ORG_DO.idFromName('other-org')).createUser({orgId:'other-org',email:'other@example.test',displayName:'Other'});
    expect((await f.set(f.token,f.child.id,other.id)).status).toBe(400);
    for (const [method,path,body] of [['POST','users',{email:'new@example.test',displayName:'New',role:'admin'}],['PATCH',`users/${f.admin.id}`,{role:'admin'}],['POST','groups',{name:'Escalation'}]] as const) {
      expect((await SELF.fetch(`${origin}/v1/orgs/${f.orgId}/${path}`,{method,headers:headers(f.token),body:JSON.stringify(body)})).status).toBe(403);
    }
  });
  it('revoking the original delegation disables issued grants and rejects a previously captured actor', async () => {
    const f=await fixture();
    expect((await f.set(f.token,f.child.id)).status).toBe(201);
    expect((await f.remove(f.owner.token,f.folder.id,f.admin.id)).status).toBe(200);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    const direct = await f.fs.grantAccessFor({type:'user',id:f.admin.id,orgRole:'standard'}, {spaceId:'space',inodeId:f.child.id,principalType:'user',principalId:f.member.id,level:'read'},false);
    expect(direct).toEqual({error:'folder_admin_required'});
    expect((await f.set(f.token,f.child.id)).status).toBe(403);
  });
  it('caps expiry and rejects deleted or moved-out nodes without resurrecting same-name permissions', async () => {
    const f=await fixture();
    const expiresAt=Date.now()+60000;
    expect((await f.set(f.owner.token,f.folder.id,f.admin.id,{level:'admin',expiresAt})).status).toBe(201);
    expect((await f.set(f.token,f.child.id,f.member.id,{expiresAt:expiresAt+999999})).status).toBe(201);
    const rows=await f.fs.listGrants(f.child.id); expect(rows[0].expiresAt).toBe(expiresAt);
    expect((await f.request(f.owner.token,'PATCH',`/items/${f.child.id}`,{parent:f.sibling.id,name:'Moved'})).status).toBe(200);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    expect((await f.set(f.token,f.child.id)).status).toBe(403);
    expect((await f.request(f.owner.token,'DELETE',`/items/${f.folder.id}?recursive=true`)).status).toBe(200);
    // Removing the sole delegated root closes administration before target lookup.
    expect((await f.set(f.token,f.folder.id)).status).toBe(403);
    const fresh=itemOf(await f.fs.createItem(f.parent.id,'Delegated',true,0));
    expect(fresh.id).not.toBe(f.folder.id);
    expect((await f.set(f.token,fresh.id)).status).toBe(403);
  });
  it('group delegates lose management on membership removal; prior shared grants belong to the group authority until revoked', async () => {
    const f=await fixture();
    await f.remove(f.owner.token,f.folder.id,f.admin.id);
    const group=await f.org.createGroup({orgId:f.orgId,name:'Folder managers'});
    await f.org.addGroupMember(group.id,f.admin.id);
    expect((await f.set(f.owner.token,f.folder.id,group.id,{principalType:'group',level:'admin'})).status).toBe(201);
    expect((await f.set(f.token,f.child.id)).status).toBe(201);
    // Direct authority-store change bypasses every isolate cache: admin routes must re-read it.
    await f.org.removeGroupMember(group.id,f.admin.id);
    expect((await f.set(f.token,f.child.id)).status).toBe(403);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(true);
    expect((await f.remove(f.owner.token,f.folder.id,group.id,'group')).status).toBe(200);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
  });
  it('deleting a delegated group invalidates issued grants and tombstones late writes for that group', async () => {
    const f=await fixture();
    await f.remove(f.owner.token,f.folder.id,f.admin.id);
    const group=await f.org.createGroup({orgId:f.orgId,name:'Folder managers'});
    await f.org.addGroupMember(group.id,f.admin.id);
    expect((await f.set(f.owner.token,f.folder.id,group.id,{principalType:'group',level:'admin'})).status).toBe(201);
    expect((await f.set(f.token,f.child.id)).status).toBe(201);
    expect((await SELF.fetch(`${origin}/v1/orgs/${f.orgId}/groups/${group.id}`,{method:'DELETE',headers:headers(f.owner.token)})).status).toBe(200);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    const result=await f.fs.grantAccessFor({type:'user',id:f.owner.userId,orgRole:'owner'},{spaceId:'space',inodeId:f.folder.id,principalType:'group',principalId:group.id,level:'admin'},false);
    expect(result).toEqual({error:'invalid_principal'});
  });
  it('managed-folder browsing omits weaker overrides and never accepts a private starting point', async () => {
    const f=await fixture();
    const restricted=itemOf(await f.fs.createItem(f.folder.id,'Read only',true,0));
    await f.set(f.owner.token,restricted.id,f.admin.id,{level:'read'});
    const page=await (await f.request(f.token,'GET',`/access-management?parent=${f.folder.id}`)).json() as any;
    expect(page.items.map((item:any)=>item.id)).toEqual([f.child.id]);
    expect((await f.request(f.token,'GET',`/access-management?parent=${f.parent.id}`)).status).toBe(403);
    expect((await f.set(f.token,restricted.id)).status).toBe(403);
  });
  it('live authority expiry and demotion stop issued access; request fields cannot forge an independent grant', async () => {
    const f=await fixture();
    expect((await f.set(f.token,f.child.id,f.member.id,{level:'edit',authorityGrantId:null,authorityInodeId:'root',grantedByMemberId:f.owner.userId})).status).toBe(201);
    // Updating an active admin's mount setting preserves existing delegated access.
    expect((await f.set(f.owner.token,f.folder.id,f.admin.id,{level:'admin',mountAsRoot:false})).status).toBe(201);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(true);
    await runInDurableObject(f.fs,(_instance,state)=> {
      state.storage.sql.exec('UPDATE grants SET expires_at=? WHERE principal_id=? AND level=?;',Date.now()-1,f.admin.id,'admin');
    });
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    expect((await f.set(f.token,f.child.id)).status).toBe(403);
    // Re-issuing an expired authority gets a fresh id; old grants stay inactive.
    await f.set(f.owner.token,f.folder.id,f.admin.id,{level:'admin'});
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
  });
  it('group retirement also reaches soft-deleted filespaces before they can be restored', async () => {
    const f=await fixture();
    await f.remove(f.owner.token,f.folder.id,f.admin.id);
    const group=await f.org.createGroup({orgId:f.orgId,name:'Managers'});
    await f.org.addGroupMember(group.id,f.admin.id);
    await f.set(f.owner.token,f.folder.id,group.id,{principalType:'group',level:'admin'});
    await f.set(f.token,f.child.id);
    await f.org.deleteSpace('space');
    await f.org.deleteGroup(group.id);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
  });
  it('suspension and deprovision retire direct delegation without reviving issued grants on reactivation', async () => {
    for (const status of ['suspended','deprovisioned'] as const) {
      const f=await fixture();
      expect((await f.set(f.token,f.child.id)).status).toBe(201);
      await f.org.setUserStatus(f.admin.id,status);
      expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
      await f.org.setUserStatus(f.admin.id,'active');
      expect((await f.set(f.token,f.child.id)).status).toBe(403);
      expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
      await f.set(f.owner.token,f.folder.id,f.admin.id,{level:'admin'});
      expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    }
  });
  it('suspension rejects a previously admitted late admin grant in every alias and soft-deleted filespace', async () => {
    const f=await fixture();
    const owner={type:'user' as const,id:f.owner.userId,orgRole:'owner' as const};
    const before=(await f.fs.accessManagementFor(owner)).grants.find(g=>g.principalId===f.admin.id && g.level==='admin')!;
    expect(typeof before.id).toBe('string');
    await f.set(f.token,f.child.id);
    // Capture the validated request while active, then retire the account before
    // its DO mutation arrives. Soft deletion must not hide this filespace.
    const admitted={spaceId:'space',inodeId:f.folder.id,principalType:'user' as const,principalId:f.admin.id,level:'admin' as const};
    await f.org.deleteSpace('space');
    await f.org.setUserStatus(f.admin.id,'suspended');
    for (const principalType of ['user','service_account'] as const) {
      expect(await f.fs.grantAccessFor(owner,{...admitted,principalType},false)).toEqual({error:'invalid_principal'});
    }
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
    await f.org.setUserStatus(f.admin.id,'active');
    const fresh=await f.fs.grantAccessFor(owner,admitted,false);
    expect('id' in fresh && fresh.id!==before.id).toBe(true);
    expect((await f.fs.checkAccess({type:'user',id:f.member.id},f.child.id,'read')).allow).toBe(false);
  });
  it('overlapping suspension and explicit reactivation leave the authority barrier in the final status', async () => {
    const f=await fixture();
    const operations=[f.org.setUserStatus(f.admin.id,'suspended'),f.org.setUserStatus(f.admin.id,'active')];
    await Promise.all(operations);
    expect((await f.org.getUser(f.admin.id))?.status).toBe('active');
    expect((await f.set(f.token,f.child.id)).status).toBe(403);
    expect((await f.set(f.owner.token,f.folder.id,f.admin.id,{level:'admin'})).status).toBe(201);
  });
  it('ordinary read/edit users and daemon tokens cannot enter folder administration', async () => {
    const f=await fixture();
    expect((await f.set(f.owner.token,f.folder.id,f.member.id,{level:'edit'})).status).toBe(201);
    const data=await (await f.request(f.memberToken,'GET','/access-management')).json() as any;
    expect(data).toMatchObject({canManageAccess:false,roots:[],grants:[],members:[],groups:[]});
    const daemon=await mintToken(e.AUTH_SIGNING_SECRET,{sub:f.admin.id,type:'service',orgId:f.orgId,scopes,ttlSeconds:900});
    expect((await f.set(daemon,f.child.id)).status).toBe(403);
    const readonly=await mintToken(e.AUTH_SIGNING_SECRET,{sub:f.admin.id,type:'session',orgId:f.orgId,scopes:['fs:read'],ttlSeconds:900});
    expect((await f.set(readonly,f.child.id)).status).toBe(403);
    const readOnlyCaps=await (await f.request(readonly,'GET','/access-management')).json() as any;
    expect(readOnlyCaps.canManageAccess).toBe(false);
    expect(readOnlyCaps.grants.every((g:any)=>!g.canModify)).toBe(true);
  });
});
