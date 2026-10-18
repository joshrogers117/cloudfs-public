// SPDX-License-Identifier: AGPL-3.0-or-later
import {SELF,env,runInDurableObject} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
import type {Env} from '../src/env';
import type {Item} from '../src/metadata/types';
import {filespaceDoName,mintToken} from '../src/security/auth';
import {seedOwnerFixture} from './setup-fixture';
const e=env as Env;
async function fixture() {
 const orgId=`open-http-${crypto.randomUUID()}`,spaceId='shared',owner=await seedOwnerFixture(orgId);
 const org=e.ORG_DO.getByName(orgId),fs=e.FILESPACE.getByName(filespaceDoName(orgId,spaceId));
 const member=await org.createUser({orgId,email:`member@${orgId}.test`,displayName:'Member',role:'standard'});
 const token=await mintToken(e.AUTH_SIGNING_SECRET,{sub:member.id,type:'session',orgId,scopes:['fs:read','fs:write','fs:lock'],ttlSeconds:900});
 await fs.grantAccess({spaceId,inodeId:'root',principalType:'user',principalId:member.id,level:'edit'},owner.userId);
 const device=crypto.randomUUID(),other=crypto.randomUUID(),base=`https://gw.local/v1/filespaces/${spaceId}`;
 const call=(method:string,path:string,body?:unknown,client:string|null=device,auth=token)=>SELF.fetch(base+path,{
  method,headers:{authorization:`Bearer ${auth}`,'content-type':'application/json',...(client?{'X-CloudFS-Client-ID':client}:{})},
  body:body===undefined?undefined:JSON.stringify(body),
 });
 const create=async(name:string)=>(await (await call('POST','/items',{name,size:0})).json<Item>());
 const createDir=async(name:string,parent='root')=>(await (await call('POST','/items',{parent,name,isDir:true,size:0})).json<Item>());
 const open=async(id:string,accessMask=1,shareMask=7)=>{
  const handleId=crypto.randomUUID(); const response=await call('POST','/open-handles',{action:'acquire',id,handleId,accessMask,shareMask,ttlMs:90000});
  expect(response.status).toBe(200); expect(await response.json()).toMatchObject({granted:true}); return handleId;
 };
 const writeStream=async(id:string,name='fork',data=new Uint8Array([1,2,3,4]))=>{
  const principal={type:'user' as const,id:member.id,orgRole:'standard' as const};
  const lockOwner=`${member.id}::client:${device.toLowerCase()}`;
  expect(await fs.putStreamFor(principal,id,name,data,data.byteLength,lockOwner)).toEqual({size:data.byteLength});
 };
 const openCount=async(handleId:string)=>runInDurableObject(fs,(_instance,state)=>
  Number(state.storage.sql.exec('SELECT COUNT(*) AS count FROM open_handles WHERE handle_id=?',handleId).one().count));
 return {orgId,owner,fs,member,token,device,other,call,create,createDir,open,writeStream,openCount};
}
describe('authenticated open-file lifetime HTTP routes',()=>{
 it('only the opening device reads an unlinked inode; listings and new opens exclude it',async()=>{
  const f=await fixture(),file=await f.create('old-file'),handle=await f.open(file.id);
  expect((await f.call('DELETE',`/items/${file.id}`)).status).toBe(200);
  expect((await f.call('GET',`/items/${file.id}`)).status).toBe(200);
  expect((await f.call('GET',`/items/${file.id}`,undefined,f.other)).status).toBe(404);
  expect((await f.call('GET',`/items/${file.id}`,undefined,null,f.owner.token)).status).toBe(404);
  expect((await f.call('GET',`/blocks/${file.id}`)).status).toBe(200);
  expect((await f.call('GET',`/blocks/${file.id}`,undefined,f.other)).status).toBe(403);
  const items=await (await f.call('GET','/items?parent=root')).json<{items:Item[]}>();
  expect(items.items.some(i=>i.id===file.id)).toBe(false);
  const fresh=await f.call('POST','/open-handles',{action:'acquire',id:file.id,handleId:crypto.randomUUID(),accessMask:1,shareMask:7});
  expect(await fresh.json()).toMatchObject({granted:false,reason:'not_found'});
  expect(await (await f.call('POST','/open-handles',{action:'close',handleId:handle},f.other)).json()).toMatchObject({closed:false});
  expect((await f.call('GET',`/items/${file.id}`)).status).toBe(200);
  await f.call('POST','/open-handles',{action:'close',handleId:handle});
  expect((await f.call('GET',`/items/${file.id}`)).status).toBe(404);
 });
 it('rechecks ACLs and does not let read-only handles publish orphan writes',async()=>{
  const f=await fixture(),file=await f.create('read-only-open'),handle=await f.open(file.id);
  await f.call('DELETE',`/items/${file.id}`);
  expect(await (await f.call('GET',`/items/${file.id}/access`)).json()).toEqual({read:true,write:false});
  expect((await f.call('PATCH',`/items/${file.id}/basic-info`,{fileAttributes:32,expectedVersion:2})).status).toBe(403);
  await f.fs.revokeAccess('root','user',f.member.id);
  expect((await f.call('GET',`/items/${file.id}`)).status).toBe(404);
  expect((await f.call('GET',`/blocks/${file.id}`)).status).toBe(403);
  expect(await (await f.call('POST','/open-handles',{action:'renew',handleId:handle})).json()).toMatchObject({granted:false});
  expect(await (await f.call('POST','/open-handles',{action:'close',handleId:handle})).json()).toMatchObject({closed:true});
 });
 it('exempts only the authenticated initiating DELETE handle from its own share-delete rule',async()=>{
  const f=await fixture(),file=await f.create('exclusive-delete'),own=await f.open(file.id,4,0);
  expect((await f.call('DELETE',`/items/${file.id}`)).status).toBe(409);
  expect((await f.call('DELETE',`/items/${file.id}?openHandle=${own}`,undefined,f.other)).status).toBe(409);
  expect((await f.call('DELETE',`/items/${file.id}?openHandle=${own}`)).status).toBe(200);
  await f.call('POST','/open-handles',{action:'close',handleId:own});
 });
 it('requires device identity, bounded inputs, and write scope',async()=>{
  const f=await fixture(),file=await f.create('validated'),body={action:'acquire',id:file.id,handleId:crypto.randomUUID(),accessMask:1,shareMask:7};
  expect((await f.call('POST','/open-handles',body,null)).status).toBe(400);
  expect((await f.call('POST','/open-handles',{...body,accessMask:8})).status).toBe(400);
  expect((await f.call('POST','/open-handles',{...body,ttlMs:120001})).status).toBe(400);
  const readToken=await mintToken(e.AUTH_SIGNING_SECRET,{sub:f.member.id,type:'session',orgId:f.orgId,scopes:['fs:read'],ttlSeconds:900});
  expect((await f.call('POST','/open-handles',{...body,accessMask:2},f.device,readToken)).status).toBe(403);
  const handle=await f.open(file.id,3);
  expect(await (await f.call('POST','/open-handles',{action:'renew',handleId:handle},f.device,readToken)).json()).toMatchObject({granted:false});
  await f.call('POST','/open-handles',{action:'close',handleId:handle});
 });
 it('batch renewal isolates devices, rejects duplicate handles, and honors reduced scopes',async()=>{
  const f=await fixture(),file=await f.create('batch-renew'),read=await f.open(file.id),write=await f.open(file.id,3);
  const body={action:'renew-batch',handles:[read,write],ttlMs:90000};
  const wrong=await (await f.call('POST','/open-handles',body,f.other)).json<{handles:{granted:boolean}[]}>();
  expect(wrong.handles).toHaveLength(2); expect(wrong.handles.every(h=>!h.granted)).toBe(true);
  expect((await f.call('POST','/open-handles',{...body,handles:[read,read]})).status).toBe(400);
  const readToken=await mintToken(e.AUTH_SIGNING_SECRET,{sub:f.member.id,type:'session',orgId:f.orgId,scopes:['fs:read'],ttlSeconds:900});
  const restricted=await (await f.call('POST','/open-handles',body,f.device,readToken)).json<{handles:{handleId:string;granted:boolean}[]}>();
  expect(restricted.handles).toEqual(expect.arrayContaining([expect.objectContaining({handleId:read,granted:true}),expect.objectContaining({handleId:write,granted:false})]));
  for (const handleId of [read,write]) await f.call('POST','/open-handles',{action:'close',handleId});
 });
 it('supports metadata-only directory and file opens without disclosing dead content',async()=>{
  const f=await fixture(),root=await f.open('root',0); await f.call('POST','/open-handles',{action:'close',handleId:root});
  const file=await f.create('metadata-only'),handle=await f.open(file.id,0);
  await f.call('DELETE',`/items/${file.id}`);
  expect((await f.call('GET',`/items/${file.id}`)).status).toBe(200);
  expect((await f.call('GET',`/blocks/${file.id}`)).status).toBe(403);
  await f.call('POST','/open-handles',{action:'close',handleId:handle});
 });
 it('returns one authorized stream lookup with the open grant and keeps exact retries idempotent',async()=>{
  const f=await fixture(),file=await f.create('stream-open'); await f.writeStream(file.id);
  const handleId=crypto.randomUUID(),body={action:'acquire',id:file.id,handleId,accessMask:1,shareMask:7,ttlMs:90000,
   stream:{name:'fork',required:true}};
  const first=await (await f.call('POST','/open-handles',body)).json<{granted:boolean;expiresAt:number;stream:{exists:boolean;size:number}}>();
  expect(first).toMatchObject({granted:true,stream:{exists:true,size:4}});
  const retry=await (await f.call('POST','/open-handles',body)).json<typeof first>();
  expect(retry).toEqual(first);
  expect(await f.openCount(handleId)).toBe(1);
  await f.call('POST','/open-handles',{action:'close',handleId});
 });
 it('checks a sharing conflict before a required missing stream and leaves no attempted handle',async()=>{
  const f=await fixture(),file=await f.create('stream-share-order');
  const held=await f.open(file.id,1,0),attempt=crypto.randomUUID();
  const response=await f.call('POST','/open-handles',{action:'acquire',id:file.id,handleId:attempt,accessMask:1,shareMask:7,
   stream:{name:'missing-fork',required:true}});
  expect(await response.json()).toMatchObject({granted:false,reason:'sharing_violation'});
  expect(await f.openCount(attempt)).toBe(0);
  await f.call('POST','/open-handles',{action:'close',handleId:held});
 });
 it('does not disclose stream absence before ACL authorization',async()=>{
  const f=await fixture(),file=await f.create('stream-acl-order');
  await f.fs.revokeAccess('root','user',f.member.id);
  const response=await f.call('POST','/open-handles',{action:'acquire',id:file.id,handleId:crypto.randomUUID(),accessMask:1,shareMask:7,
   stream:{name:'missing-fork',required:true}});
  const payload=await response.json();
  expect(payload).toEqual({granted:false,reason:'forbidden'});
  expect((payload as {stream?:unknown}).stream).toBeUndefined();
 });
 it('reports an optional missing stream with the open and rolls back exact-handle retries on required miss',async()=>{
  const f=await fixture(),file=await f.create('stream-optional');
  const handleId=crypto.randomUUID();
  const optional=await (await f.call('POST','/open-handles',{action:'acquire',id:file.id,handleId,accessMask:1,shareMask:7,
   stream:{name:'missing-fork',required:false}})).json();
  expect(optional).toMatchObject({granted:true,stream:{exists:false,size:0}});
  await f.call('POST','/open-handles',{action:'close',handleId});

  await f.writeStream(file.id);
  const required={action:'acquire',id:file.id,handleId,accessMask:1,shareMask:7,ttlMs:90000,stream:{name:'fork',required:true}};
  expect(await (await f.call('POST','/open-handles',required)).json()).toMatchObject({granted:true,stream:{exists:true,size:4}});
  const principal={type:'user' as const,id:f.member.id,orgRole:'standard' as const};
  const lockOwner=`${f.member.id}::client:${f.device.toLowerCase()}`;
  expect(await f.fs.deleteStreamFor(principal,file.id,'fork',lockOwner)).toMatchObject({deleted:true});
  expect(await (await f.call('POST','/open-handles',required)).json()).toEqual({granted:false,reason:'stream_not_found'});
  expect(await f.openCount(handleId)).toBe(0);
 });
 it('rejects malformed stream lookup objects at the HTTP boundary',async()=>{
  const f=await fixture(),file=await f.create('stream-invalid-input'),base={action:'acquire',id:file.id,handleId:crypto.randomUUID(),accessMask:1,shareMask:7};
  for (const stream of [[],{}, {name:'',required:true}, {name:'a/b',required:true}, {name:'fork',required:1}, {name:'fork'}]) {
   expect((await f.call('POST','/open-handles',{...base,stream})).status).toBe(400);
  }
  expect((await f.call('POST','/open-handles',{action:'close',handleId:base.handleId,stream:{name:'fork',required:true}})).status).toBe(400);
 });
 it('returns an ACL-filtered directory snapshot and leaves no temporary open row',async()=>{
  const f=await fixture(),directory=await f.createDir('snapshot-directory');
  // Create children under the directory via the ordinary authorized namespace route.
  const childA=(await (await f.call('POST','/items',{parent:directory.id,name:'a',size:3})).json<Item>());
  const childB=(await (await f.call('POST','/items',{parent:directory.id,name:'b',size:4})).json<Item>());
  const handleId=crypto.randomUUID();
  const response=await f.call('POST','/open-handles',{action:'directory-snapshot',id:directory.id,handleId,accessMask:1,shareMask:7,ttlMs:90000});
  expect(response.status).toBe(200);
  const result=await response.json<{granted:boolean;directory:Item;items:Item[]}>();
  expect(result.granted).toBe(true); expect(result.directory.id).toBe(directory.id);
  expect(result.items.map(i=>i.id)).toEqual([childA.id,childB.id]);
  expect(await f.openCount(handleId)).toBe(0);
 });
 it('honors cross-client sharing before listing and preserves a reused persistent handle',async()=>{
  const f=await fixture(),directory=await f.createDir('snapshot-share');
  const held=await f.open(directory.id,1,0),attempt=crypto.randomUUID();
  const denied=await (await f.call('POST','/open-handles',{action:'directory-snapshot',id:directory.id,handleId:attempt,
    accessMask:1,shareMask:7,ttlMs:90000},f.other)).json();
  expect(denied).toEqual({granted:false,reason:'sharing_violation'});
  expect(await f.openCount(attempt)).toBe(0);

  const reused=await (await f.call('POST','/open-handles',{action:'directory-snapshot',id:directory.id,handleId:held,
    accessMask:1,shareMask:0,ttlMs:90000})).json();
  expect(reused).toEqual({granted:false,reason:'handle_conflict'});
  expect(await f.openCount(held)).toBe(1);
  expect(await (await f.call('POST','/open-handles',{action:'renew',handleId:held})).json()).toMatchObject({granted:true});
  await f.call('POST','/open-handles',{action:'close',handleId:held});
 });
 it('uses the ACL-filtered list core and returns no children when directory access is denied',async()=>{
  const f=await fixture(),allowed=await f.createDir('allowed-scope'),hidden=await f.createDir('hidden-sibling');
  const visible=(await f.call('POST','/items',{parent:allowed.id,name:'visible-child',size:1}));
  await f.call('POST','/items',{parent:hidden.id,name:'secret',size:1});
  await f.fs.revokeAccess('root','user',f.member.id);
  await f.fs.grantAccess({spaceId:'shared',inodeId:allowed.id,principalType:'user',principalId:f.member.id,level:'read'},f.owner.userId);
  const principal={type:'user' as const,id:f.member.id,orgRole:'standard' as const};
  const ordinary=await f.fs.listPageFor(principal,allowed.id);
  const handleId=crypto.randomUUID();
  const snapshot=await (await f.call('POST','/open-handles',{action:'directory-snapshot',id:allowed.id,handleId,accessMask:1,shareMask:7})).json<{granted:boolean;items:Item[]}>();
  expect(snapshot.granted).toBe(true);
  expect(snapshot.items).toEqual(ordinary.items);
  expect(snapshot.items.map(item=>item.name)).toContain((await visible.json<Item>()).name);

  const deniedHandle=crypto.randomUUID();
  const denied=await (await f.call('POST','/open-handles',{action:'directory-snapshot',id:'root',handleId:deniedHandle,accessMask:1,shareMask:7})).json();
  expect(denied).toEqual({granted:false,reason:'forbidden'});
  expect(denied).not.toHaveProperty('directory'); expect(denied).not.toHaveProperty('items');
  expect(await f.openCount(handleId)).toBe(0); expect(await f.openCount(deniedHandle)).toBe(0);
 });
 it('rejects stale and non-directory targets without retaining a handle',async()=>{
  const f=await fixture(),directory=await f.createDir('snapshot-deleted'),file=await f.create('snapshot-file');
  const removed=await f.call('DELETE',`/items/${directory.id}`); expect(removed.status).toBe(200);
  for (const [id,reason] of [[directory.id,'not_found'],[file.id,'not_directory']] as const) {
   const handleId=crypto.randomUUID();
   expect(await (await f.call('POST','/open-handles',{action:'directory-snapshot',id,handleId,accessMask:1,shareMask:7})).json())
    .toEqual({granted:false,reason});
   expect(await f.openCount(handleId)).toBe(0);
  }
 });
 it('falls back for directories above 500 children and cleans up the admission row',async()=>{
  const f=await fixture(),directory=await f.createDir('snapshot-large');
  const handleId=crypto.randomUUID();
  expect(await f.fs.seedChildren(directory.id,'child-',500,false)).toBe(500);
  const exact=await (await f.call('POST','/open-handles',{action:'directory-snapshot',id:directory.id,handleId,accessMask:1,shareMask:7})).json<{granted:boolean;items:Item[]}>();
  expect(exact.granted).toBe(true); expect(exact.items).toHaveLength(500);
  expect(await f.openCount(handleId)).toBe(0);
  expect(await f.fs.seedChildren(directory.id,'overflow-',1,false)).toBe(1);
  expect(await (await f.call('POST','/open-handles',{action:'directory-snapshot',id:directory.id,handleId,accessMask:1,shareMask:7})).json())
   .toEqual({granted:false,reason:'snapshot_too_large'});
  expect(await f.openCount(handleId)).toBe(0);
 });
 it('validates directory-snapshot fields and keeps the read-only scope boundary',async()=>{
  const f=await fixture(),directory=await f.createDir('snapshot-validate'),handleId=crypto.randomUUID();
  const base={action:'directory-snapshot',id:directory.id,handleId,accessMask:1,shareMask:7};
  for (const patch of [{accessMask:2},{accessMask:3},{accessMask:null},{shareMask:8},{shareMask:'7'},{ttlMs:'1000'},{ttlMs:{}},
    {id:12},{id:[]},{handleId:12},{stream:{name:'x',required:true}}]) {
   expect((await f.call('POST','/open-handles',{...base,...patch})).status).toBe(400);
  }
  const readToken=await mintToken(e.AUTH_SIGNING_SECRET,{sub:f.member.id,type:'session',orgId:f.orgId,scopes:['fs:read'],ttlSeconds:900});
  expect((await f.call('POST','/open-handles',base,f.device,readToken)).status).toBe(200);
  expect((await f.call('POST','/open-handles',{...base,action:'directory-snap'})).status).toBe(400);
  expect((await f.call('POST','/open-handles',{...base,action:42})).status).toBe(400);
 });
});
