// SPDX-License-Identifier: AGPL-3.0-or-later
import {env,SELF,runInDurableObject} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
import type {Env} from '../src/env';
import {NamespaceStore} from '../src/metadata/namespace';
import {SnapshotStore} from '../src/metadata/snapshots';
import {DoAclStore} from '../src/metadata/acl-store';
import {grant} from '../src/permissions';
import {mintToken} from '../src/security/auth';
const bindings=env as Env,owner={type:'user' as const,id:'owner',orgRole:'owner' as const};
describe('persistent basic file metadata',()=>{
 it('checks authority, CAS, bounds and lease fences without changing content',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(instance,state)=>{
   const ns=new NamespaceStore(state.storage.sql), item=ns.put('root','clip',false,0,{id:'file'});
   const patch={createdAt:1000,modifiedAt:2000,accessedAt:3000,changedAt:4000,fileAttributes:2,expectedVersion:item.version};
   expect(await instance.setBasicInfoFor({...owner,orgRole:'standard'},'file',patch)).toEqual({error:'forbidden'});
   expect(await instance.setBasicInfoFor(owner,'file',{...patch,fence:999},'owner')).toEqual({error:'locked'});
   expect(await instance.setBasicInfoFor(owner,'file',{...patch,fileAttributes:0x400})).toEqual({error:'unsupported_attributes'});
   expect(await instance.setBasicInfoFor(owner,'file',{...patch,modifiedAt:Infinity})).toEqual({error:'invalid_metadata'});
   expect(await instance.setBasicInfoFor(owner,'file',patch)).toMatchObject({item:{createdAt:1000,modifiedAt:2000,accessedAt:3000,changedAt:4000,fileAttributes:2,version:item.version+1,contentVersion:item.contentVersion}});
   expect(await instance.setBasicInfoFor(owner,'file',patch)).toEqual({error:'version_conflict',actual:item.version+1});
   const fresh=new NamespaceStore(state.storage.sql).getItem('file')!;
   expect(fresh.modifiedAt).toBe(2000);expect(ns.list('root').items.find(i=>i.id==='file')?.fileAttributes).toBe(2);
  });
 });
 it('protects read-only bytes across direct manifest, stream, replacement and delete APIs while allowing an editor to clear it',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(instance,state)=>{
   const ns=new NamespaceStore(state.storage.sql);ns.put(null,'root',true,0,{id:'root'});
   const item=ns.put('root','protected',false,0,{id:'file'}),acl=new DoAclStore(state.storage.sql);
   grant(acl,{spaceId:'test',inodeId:'root',principalType:'user',principalId:'editor',level:'edit'},'owner');
   const editor={type:'user' as const,id:'editor',orgRole:'standard' as const};
   const locked=await instance.setBasicInfoFor(editor,'file',{fileAttributes:1,expectedVersion:item.version});
   expect(locked).toHaveProperty('item');const version=ns.getItem('file')!.version;
   expect(await instance.setBlockMap('file',[],{principal:owner})).toMatchObject({forbidden:true});
   expect(await instance.setBlockMap('file',[])).toMatchObject({forbidden:true});
   expect(await instance.commitFileDelta(owner,'file',{format:1,size:0,expectedVersion:version,blockSize:1024*1024,fence:1,blocks:[]},'owner')).toMatchObject({error:'forbidden'});
   expect(await instance.commitStreamManifestFor(owner,'file','AFP_Resource',{format:1,size:0,expectedVersion:0,blockSize:1024*1024,fence:1,blocks:[]},'owner')).toMatchObject({error:'forbidden'});
   expect(await instance.putStreamFor(owner,'file','metadata',new Uint8Array([1]),1)).toEqual({denied:true});
   expect(await instance.deleteStreamFor(owner,'file','metadata')).toEqual({denied:true});
   expect(await instance.createItem('root','protected',false,9)).toMatchObject({forbidden:true});
   expect(await instance.deleteItem('file')).toMatchObject({deleted:false,reason:'readonly'});
   expect(ns.getItem('file')).toMatchObject({size:0,version,fileAttributes:1,deleted:false});
   expect(await instance.setBasicInfoFor({...editor,id:'ungranted'},'file',{fileAttributes:0,expectedVersion:version})).toEqual({error:'forbidden'});
   expect(await instance.setBasicInfoFor(editor,'file',{fileAttributes:0,expectedVersion:version})).toHaveProperty('item');
   expect(await instance.putStreamFor(editor,'file','metadata',new Uint8Array([1]),1)).toEqual({size:1});
  });
 });
 it('preserves times and flags across delta snapshots, base deletion and restore',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),(_instance,state)=>{
   const ns=new NamespaceStore(state.storage.sql);ns.put(null,'root',true,0,{id:'root'});
   const file=ns.put('root','clip',false,0,{id:'file'});
   ns.setBasicInfo('file',{createdAt:1000,modifiedAt:2000,accessedAt:3000,changedAt:4000,fileAttributes:2},file.version);
   const snapshots=new SnapshotStore(state.storage.sql,()=>ns.currentSeq(),ns);
   snapshots.create({id:'one'});snapshots.create({id:'two'});
   ns.setBasicInfo('file',{modifiedAt:9000,fileAttributes:0},ns.getItem('file')!.version);
   snapshots.deleteSnapshot('one');
   expect(snapshots.itemAt('two','file')).toMatchObject({createdAt:1000,modifiedAt:2000,accessedAt:3000,changedAt:4000,fileAttributes:2});
   const before=ns.getItem('file')!.version;snapshots.restore('two','file');
   expect(ns.getItem('file')).toMatchObject({version:before+1,createdAt:1000,modifiedAt:2000,accessedAt:3000,changedAt:4000,fileAttributes:2});
  });
 });
 it('routes authenticated PATCH and returns persisted metadata after a fresh GET',async()=>{
   const orgId=`basic-${crypto.randomUUID()}`;
   const user=await bindings.ORG_DO.getByName(orgId).createUser({orgId,email:`${orgId}@example.test`,displayName:'Metadata',role:'admin'});
   const token=await mintToken(bindings.AUTH_SIGNING_SECRET,{sub:user.id,orgId,type:'session',scopes:['fs:read','fs:write'],ttlSeconds:300});
   const headers={Authorization:`Bearer ${token}`,'content-type':'application/json'},base='https://gw.local/v1/filespaces/space';
   const created=await SELF.fetch(base+'/items',{method:'POST',headers,body:JSON.stringify({parent:'root',name:'clip',size:0})});
   expect(created.status).toBe(201);const file=await created.json<{id:string;version:number}>();
   const response=await SELF.fetch(`${base}/items/${file.id}/basic-info`,{method:'PATCH',headers,body:JSON.stringify({expectedVersion:file.version,modifiedAt:1234000,fileAttributes:2})});
   expect(response.status).toBe(200);
   expect(await (await SELF.fetch(`${base}/items/${file.id}`,{headers})).json()).toMatchObject({modifiedAt:1234000,fileAttributes:2});
   const protectedResponse=await SELF.fetch(`${base}/items/${file.id}/basic-info`,{method:'PATCH',headers,body:JSON.stringify({expectedVersion:file.version+1,fileAttributes:3})});
   expect(protectedResponse.status).toBe(200);
   expect((await SELF.fetch(base+'/items',{method:'POST',headers,body:JSON.stringify({parent:'root',name:'clip',size:9})})).status).toBe(403);
   expect((await SELF.fetch(`${base}/items/${file.id}`,{method:'DELETE',headers})).status).toBe(403);
   expect((await SELF.fetch(`${base}/items/${file.id}/basic-info`,{method:'PATCH',headers,body:JSON.stringify({expectedVersion:file.version+2,fileAttributes:2})})).status).toBe(200);
   expect((await SELF.fetch(`${base}/items/${file.id}`,{method:'DELETE',headers})).status).toBe(200);
 });
});
