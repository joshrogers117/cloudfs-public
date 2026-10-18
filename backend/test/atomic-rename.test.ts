// SPDX-License-Identifier: AGPL-3.0-or-later
import {env,SELF,runInDurableObject} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
import type {Env} from '../src/env';
import {NamespaceStore} from '../src/metadata/namespace';
import {SnapshotStore} from '../src/metadata/snapshots';
import {mintToken} from '../src/security/auth';
import {OPEN_HANDLE_READ, OPEN_HANDLE_WRITE} from '../src/metadata/open-handles';
const bindings=env as Env,owner={type:'user' as const,id:'owner',orgRole:'owner' as const};
const block=(hash:string)=>({chunkIdx:0,blockIdx:0,blockHash:hash,objectKey:`blocks/${hash}`,offset:0,length:16});
describe('atomic rename replacement',()=>{
 it('keeps source content/identity, tombstones target and retains snapshot refs',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),a=ns.put('root','save.tmp',false,0),b=ns.put('root','project',false,0);
   ns.setBlockMap(a.id,[block('new')]);ns.setBlockMap(b.id,[block('old')]);ns.putStream(a.id,'meta',new Uint8Array([1,2]));
   const snapshot=new SnapshotStore(state.storage.sql,()=>ns.currentSeq(),ns);snapshot.create({id:'before'});
   const before=ns.currentSeq(),am=ns.getItem(a.id)!,bm=ns.getItem(b.id)!;
   expect(await fs.renameItem(a.id,{name:'project',expectedVersion:am.version,replace:{id:b.id,expectedVersion:bm.version},principal:owner})).toMatchObject({item:{id:a.id,name:'project',version:am.version+1,contentVersion:am.contentVersion}});
   expect(ns.liveSiblingByName('root','project')?.id).toBe(a.id);expect(ns.getItem(b.id)?.deleted).toBe(true);
   expect(Array.from(ns.getStream(a.id,'meta')!)).toEqual([1,2]);
   expect(ns.changesSince(before).items.map(i=>({id:i.id,deleted:i.deleted}))).toEqual([{id:b.id,deleted:true},{id:a.id,deleted:false},{id:'root',deleted:false}]);
   expect(Number(state.storage.sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','old').one().refcount)).toBe(1);
   expect(snapshot.itemAt('before',b.id)?.name).toBe('project');
  });
 });
 it('keeps both names unchanged on either version or destination identity conflict',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),a=ns.put('root','a',false,0),b=ns.put('root','b',false,0),before=ns.currentSeq();
   for(const opts of [{expectedVersion:a.version+1,replace:{id:b.id,expectedVersion:b.version}},{expectedVersion:a.version,replace:{id:b.id,expectedVersion:b.version+1}},{expectedVersion:a.version,replace:{id:'different',expectedVersion:b.version}}])
    expect(await fs.renameItem(a.id,{name:'b',principal:owner,...opts})).not.toHaveProperty('item');
   expect(ns.currentSeq()).toBe(before);expect(ns.getItem(a.id)?.name).toBe('a');expect(ns.getItem(b.id)?.deleted).toBe(false);
  });
 });
 it('rolls back tombstone and refs on SQL failure after target deletion',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),a=ns.put('root','a',false,0),b=ns.put('root','b',false,0);
   ns.setBlockMap(b.id,[block('retained')]);const bm=ns.getItem(b.id)!,before=ns.currentSeq();
   state.storage.sql.exec(`CREATE TRIGGER fail_rename BEFORE UPDATE OF name ON items BEGIN SELECT RAISE(ABORT, 'injected rename failure'); END;`);
   await expect(fs.renameItem(a.id,{name:'b',expectedVersion:a.version,replace:{id:b.id,expectedVersion:bm.version},principal:owner})).rejects.toThrow('injected rename failure');
   expect(ns.currentSeq()).toBe(before);expect(ns.getItem(b.id)?.deleted).toBe(false);
   expect(Number(state.storage.sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','retained').one().refcount)).toBe(1);
  });
 });
 it('rejects invalid parents, root moves, cycles, type mismatch and nonempty replacement',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),a=ns.put('root','a',true,0),b=ns.put('root','b',true,0),f=ns.put('root','file',false,0);
   ns.put(b.id,'child',false,0);const before=ns.currentSeq();
   expect(await fs.renameItem('root',{name:'moved',principal:owner})).toMatchObject({invalidMutation:'root_protected'});
   for(const parent of ['missing',f.id]) expect(await fs.renameItem(a.id,{parent,principal:owner})).toMatchObject({invalidMutation:'invalid_parent'});
   expect(await fs.renameItem(a.id,{parent:a.id,principal:owner})).toHaveProperty('invalidMove');
   expect(await fs.renameItem(a.id,{name:'file',expectedVersion:a.version,replace:{id:f.id,expectedVersion:f.version},principal:owner})).toMatchObject({invalidMutation:'type_mismatch'});
   expect(await fs.renameItem(a.id,{name:'b',expectedVersion:a.version,replace:{id:b.id,expectedVersion:ns.getItem(b.id)!.version},principal:owner})).toMatchObject({invalidMutation:'directory_not_empty'});
   expect(ns.currentSeq()).toBe(before);
  });
 });
 it('requires both inode leases and refuses readonly target deletion/replacement',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),a=ns.put('root','a',false,0),b=ns.put('root','b',false,0),opts={name:'b',expectedVersion:a.version,replace:{id:b.id,expectedVersion:b.version},principal:owner,owner:'mine'};
   await fs.acquireLock(b.id,'other',60000);expect(await fs.renameItem(a.id,opts)).toMatchObject({locked:true,heldBy:'other'});
   state.storage.sql.exec('DELETE FROM locks');await fs.acquireLock(a.id,'other',60000);expect(await fs.renameItem(a.id,opts)).toMatchObject({locked:true,heldBy:'other'});state.storage.sql.exec('DELETE FROM locks');
   const readonly=ns.setBasicInfo(b.id,{fileAttributes:1},b.version);
   expect(await fs.renameItem(a.id,{...opts,replace:{id:b.id,expectedVersion:readonly.version}})).toMatchObject({invalidMutation:'readonly'});
   expect(await fs.deleteItem(b.id)).toMatchObject({deleted:false,reason:'readonly'});expect(ns.getItem(a.id)?.name).toBe('a');expect(ns.getItem(b.id)?.deleted).toBe(false);
  });
 });
 it('allows a caller-owned write lease to replace a share-delete target and retains its open inode',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),source=ns.put('root','new.tmp',false,16),target=ns.put('root','project',false,16);
   ns.setBlockMap(source.id,[block('replacement')]);ns.setBlockMap(target.id,[block('retained-target')]);
   const sourceMeta=ns.getItem(source.id)!,targetMeta=ns.getItem(target.id)!;
   const principal={type:'user' as const,id:'owner',orgRole:'owner' as const},owner='owner:device-a',handleId=crypto.randomUUID();
   expect(await fs.beginOpenFor(principal,target.id,owner,{handleId,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000}))
    .toMatchObject({granted:true});
   expect(await fs.acquireLock(target.id,owner,60_000)).toMatchObject({granted:true});
   const result=await fs.renameItem(source.id,{name:'project',expectedVersion:sourceMeta.version,
    replace:{id:target.id,expectedVersion:targetMeta.version},owner,principal});
   expect(result).toMatchObject({item:{id:source.id,name:'project'}});
   expect(ns.getItem(target.id)?.deleted).toBe(true);
   expect(ns.liveSiblingByName('root','project')?.id).toBe(source.id);
   expect(ns.getBlockMap(target.id)).toEqual([block('retained-target')]);
   expect((await fs.checkOpenAccess(principal,target.id,'write',owner)).allow).toBe(true);
   expect(await fs.closeOpenFor(owner,handleId)).toMatchObject({closed:true});
   expect(ns.getBlockMap(target.id)).toEqual([]);
   await fs.releaseLock(target.id,owner);
  });
 });
 it('keeps share-delete and foreign write-lease checks independent for replacement',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
   const source=ns.put('root','source-a',false,0),target=ns.put('root','target-a',false,0);
   const owner='owner:device-a',handleId=crypto.randomUUID();
   expect(await fs.beginOpenFor(principal,target.id,owner,{handleId,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:3,ttlMs:60_000}))
    .toMatchObject({granted:true});
   expect(await fs.renameItem(source.id,{name:'target-a',expectedVersion:source.version,
    replace:{id:target.id,expectedVersion:target.version},owner,principal}))
    .toMatchObject({invalidMutation:'sharing_violation'});
   expect(ns.getItem(source.id)?.deleted).toBe(false);expect(ns.getItem(target.id)?.deleted).toBe(false);
   await fs.closeOpenFor(owner,handleId);

   const source2=ns.put('root','source-b',false,0),target2=ns.put('root','target-b',false,0);
   const holder='owner:device-b',handleId2=crypto.randomUUID();
   expect(await fs.beginOpenFor(principal,target2.id,holder,{handleId:handleId2,
    accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:3,ttlMs:60_000})).toMatchObject({granted:true});
   expect(await fs.acquireLock(target2.id,holder,60_000)).toMatchObject({granted:true});
   expect(await fs.renameItem(source2.id,{name:'target-b',expectedVersion:source2.version,
    replace:{id:target2.id,expectedVersion:target2.version},owner,principal}))
    .toMatchObject({locked:true,heldBy:holder});
   expect(ns.getItem(source2.id)?.deleted).toBe(false);expect(ns.getItem(target2.id)?.deleted).toBe(false);
   await fs.closeOpenFor(holder,handleId2);
   await fs.releaseLock(target2.id,holder);
  });
 });
 it('lets a foreign writer keep writing its retained inode after replacement when its open shares delete',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
   const source=ns.put('root','incoming',false,16),target=ns.put('root','document',false,16);
   ns.setBlockMap(source.id,[block('incoming-bytes')]);ns.setBlockMap(target.id,[block('old-bytes')]);
   const holder='owner:device-b',handleId=crypto.randomUUID();
   const opened=await fs.beginOpenFor(principal,target.id,holder,{handleId,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000});
   expect(opened).toMatchObject({granted:true});
   const lease=await fs.acquireLock(target.id,holder,60_000,'exclusive','publication');
   expect(lease).toMatchObject({granted:true});
   const replaced=await fs.renameItem(source.id,{name:'document',expectedVersion:ns.getItem(source.id)!.version,
    replace:{id:target.id,expectedVersion:ns.getItem(target.id)!.version},owner:'owner:device-a',principal});
   expect(replaced).toMatchObject({item:{id:source.id,name:'document'}});
   expect(ns.liveSiblingByName('root','document')?.id).toBe(source.id);
   expect(ns.getItem(target.id)).toMatchObject({deleted:true});

   const fsEnv=(fs as unknown as {env:Env & {STORAGE_VERIFY_UPLOADS?:string}}).env,previous=fsEnv.STORAGE_VERIFY_UPLOADS;
   fsEnv.STORAGE_VERIFY_UPLOADS='0';
   try {
    const retained=ns.getItem(target.id)!;
    expect(await fs.setBlockMap(target.id,[block('written-through-old-handle')],{
     expectedVersion:retained.version,owner:holder,fence:lease.granted?lease.fence:undefined,principal,
    })).toMatchObject({id:target.id,deleted:true});
    expect(ns.getBlockMap(target.id)).toEqual([block('written-through-old-handle')]);
    expect(ns.getBlockMap(source.id)).toEqual([block('incoming-bytes')]);
    expect(await fs.setBlockMap(target.id,[block('stale-fence-write')],{
     expectedVersion:ns.getItem(target.id)!.version,owner:holder,fence:(lease.fence??0)+1,principal,
    })).toMatchObject({locked:true,reason:'fence-stale'});
   } finally {fsEnv.STORAGE_VERIFY_UPLOADS=previous;}
   await fs.closeOpenFor(holder,handleId);
   expect(ns.getBlockMap(target.id)).toEqual([]);
   await fs.releaseLock(target.id,holder,lease.granted?lease.fence:undefined);
  });
 });
 it('keeps foreign application and byte-range locks exclusive during replacement',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
   const source=ns.put('root','source',false,0),target=ns.put('root','target',false,0);
   const opts={name:'target',expectedVersion:source.version,replace:{id:target.id,expectedVersion:target.version},owner:'owner:device-a',principal};
   const holder='owner:device-b',handleId=crypto.randomUUID();
   expect(await fs.beginOpenFor(principal,target.id,holder,{handleId,accessMask:OPEN_HANDLE_READ,shareMask:7,ttlMs:60_000})).toMatchObject({granted:true});
   await fs.acquireLock(target.id,holder,60_000);
   expect(await fs.renameItem(source.id,opts)).toMatchObject({locked:true,heldBy:holder});
   state.storage.sql.exec('DELETE FROM locks');await fs.closeOpenFor(holder,handleId);

   const writeHandle=crypto.randomUUID();
   expect(await fs.beginOpenFor(principal,target.id,holder,{handleId:writeHandle,
    accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:3,ttlMs:60_000})).toMatchObject({granted:true});
   await fs.acquireLock(target.id,holder,60_000);
   expect(await fs.renameItem(source.id,opts)).toMatchObject({locked:true,heldBy:holder});
   state.storage.sql.exec('DELETE FROM locks');await fs.closeOpenFor(holder,writeHandle);

   const rangeHandle=crypto.randomUUID();
   expect(await fs.beginOpenFor(principal,target.id,holder,{handleId:rangeHandle,
    accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000})).toMatchObject({granted:true});
   expect(await fs.acquireRangesFor(principal,target.id,holder,rangeHandle,[{offset:'0',length:'1',exclusive:true}],60_000)).toMatchObject({granted:true});
   expect(await fs.renameItem(source.id,opts)).toMatchObject({locked:true,heldBy:holder});
   await fs.closeOpenFor(holder,rangeHandle);
  });
 });
 it('does not promote advisory leases and keeps publication purpose exclusive across reacquire and renew',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
   const source=ns.put('root','source',false,0),target=ns.put('root','target',false,0);
   const holder='owner:device-b',handle=crypto.randomUUID();
   const headless=await fs.acquireLock(target.id,holder,60_000,'exclusive','publication');
   expect(headless).toMatchObject({granted:true,purpose:'publication'});
   expect(await fs.renameItem(source.id,{name:'target',expectedVersion:source.version,
    replace:{id:target.id,expectedVersion:target.version},owner:'owner:device-a',principal})).toMatchObject({locked:true,heldBy:holder});
   await fs.releaseLock(target.id,holder,headless.fence);
   await fs.beginOpenFor(principal,target.id,holder,{handleId:handle,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000});
   const advisory=await fs.acquireLock(target.id,holder,60_000);
   expect(advisory).toMatchObject({granted:true,purpose:'advisory'});
   expect(await fs.acquireLock(target.id,holder,60_000,'exclusive','publication')).toMatchObject({granted:false,reason:'purpose-mismatch'});
   expect(await fs.renameItem(source.id,{name:'target',expectedVersion:source.version,
    replace:{id:target.id,expectedVersion:target.version},owner:'owner:device-a',principal})).toMatchObject({locked:true,heldBy:holder});
   expect(await fs.releaseLock(target.id,holder,advisory.fence)).toMatchObject({released:true});

   const shared=await fs.acquireLock(target.id,holder,60_000,'shared');
   expect(shared).toMatchObject({granted:true,purpose:'advisory'});
   expect(await fs.acquireLock(target.id,holder,60_000,'shared','publication')).toMatchObject({granted:false,reason:'purpose-mismatch'});
   expect(await fs.renameItem(source.id,{name:'target',expectedVersion:source.version,
    replace:{id:target.id,expectedVersion:target.version},owner:'owner:device-a',principal})).toMatchObject({locked:true,heldBy:holder});
   await fs.releaseLock(target.id,holder,shared.fence);

   const publication=await fs.acquireLock(target.id,holder,60_000,'exclusive','publication');
   expect(publication).toMatchObject({granted:true,purpose:'publication'});
   const renewed=await fs.renewLock(target.id,holder,publication.fence!,60_000);
   expect(renewed).toMatchObject({granted:true,purpose:'publication'});
   expect(await fs.acquireLock(target.id,holder,60_000,'exclusive','advisory')).toMatchObject({granted:false,reason:'purpose-mismatch'});
   await fs.closeOpenFor(holder,handle);
  });
 });
 it('requires a live writable share-delete handle and every open must permit deletion',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
   const source=ns.put('root','source',false,0),target=ns.put('root','target',false,0);
   const holder='owner:device-b',first=crypto.randomUUID(),second=crypto.randomUUID();
   await fs.beginOpenFor(principal,target.id,holder,{handleId:first,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000});
   const publication=await fs.acquireLock(target.id,holder,60_000,'exclusive','publication');
   await fs.beginOpenFor(principal,target.id,holder,{handleId:second,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:3,ttlMs:60_000});
   expect(await fs.renameItem(source.id,{name:'target',expectedVersion:source.version,
    replace:{id:target.id,expectedVersion:target.version},owner:'owner:device-a',principal})).toMatchObject({invalidMutation:'sharing_violation'});
   await fs.closeOpenFor(holder,second);
   state.storage.sql.exec('UPDATE open_handles SET expires_at=? WHERE handle_id=?',Date.now()-1,first);
   expect(await fs.renameItem(source.id,{name:'target',expectedVersion:source.version,
    replace:{id:target.id,expectedVersion:target.version},owner:'owner:device-a',principal})).toMatchObject({locked:true,heldBy:holder});
   await fs.releaseLock(target.id,holder,publication.fence);

   const source2=ns.put('root','source-2',false,0),target2=ns.put('root','target-2',false,0),writeOnlyShare=crypto.randomUUID();
   await fs.beginOpenFor(principal,target2.id,holder,{handleId:writeOnlyShare,
    accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:3,ttlMs:60_000});
   const lease2=await fs.acquireLock(target2.id,holder,60_000,'exclusive','publication');
   expect(lease2).toMatchObject({granted:true,purpose:'publication'});
   expect(await fs.renameItem(source2.id,{name:'target-2',expectedVersion:source2.version,
    replace:{id:target2.id,expectedVersion:target2.version},owner:'owner:device-a',principal})).toMatchObject({locked:true,heldBy:holder});
   await fs.closeOpenFor(holder,writeOnlyShare);await fs.releaseLock(target2.id,holder,lease2.fence);
  });
 });
 it('rejects nonempty deletes, readonly subtree/snapshot writes and invalid create parents',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),async(fs,state)=>{
   const ns=new NamespaceStore(state.storage.sql),dir=ns.put('root','dir',true,0),file=ns.put(dir.id,'file',false,0);
   const snapshots=new SnapshotStore(state.storage.sql,()=>ns.currentSeq(),ns);snapshots.create({id:'snap'});
   ns.setBasicInfo(file.id,{fileAttributes:1},file.version);const before=ns.currentSeq();
   expect(await fs.deleteItem(dir.id)).toMatchObject({deleted:false,reason:'directory_not_empty'});
   expect(await fs.deleteSubtree(dir.id,'owner')).toHaveProperty('forbidden');
   expect(await fs.deleteSubtree('root','owner')).toHaveProperty('forbidden');
   expect(await fs.createItem(file.id,'child',false,0)).toEqual({invalidParent:true});
   expect(await fs.createItem('missing','child',false,0)).toEqual({invalidParent:true});
   const restored=await fs.restoreSnapshot('snap',file.id,{principal:owner});
   expect(restored.restored).toHaveLength(0);expect(ns.getItem(file.id)?.fileAttributes).toBe(1);
   expect(ns.currentSeq()).toBe(before);
  });
 });
 it('requires destination delete ACL as well as parent create permission through HTTP',async()=>{
  const orgId=`replace-${crypto.randomUUID()}`,org=bindings.ORG_DO.getByName(orgId);
  const admin=await org.createUser({orgId,email:`a-${orgId}@example.test`,displayName:'Admin',role:'admin'}),user=await org.createUser({orgId,email:`u-${orgId}@example.test`,displayName:'User',role:'standard'});
  const auth=async(sub:string)=>({Authorization:`Bearer ${await mintToken(bindings.AUTH_SIGNING_SECRET,{sub,orgId,type:'session',scopes:['fs:read','fs:write','fs:admin'],ttlSeconds:300})}`,'content-type':'application/json'});
  const ah=await auth(admin.id),uh=await auth(user.id),base='https://gw.local/v1/filespaces/space';
  const send=(headers:Record<string,string>,method:string,path:string,body?:unknown)=>SELF.fetch(base+path,{headers,method,body:body?JSON.stringify(body):undefined});
  const a=await(await send(ah,'POST','/items',{name:'a',size:0})).json<{id:string;version:number}>(),b=await(await send(ah,'POST','/items',{name:'b',size:0})).json<{id:string;version:number}>();
  expect((await send(ah,'POST','/grants',{inodeId:'root',principalType:'user',principalId:user.id,level:'edit'})).status).toBe(201);
  expect((await send(ah,'POST','/grants',{inodeId:b.id,principalType:'user',principalId:user.id,level:'read'})).status).toBe(201);
  const patch={name:'b',expectedVersion:a.version,replace:{id:b.id,expectedVersion:b.version}};
  expect((await send(uh,'PATCH',`/items/${a.id}`,patch)).status).toBe(403);expect((await send(ah,'GET',`/items/${b.id}`)).status).toBe(200);
  expect((await send(ah,'PATCH',`/items/${a.id}`,patch)).status).toBe(200);expect((await send(ah,'GET',`/items/${b.id}`)).status).toBe(404);
 });
});
