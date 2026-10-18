// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { NamespaceStore } from '../src/metadata/namespace';
import { SnapshotStore } from '../src/metadata/snapshots';
import { applyFileDelta, type FileDelta } from '../src/metadata/file-manifest';
import { seedOwnerFixture } from './setup-fixture';
import { filespaceDoName } from '../src/security/auth';
const bindings=env as Env, BS=1024*1024;
const block=(index:number,hash='a',length=BS)=>({chunkIdx:index,blockIdx:0,blockHash:hash.repeat(64),objectKey:`blocks/org::s/${hash.repeat(64)}`,offset:index*BS,length});
const delta=(size:number,expectedVersion:number,blocks:FileDelta['blocks']):FileDelta=>({format:1,size,expectedVersion,blockSize:BS,fence:1,blocks});
async function stores(fn:(sql:SqlStorage,ns:NamespaceStore,snap:SnapshotStore,state:DurableObjectState)=>void) {
 const fs=bindings.FILESPACE.getByName(crypto.randomUUID());
 await runInDurableObject(fs,(_instance,state)=>{const ns=new NamespaceStore(state.storage.sql);ns.put('root','file',false,0,{id:'file'});fn(state.storage.sql,ns,new SnapshotStore(state.storage.sql,()=>ns.currentSeq(),ns),state);});
}
describe('versioned main-file deltas',()=>{
 it('updates one extent in a 16 GiB map with bounded metadata work and exact lost-reply idempotency',async()=>{
  await stores((sql,ns,snap,state)=>{
   const old=Array.from({length:16384},(_,i)=>block(i));ns.setBlockMap('file',old);snap.create({id:'before'});
   const d=delta(old.length*BS,ns.getItem('file')!.version,[block(8000,'b')]);
   const cursors:SqlStorageCursor<Record<string,SqlStorageValue>>[]=[];
   const measured=new Proxy(sql,{get(target,key){if(key==='exec')return(...args:Parameters<SqlStorage['exec']>)=>{const c=target.exec(...args);cursors.push(c);return c;};return Reflect.get(target,key,target);}});
   state.storage.transactionSync(()=>applyFileDelta(measured,'file',d,()=>ns.nextSeq()));
   const reads=cursors.reduce((sum,c)=>sum+c.rowsRead,0),writes=cursors.reduce((sum,c)=>sum+c.rowsWritten,0);
   expect(reads).toBeLessThan(100);expect(writes).toBeLessThan(50);
   const seq=ns.currentSeq();expect(state.storage.transactionSync(()=>applyFileDelta(sql,'file',d,()=>ns.nextSeq()))).toBe(false);
   expect(ns.currentSeq()).toBe(seq);expect(ns.getItem('file')!.version).toBe(d.expectedVersion+1);
   expect(ns.getBlockMap('file')[8000]).toEqual(block(8000,'b'));
   expect(()=>state.storage.transactionSync(()=>applyFileDelta(sql,'file',{...d,blocks:[]},()=>ns.nextSeq()))).toThrow('version conflict');
   expect(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?;',block(0).blockHash).one().refcount).toBe(32767);
   state.storage.transactionSync(()=>snap.restore('before','file'));
   expect(ns.getBlockMap('file')[8000]).toEqual(block(8000));
  });
 });
 it('requires dense growth and rewritten boundaries, rolls back SQL errors, and preserves recovery references',async()=>{
  await stores((sql,ns,_snap,state)=>{
   ns.setBlockMap('file',[block(0),block(1,'b',10)]);
   const commit=(d:FileDelta)=>state.storage.transactionSync(()=>applyFileDelta(sql,'file',d,()=>ns.nextSeq()));
   const version=()=>ns.getItem('file')!.version;
   expect(()=>commit(delta(3*BS,version(),[block(2,'c')]))).toThrow('growth');
   expect(()=>commit(delta(15,version(),[]))).toThrow('boundary');
   commit(delta(3*BS,version(),[block(1,'d'),block(2,'c')]));
   expect(ns.getItem('file')!.size).toBe(3*BS);
   sql.exec(`CREATE TRIGGER file_fail BEFORE INSERT ON blocks WHEN NEW.block_hash='${'e'.repeat(64)}' BEGIN SELECT RAISE(ABORT,'injected file failure'); END;`);
   expect(()=>commit(delta(3*BS,version(),[block(0,'e')]))).toThrow('injected file failure');
   expect(ns.getBlockMap('file')[0]).toEqual(block(0));
   expect(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?;',block(0).blockHash).one().refcount).toBe(1);
   commit(delta(5,version(),[block(0,'f',5)]));
   expect(ns.getBlockMap('file')).toEqual([block(0,'f',5)]);
   expect([...ns.readOwnersForObjectKey(block(2,'c').objectKey)]).toEqual(['file']);
   expect(()=>commit(delta(7,version(),[block(0,'f',6)]))).toThrow('fixed extents');
  });
 });
 it('rejects legacy layouts until a full publication establishes the fixed layout',async()=>{
  await stores((sql,ns,_snap,state)=>{
   ns.setBlockMap('file',[{...block(0),chunkIdx:0,blockIdx:8}]);
   const d=delta(BS,ns.getItem('file')!.version,[block(0,'b')]);
   expect(()=>state.storage.transactionSync(()=>applyFileDelta(sql,'file',d,()=>ns.nextSeq()))).toThrow('full replacement');
   ns.setBlockMap('file',[block(0,'b')],{expectedVersion:d.expectedVersion,blockSize:BS});
   expect(()=>state.storage.transactionSync(()=>applyFileDelta(sql,'file',{...d,expectedVersion:d.expectedVersion+1,blocks:[block(0,'c')]},()=>ns.nextSeq()))).not.toThrow();
  });
 });
 it('enforces gateway CAS/fences and version-bound reads; never exposes a mixed page',async()=>{
  const org=`file-delta-${crypto.randomUUID()}`,owner=await seedOwnerFixture(org),headers={authorization:`Bearer ${owner.token}`,'content-type':'application/json'};
  await SELF.fetch(`https://test/v1/orgs/${org}/spaces`,{method:'POST',headers,body:JSON.stringify({spaceId:'s',name:'S',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''})});
  const fs=bindings.FILESPACE.getByName(filespaceDoName(org,'s')),created=await fs.createItem('root','file',false,0);if(!('item'in created))throw Error('fixture');
  const item=created.item.id,url=`https://test/v1/filespaces/s/blocks/${item}`,prefix=`blocks/${filespaceDoName(org,'s')}/`;
  const b=(i:number,h:string,length=BS)=>({...block(i,h,length),objectKey:prefix+h.repeat(64)});
  await fs.setBlockMap(item,[b(0,'a'),b(1,'b')]);const initial=await fs.getItem(item);
  const lease=await fs.acquireLock(item,owner.userId,60000),body={...delta(2*BS,initial!.version,[b(0,'c')]),fence:lease.fence!};
  const page=await(await SELF.fetch(url+'/range?limit=1',{headers})).json() as {item:{version:number};cursor:number};expect(page.cursor).toBe(0);
  expect((await SELF.fetch(url,{method:'PATCH',headers,body:JSON.stringify({...body,fence:body.fence+1})})).status).toBe(409);
  expect((await SELF.fetch(url,{method:'PATCH',headers,body:JSON.stringify(body)})).status).toBe(200);
  expect((await SELF.fetch(url,{method:'PATCH',headers,body:JSON.stringify(body)})).status).toBe(200);
  expect((await SELF.fetch(url+`/range?after=0&version=${page.item.version}`,{headers})).status).toBe(409);
  expect((await SELF.fetch(url+'/range?limit=1025',{headers})).status).toBe(400);
  expect((await SELF.fetch(url,{method:'PATCH',headers,body:JSON.stringify({...body,blocks:[b(1,'d')]})})).status).toBe(409);
 });
 it('requires live upload receipts and current permission at final publication',async()=>{
  const fs=bindings.FILESPACE.getByName(crypto.randomUUID()),created=await fs.createItem('root','file',false,0);if(!('item'in created))throw Error('fixture');
  const item=created.item.id,owner={type:'user' as const,id:'owner',orgRole:'owner' as const};
  const lease=await fs.acquireLock(item,'owner',60000),d={...delta(BS,created.item.version,[block(0)]),fence:lease.fence!};
  await runInDurableObject(fs,async(instance,state)=>{
   const config=(instance as unknown as {env:Env & {STORAGE_VERIFY_UPLOADS?:string}}).env,previous=config.STORAGE_VERIFY_UPLOADS;config.STORAGE_VERIFY_UPLOADS='1';
   try {
    expect(await instance.commitFileDelta(owner,item,d,'owner','storage')).toEqual({error:'objects_unverified'});
    state.storage.sql.exec('INSERT INTO verified_objects VALUES(?,?,?,?,?,0);','storage',block(0).objectKey,block(0).blockHash,BS+69,BS);
    expect(await instance.commitFileDelta(owner,item,d,'owner','wrong')).toEqual({error:'objects_unverified'});
    expect(await instance.commitFileDelta(owner,item,d,'owner','storage')).toHaveProperty('item');
    expect(await instance.commitFileDelta({...owner,orgRole:'standard'},item,{...d,expectedVersion:d.expectedVersion+1},'owner','storage')).toMatchObject({error:'forbidden'});
   } finally {config.STORAGE_VERIFY_UPLOADS=previous;}
  });
 });
});
