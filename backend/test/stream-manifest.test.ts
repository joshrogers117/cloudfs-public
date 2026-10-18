// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, SELF, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { NamespaceStore } from '../src/metadata/namespace';
import { SnapshotStore } from '../src/metadata/snapshots';
import { commitStreamDelta, readStreamManifest, STREAM_BLOCK_SIZE as BS, type StreamDelta } from '../src/metadata/stream-manifest';
import { BackupState, type BackupPage } from '../src/backup-state';
import { seedOwnerFixture } from './setup-fixture';
import { filespaceDoName } from '../src/security/auth';
const e=env as Env;
const block=(index:number,hash='a',length=BS)=>({index,hash:hash.repeat(64),length,objectKey:`blocks/org::space/${hash.repeat(64)}`});
const delta=(size:number,expectedVersion:number,blocks:StreamDelta['blocks']):StreamDelta=>({format:1,blockSize:BS,size,expectedVersion,fence:1,blocks});
async function stores(fn:(sql:SqlStorage,ns:NamespaceStore,snapshots:SnapshotStore,state:DurableObjectState)=>void){
 const stub=e.FILESPACE.getByName(crypto.randomUUID());
 await runInDurableObject(stub,(_i,s)=>{const ns=new NamespaceStore(s.storage.sql);ns.put('root','clip',false,0,{id:'clip'});fn(s.storage.sql,ns,new SnapshotStore(s.storage.sql,()=>ns.currentSeq(),ns),s);});
}
describe('object backed named streams',()=>{
 it('writes sparse deltas with bounded ranges, shrinks safely and retains CAS tombstones',async()=>{
  await stores((sql,ns,_sn,state)=>{
   const commit=(d:StreamDelta)=>state.storage.transactionSync(()=>commitStreamDelta(sql,'clip','AFP_Resource',d,ns.nextSeq()));
   expect(readStreamManifest(sql,'clip','AFP_Resource')).toMatchObject({exists:false,version:0});
   expect(commit(delta(64*BS,0,[block(0),block(63,'b')]))).toMatchObject({size:64*BS,version:1,legacy:false});
   expect(readStreamManifest(sql,'clip','AFP_Resource',63*BS,BS).blocks).toEqual([block(63,'b')]);
   expect(readStreamManifest(sql,'clip','AFP_Resource',BS,BS).blocks).toEqual([]);
   expect(()=>commit(delta(BS+10,1,[]))).not.toThrow();
   expect(readStreamManifest(sql,'clip','AFP_Resource',0,BS*2).blocks).toEqual([block(0)]);
   expect(()=>commit(delta(10,2,[]))).toThrow('boundary');
   commit(delta(10,2,[block(0,'c',10)]));
   commit(delta(100*BS,3,[])); // short chunk zeros stay sparse
   expect(readStreamManifest(sql,'clip','AFP_Resource',0,BS).blocks[0].length).toBe(10);
   expect(ns.deleteStream('clip','AFP_Resource')).toBe(true);
   expect(readStreamManifest(sql,'clip','AFP_Resource')).toMatchObject({exists:false,version:5});
   expect(()=>commit(delta(1,0,[block(0,'d',1)]))).toThrow('version conflict');
   commit(delta(1,5,[block(0,'d',1)]));
   expect(ns.listStreams('clip')).toEqual([{name:'AFP_Resource',size:1}]);
   expect([...ns.readOwnersForObjectKey(block(63,'b').objectKey)]).toEqual(['clip']);
  });
 });
 it('captures/restores/prunes streams with exact references and no live fallback',async()=>{
  await stores((sql,ns,sn,state)=>{
   const commit=(d:StreamDelta)=>state.storage.transactionSync(()=>commitStreamDelta(sql,'clip','AFP_Resource',d,ns.nextSeq()));
   commit(delta(64*BS,0,[block(0),block(63,'b')]));sn.create({id:'old'});sn.create({id:'inherited'});
   commit(delta(BS,1,[block(0,'c')]));sn.create({id:'new'});
   sn.deleteSnapshot('old');
   expect(sn.streamManifestAt('inherited','clip','AFP_Resource',63*BS,BS)?.blocks).toEqual([block(63,'b')]);
   expect(sn.ownsObjectAt('inherited','clip',block(63,'b').objectKey)).toBe(true);
   expect(sn.ownsObjectAt('new','clip',block(63,'b').objectKey)).toBe(false);
   expect(sn.itemAt('inherited','clip')?.rsrcForkSize).toBe(64*BS);
   state.storage.transactionSync(()=>sn.restore('inherited','clip'));
   expect(readStreamManifest(sql,'clip','AFP_Resource',63*BS,BS).blocks).toEqual([block(63,'b')]);
   expect(readStreamManifest(sql,'clip','AFP_Resource',0,0).version).toBeGreaterThan(2);
   ns.remove('clip');expect([...ns.readOwnersForObjectKey(block(63,'b').objectKey)]).toEqual([]);
   expect(sn.streamManifestAt('inherited','clip','AFP_Resource',63*BS,BS)?.blocks).toEqual([block(63,'b')]);
   sn.deleteSnapshot('inherited');sn.deleteSnapshot('new');
   expect(sql.exec('SELECT * FROM block_refs WHERE refcount!=0;').toArray()).toEqual([]);
  });
 });
 it('backs up live, retained, and snapshot stream references and refuses missing object receipts',async()=>{
  await stores((sql,ns,sn,state)=>{
   commitStreamDelta(sql,'clip','AFP_Resource',delta(BS,0,[block(0)]),ns.nextSeq());sn.create({id:'s'});
   commitStreamDelta(sql,'clip','AFP_Resource',delta(BS,1,[block(0,'b')]),ns.nextSeq());
   const b=new BackupState(state.storage,{BACKUP_MODE:'export'},'filespace');b.initialize();b.freeze({backupId:'stream-backup',mode:'export'});
   expect(b.describe().tables.map(t=>t.name)).toContain('snapshot_stream_blocks');
   expect(b.objectsPage({backupId:'stream-backup'}).entries.map(o=>o.key).sort()).toEqual([block(0).objectKey,block(0,'b').objectKey].sort());
  });
 });
 it('enforces actual gateway lease/CAS, returns legacy headers and prevents old client truncation',async()=>{
  const orgId=`stream-manifest-${crypto.randomUUID()}`,owner=await seedOwnerFixture(orgId),spaceId='s';
  const auth={authorization:`Bearer ${owner.token}`,'content-type':'application/json'};
  expect((await SELF.fetch(`https://test/v1/orgs/${orgId}/spaces`,{method:'POST',headers:auth,body:JSON.stringify({spaceId,name:'S',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''})})).status).toBe(201);
  const fs=e.FILESPACE.getByName(filespaceDoName(orgId,spaceId)),res=await fs.createItem('root','clip',false,0);if(!('item'in res))throw Error('fixture');
  const principal={type:'user' as const,id:owner.userId,orgRole:'owner' as const},item=res.item.id,url=`https://test/v1/filespaces/s/items/${item}/streams/AFP_Resource`;
  await fs.putStreamFor(principal,item,'AFP_Resource',new Uint8Array([1,2]),2);
  expect(await(await SELF.fetch(url+'/manifest',{headers:auth})).json()).toMatchObject({legacy:true,version:1,size:2});
  const lease=await fs.acquireLock(item,owner.userId,60000);const fence=lease.fence!;
  const b={...block(0),objectKey:`blocks/${filespaceDoName(orgId,spaceId)}/${'a'.repeat(64)}`},body={...delta(BS,1,[b]),fence};
  expect((await SELF.fetch(url+'/manifest',{method:'PUT',headers:auth,body:JSON.stringify({...body,fence:fence+1})})).status).toBe(409);
  const response=await SELF.fetch(url+'/manifest',{method:'PUT',headers:auth,body:JSON.stringify(body)});expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({legacy:false,size:BS,version:2});
  expect((await SELF.fetch(url,{headers:auth})).status).toBe(409);
  expect((await SELF.fetch(url,{method:'PUT',headers:auth,body:new Uint8Array([8])})).status).toBe(409);
  expect((await fs.streamManifestFor(principal,item,'AFP_Resource'))?.size).toBe(BS);
  expect((await SELF.fetch(url+'/manifest?length=999999999',{headers:auth})).status).toBe(400);
 });
 it('accepts only an exact lost-reply retry and rolls back a failed chunk replacement',async()=>{
  await stores((sql,ns,_sn,state)=>{
   const commit=(d:StreamDelta)=>state.storage.transactionSync(()=>commitStreamDelta(sql,'clip','AFP_Resource',d,ns.nextSeq()));
   const original=delta(2*BS,0,[block(0),block(1,'b')]);commit(original);
   const change=delta(2*BS,1,[block(0,'c')]);const result=commit(change);
   expect(commit(change)).toEqual(result);
   expect(()=>commit(delta(2*BS,1,[]))).toThrow('version conflict');
   expect(()=>commit(delta(2*BS,1,[block(1,'b')]))).toThrow('version conflict');
   const before=readStreamManifest(sql,'clip','AFP_Resource');
   sql.exec(`CREATE TRIGGER stream_fail BEFORE INSERT ON stream_blocks WHEN NEW.block_hash='${'d'.repeat(64)}' BEGIN SELECT RAISE(ABORT,'injected stream failure'); END;`);
   expect(()=>commit(delta(2*BS,2,[block(0,'d')]))).toThrow('injected stream failure');
   expect(readStreamManifest(sql,'clip','AFP_Resource')).toEqual(before);
   expect(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?;',block(0,'c').hash).one().refcount).toBe(1);
  });
 });
 it('requires verified storage receipts, live ACL and upload provenance at final publication',async()=>{
  const fs=e.FILESPACE.getByName(crypto.randomUUID()),created=await fs.createItem('root','clip',false,0);if(!('item'in created))throw Error('fixture');
  const item=created.item.id,owner={type:'user' as const,id:'owner',orgRole:'owner' as const};
  const lease=await fs.acquireLock(item,'owner',60000),d={...delta(BS,0,[block(0)]),fence:lease.fence!};
  await runInDurableObject(fs,async(instance,state)=>{
   const config=(instance as unknown as {env:Env & {STORAGE_VERIFY_UPLOADS?:string}}).env,prior=config.STORAGE_VERIFY_UPLOADS;
   config.STORAGE_VERIFY_UPLOADS='1';
   try {
    expect(await instance.commitStreamManifestFor(owner,item,'AFP_Resource',d,'owner','storage')).toEqual({error:'objects_unverified'});
    expect(await instance.streamManifestFor(owner,item,'AFP_Resource')).toMatchObject({exists:false});
    state.storage.sql.exec(`INSERT INTO verified_objects(storage_identity,object_key,block_hash,ciphertext_size,plaintext_size,verified_at) VALUES(?,?,?,?,?,0);`,'storage',block(0).objectKey,block(0).hash,BS+69,BS);
    expect(await instance.commitStreamManifestFor(owner,item,'AFP_Resource',d,'owner','wrong-storage')).toEqual({error:'objects_unverified'});
    expect(await instance.commitStreamManifestFor(owner,item,'AFP_Resource',d,'owner','storage')).toMatchObject({version:1});
   } finally {config.STORAGE_VERIFY_UPLOADS=prior;}
  });
  const second=await fs.createItem('root','second',false,0);if(!('item'in second))throw Error('fixture');
  const writer={type:'user' as const,id:'writer',orgRole:'standard' as const};
  await fs.grantAccess({spaceId:'space',inodeId:second.item.id,principalType:'user',principalId:'writer',level:'edit'},'owner');
  const writerLease=await fs.acquireLock(second.item.id,'writer',60000);
  expect(await fs.commitStreamManifestFor(writer,second.item.id,'fork',{...d,expectedVersion:0,fence:writerLease.fence!},'writer')).toEqual({error:'forbidden'});
  const unknown={...delta(BS,0,[block(0,'f')]),fence:writerLease.fence!};
  expect(await fs.commitStreamManifestFor(writer,second.item.id,'fork',unknown,'writer')).toEqual({error:'forbidden'});
  expect(await fs.prepareObjectUpload(writer,block(0,'f').objectKey,second.item.id)).toEqual({inodeId:second.item.id,error:null});
  expect(await fs.commitStreamManifestFor(writer,second.item.id,'fork',unknown,'writer')).toMatchObject({version:1});
  await fs.revokeAccess(second.item.id,'user','writer');
  expect(await fs.streamManifestFor(writer,second.item.id,'fork')).toBeNull();
  expect(await fs.commitStreamManifestFor(writer,second.item.id,'fork',{...unknown,expectedVersion:1,blocks:[]},'writer')).toEqual({error:'forbidden'});
 });
 it('preserves the frozen/current permission intersection for stream objects and denies revoked readers',async()=>{
  const fs=e.FILESPACE.getByName(crypto.randomUUID());
  const owner={type:'user' as const,id:'owner',orgRole:'owner' as const},reader={type:'user' as const,id:'reader',orgRole:'standard' as const};
  const created=await fs.createItem('root','clip',false,0);if(!('item'in created))throw Error('fixture');const item=created.item.id;
  const lease=await fs.acquireLock(item,'owner',60000);
  await fs.commitStreamManifestFor(owner,item,'fork',{...delta(BS,0,[block(0)]),fence:lease.fence!},'owner');
  await fs.createSnapshotFor(owner,{id:'frozen',scope:'root'});
  await fs.grantAccess({spaceId:'space',inodeId:'root',principalType:'user',principalId:'reader',level:'read'},'owner');
  expect(await fs.snapshotStreamManifestFor(reader,'frozen',item,'fork')).toMatchObject({version:1,blocks:[block(0)]});
  expect(await fs.checkSnapshotObjectReadsFor(reader,'frozen',item,[block(0).objectKey])).toEqual([null]);
  expect(await fs.checkSnapshotObjectReadsFor(reader,'frozen',item,[block(0,'b').objectKey])).toEqual(['object_not_in_snapshot']);
  await fs.revokeAccess('root','user','reader');
  expect(await fs.snapshotStreamManifestFor(reader,'frozen',item,'fork')).toBeNull();
  expect((await fs.checkSnapshotObjectReadsFor(reader,'frozen',item,[block(0).objectKey]))[0]).not.toBeNull();
 });
 it('restores encrypted stream metadata only after every live and historical payload is verified',async()=>{
  const source=e.FILESPACE.getByName(crypto.randomUUID()),target=e.FILESPACE.getByName(crypto.randomUUID()),backupId='fork-roundtrip';
  const archive=await runInDurableObject(source,(_i,state)=>{
   const sql=state.storage.sql,ns=new NamespaceStore(sql),sn=new SnapshotStore(sql,()=>ns.currentSeq(),ns);ns.put('root','clip',false,0,{id:'clip'});
   commitStreamDelta(sql,'clip','fork',delta(BS,0,[block(0)]),ns.nextSeq());sn.create({id:'old'});
   commitStreamDelta(sql,'clip','fork',delta(64*BS,1,[block(63,'b')]),ns.nextSeq());
   const b=new BackupState(state.storage,{BACKUP_MODE:'export'},'filespace');b.initialize();b.freeze({backupId,mode:'export'});
   const manifest=b.describe(),pages:BackupPage[]=[];
   for(const table of manifest.tables){let afterRowId:number|undefined;do{const page=b.exportPage({backupId,table:table.name,afterRowId});pages.push(page);afterRowId=page.nextRowId??undefined;}while(afterRowId!==undefined);}
   return{manifest,pages};
  });
  await runInDurableObject(target,(_i,state)=>{
   state.storage.sql.exec(`DELETE FROM items WHERE id!='root';`);state.storage.sql.exec(`UPDATE items SET version=1,created_seq=1,updated_seq=1 WHERE id='root'; UPDATE meta SET value=1 WHERE key='seq';`);
   const b=new BackupState(state.storage,{BACKUP_MODE:'restore'},'filespace');b.initialize();b.freeze({backupId,mode:'restore'});b.restoreBegin({backupId,manifest:archive.manifest});
   archive.pages.forEach((page,pageIndex)=>b.restorePage({...page,pageIndex,backupId}));
   expect(()=>b.verifyObjects({backupId,expectedCount:0})).toThrow('referenced_object_missing');
   const entries=[block(0),block(63,'b')].map(v=>({kind:'data' as const,key:v.objectKey,sha256:v.hash,bytes:v.length+69}));
   b.expectObjects({backupId,pageIndex:0,entries});entries.forEach(v=>b.recordObject({backupId,...v}));
   b.validateCatalog({backupId,organizations:['org'],orgId:'org'});b.restoreCommit({backupId,pageCount:archive.pages.length});
   expect(readStreamManifest(state.storage.sql,'clip','fork',63*BS,BS)).toMatchObject({size:64*BS,blocks:[block(63,'b')]});
   const ns=new NamespaceStore(state.storage.sql),sn=new SnapshotStore(state.storage.sql,()=>ns.currentSeq(),ns);
   expect(sn.streamManifestAt('old','clip','fork')).toMatchObject({size:BS,blocks:[block(0)]});
  });
 });

 it('rolls back actual snapshot create and restore after a stream-storage failure',async()=>{
  const fs=e.FILESPACE.getByName(crypto.randomUUID()),created=await fs.createItem('root','clip',false,0);if(!('item'in created))throw Error('fixture');
  const item=created.item.id,owner={type:'user' as const,id:'owner',orgRole:'owner' as const},lease=await fs.acquireLock(item,'owner',60000);
  await fs.commitStreamManifestFor(owner,item,'fork',{...delta(BS,0,[block(0)]),fence:lease.fence!},'owner');
  await runInDurableObject(fs,async(instance,state)=>{
   state.storage.sql.exec(`CREATE TRIGGER fail_snapshot_stream BEFORE INSERT ON snapshot_stream_blocks BEGIN SELECT RAISE(ABORT,'snapshot injected failure'); END;`);
   let failed=false;try{await instance.createSnapshotFor(owner,{id:'broken'});}catch{failed=true;}expect(failed).toBe(true);
   expect(state.storage.sql.exec(`SELECT * FROM snapshots WHERE id='broken';`).toArray()).toEqual([]);
   expect(state.storage.sql.exec(`SELECT * FROM snapshot_items WHERE snapshot_id='broken';`).toArray()).toEqual([]);
   expect(state.storage.sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?;',block(0).hash).one().refcount).toBe(1);
   state.storage.sql.exec(`DROP TRIGGER fail_snapshot_stream;`);
  });
  await fs.createSnapshotFor(owner,{id:'good'});
  await fs.commitStreamManifestFor(owner,item,'fork',{...delta(BS,1,[block(0,'b')]),fence:lease.fence!},'owner');
  const beforeItem=await fs.getItem(item),beforeStream=await fs.streamManifestFor(owner,item,'fork');
  await runInDurableObject(fs,async(instance,state)=>{
   const beforeRefs=state.storage.sql.exec('SELECT * FROM block_refs ORDER BY block_hash;').toArray(),beforeSeq=state.storage.sql.exec(`SELECT value FROM meta WHERE key='seq';`).one().value;
   state.storage.sql.exec(`CREATE TRIGGER fail_restore_stream BEFORE INSERT ON stream_blocks WHEN NEW.block_hash='${'a'.repeat(64)}' BEGIN SELECT RAISE(ABORT,'restore injected failure'); END;`);
   let failed=false;try{await instance.restoreSnapshot('good',item,{requesterOwner:'owner',principal:owner});}catch{failed=true;}expect(failed).toBe(true);
   expect(state.storage.sql.exec('SELECT * FROM block_refs ORDER BY block_hash;').toArray()).toEqual(beforeRefs);
   expect(state.storage.sql.exec(`SELECT value FROM meta WHERE key='seq';`).one().value).toBe(beforeSeq);
  });
  expect(await fs.getItem(item)).toEqual(beforeItem);expect(await fs.streamManifestFor(owner,item,'fork')).toEqual(beforeStream);
 });

 it('bounds a single-chunk delta to changed references even in a large fork',async()=>{
  await stores((sql,ns,_sn,state)=>{
   sql.exec(`INSERT INTO item_streams(item_id,name,size,data,updated_seq,storage_kind,version) VALUES('clip','fork',?,X'',1,'blocks',1);`,10000*BS);
   sql.exec(`WITH RECURSIVE n(x) AS(SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<9999)
     INSERT INTO stream_blocks SELECT 'clip','fork',x,printf('%064x',x),'blocks/org::space/'||printf('%064x',x),1048576 FROM n;`);
   sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount) SELECT block_hash,object_key,1 FROM stream_blocks;`);
   sql.exec(`INSERT INTO known_objects SELECT object_key,block_hash FROM stream_blocks;`);
   const cursors:{readonly rowsRead:number}[]=[],counted={exec:(...args:Parameters<SqlStorage['exec']>)=>{const cursor=sql.exec(...args);cursors.push(cursor);return cursor;}} as SqlStorage;
   state.storage.transactionSync(()=>commitStreamDelta(counted,'clip','fork',delta(10000*BS,1,[block(5000,'f')]),ns.nextSeq()));
   const reads=cursors.reduce((sum,c)=>sum+c.rowsRead,0);
   expect(reads).toBeLessThan(1000);
  });
 });

});
