// SPDX-License-Identifier: AGPL-3.0-or-later
import { env,runInDurableObject,SELF } from 'cloudflare:test';
import { describe,it,expect } from 'vitest';
import type { Env } from '../src/env';
import { NamespaceStore } from '../src/metadata/namespace';
import { SnapshotStore } from '../src/metadata/snapshots';
import { ReclamationStore,RECLAMATION_GRACE_MS } from '../src/metadata/reclamation';
import { BackupState } from '../src/backup-state';
import { seedOwnerFixture } from './setup-fixture';
import { filespaceDoName,mintToken } from '../src/security/auth';
const bindings=env as Env;
const block=(hash:string)=>({chunkIdx:0,blockIdx:0,blockHash:hash,objectKey:`blocks/org::s/${hash}`,offset:0,length:1});
async function stores(fn:(sql:SqlStorage,ns:NamespaceStore,gc:ReclamationStore,snap:SnapshotStore,state:DurableObjectState)=>void){
 await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),(_instance,state)=>{
  const sql=state.storage.sql,ns=new NamespaceStore(sql);fn(sql,ns,new ReclamationStore(sql),new SnapshotStore(sql,()=>ns.currentSeq(),ns),state);
 });
}
describe('quarantined object reclamation',()=>{
 it('requires a recovered-client watermark and preserves live, retained, snapshot and upload roots',async()=>{
  await stores((sql,ns,gc,snap)=>{
   for(const h of ['live','history','snapshot','claim','upload','free']){ns.put('root',h,false,0,{id:h});ns.setBlockMap(h,[block(h)]);}
   snap.create({id:'protected',scope:'snapshot'});
   ns.setBlockMap('history',[block('history-new')]);
   for(const h of ['snapshot','claim','upload','free'])ns.remove(h);
   sql.exec("INSERT INTO block_upload_claims VALUES(?,?,?,?);",block('claim').objectKey,'claim','user',0); // even expired claims stay protected
   sql.exec("INSERT INTO uploads(upload_id,item_id,key,total_size,part_size,state,created_at,updated_at) VALUES('u','upload',?,1,1,'in_progress',0,0);",block('upload').objectKey);
   expect(gc.report().candidateObjects).toBe(1);
   expect(gc.quarantine(0)).toBe(0);
   const now=Date.now();expect(gc.quarantine(now,now)).toBe(1);expect(gc.due(now)).toEqual([]);
   expect(gc.due(now+RECLAMATION_GRACE_MS).map(t=>t.key)).toEqual([block('free').objectKey]);
   expect(()=>gc.quarantine(now+1,now)).toThrow('watermark');
  });
 });
 it('cancels quarantine on republishing and refuses stale deletion tokens',async()=>{
  await stores((sql,ns,gc,_snap,state)=>{
   ns.put('root','f',false,0,{id:'f'});ns.setBlockMap('f',[block('a')]);ns.remove('f');
   const now=Date.now();gc.quarantine(now,now);const [ticket]=gc.due(now+RECLAMATION_GRACE_MS);
   ns.put('root','second',false,0,{id:'second'});state.storage.transactionSync(()=>ns.setBlockMap('second',[block('a')]));
   expect(gc.begin(ticket,now+RECLAMATION_GRACE_MS)).toBe(false);expect(gc.report().states).toEqual([]);
   ns.remove('second');gc.quarantine(Date.now(),now+RECLAMATION_GRACE_MS);
   expect(gc.begin(ticket,now+2*RECLAMATION_GRACE_MS)).toBe(false);
  });
 });
 it('tombstones before deletion, retries unknown outcomes, and cleans receipts only after success',async()=>{
  await stores((sql,ns,gc,_snap,state)=>{
   ns.put('root','f',false,0,{id:'f'});ns.setBlockMap('f',[block('a')]);ns.remove('f');
   sql.exec('INSERT INTO verified_objects VALUES(?,?,?,?,?,0);','storage',block('a').objectKey,'a',70,1);
   const now=Date.now();gc.quarantine(now,now);const at=now+RECLAMATION_GRACE_MS,[ticket]=gc.due(at);
   expect(state.storage.transactionSync(()=>gc.begin(ticket,at))).toBe(true);
   ns.put('root','new',false,0,{id:'new'});
   expect(()=>state.storage.transactionSync(()=>ns.setBlockMap('new',[block('a')]))).toThrow('object_retired');
   gc.finish(ticket,false,at);expect(gc.report().failures[0].attempts).toBe(1);
   expect(sql.exec('SELECT COUNT(*) AS n FROM verified_objects;').one().n).toBe(1);
   const retry=at+24*60*60*1000;expect(gc.begin(ticket,retry)).toBe(true);gc.finish(ticket,true,retry);
   expect(sql.exec('SELECT COUNT(*) AS n FROM verified_objects;').one().n).toBe(0);
   expect(sql.exec('SELECT COUNT(*) AS n FROM block_refs;').one().n).toBe(0);
   expect(gc.report().states).toEqual([{state:'deleted',objects:1}]);
   expect(()=>sql.exec('INSERT INTO block_upload_claims VALUES(?,?,?,?);',block('a').objectKey,'new','writer',retry+100)).toThrow('object_retired');
   const later=new ReclamationStore(sql);expect(later.due(retry+31*24*60*60*1000)).toEqual([ticket]);
  });
 });
 it('rechecks authoritative references and keeps backup holds and retirement state coherent',async()=>{
  await stores((sql,ns,gc,_snap,state)=>{
   ns.put('root','f',false,0,{id:'f'});ns.setBlockMap('f',[block('a')]);ns.remove('f');
   const now=Date.now();gc.quarantine(now,now);const at=now+RECLAMATION_GRACE_MS,[ticket]=gc.due(at);
   sql.exec('UPDATE block_refs SET refcount=1 WHERE block_hash=?;','a');
   expect(gc.begin(ticket,at)).toBe(false);
   const backup=new BackupState(state.storage,{BACKUP_MODE:'export'},'filespace');backup.initialize();backup.freeze({backupId:'reclamation-backup',mode:'export'});
   expect(backup.describe().tables.map(t=>t.name)).toContain('object_reclamation');
   expect(()=>new ReclamationStore(backup.guardedSQL).quarantine(now)).toThrow('backup');
  });
 });
 it('arms bounded work through the admin API and executes storage deletion only after quarantine is durable',async()=>{
  const org=`reclaim-${crypto.randomUUID()}`,owner=await seedOwnerFixture(org),headers={authorization:`Bearer ${owner.token}`,'content-type':'application/json'};
  await SELF.fetch(`https://test/v1/orgs/${org}/spaces`,{method:'POST',headers,body:JSON.stringify({spaceId:'s',name:'S',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''})});
  const fs=bindings.FILESPACE.getByName(filespaceDoName(org,'s')),key=`blocks/${filespaceDoName(org,'s')}/retired`;
  await runInDurableObject(fs,(_instance,state)=>{
   const ns=new NamespaceStore(state.storage.sql);ns.put('root','f',false,0,{id:'f'});ns.setBlockMap('f',[{...block('retired'),objectKey:key}]);ns.remove('f');
  });
  expect((await SELF.fetch('https://test/v1/filespaces/s/reclamation',{headers})).status).toBe(200);
  const limited=await mintToken(bindings.AUTH_SIGNING_SECRET,{sub:owner.userId,type:'session',orgId:org,scopes:['fs:read','fs:write'],ttlSeconds:900});
  expect((await SELF.fetch('https://test/v1/filespaces/s/reclamation/quarantine',{method:'POST',headers:{...headers,authorization:`Bearer ${limited}`},body:JSON.stringify({recoveredThrough:Date.now()})})).status).toBe(403);
  const result=await SELF.fetch('https://test/v1/filespaces/s/reclamation/quarantine',{method:'POST',headers,body:JSON.stringify({recoveredThrough:Date.now()})});
  expect(result.status).toBe(200);expect(await result.json()).toMatchObject({quarantined:1});
  await runInDurableObject(fs,async(instance,state)=>{
   let requests=0;
   const fetchImpl:typeof fetch=async(_input,init)=>{
    requests++;expect(init?.method).toBe('POST');expect(String(init?.body)).toContain(key);
    expect(state.storage.sql.exec('SELECT state FROM object_reclamation WHERE object_key=?;',key).one().state).toBe('deleting');
    return new Response(`<DeleteResult><Deleted><Key>${key}</Key></Deleted></DeleteResult>`);
   };
   const runner=instance as unknown as {runReclamation(fetchImpl:typeof fetch):Promise<void>};
   await runner.runReclamation(fetchImpl);expect(requests).toBe(0);
   state.storage.sql.exec('UPDATE object_reclamation SET next_at=0;');
   await runner.runReclamation(fetchImpl);expect(requests).toBe(1);
   expect(state.storage.sql.exec('SELECT state FROM object_reclamation;').one().state).toBe('deleted');
   expect(await instance.prepareObjectUpload({type:'user',id:owner.userId,orgRole:'owner'},key)).toMatchObject({error:'object_retired'});
   await state.storage.deleteAlarm();
  });
 });

});
