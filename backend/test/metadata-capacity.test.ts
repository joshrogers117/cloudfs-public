// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { MetadataCapacity, isMetadataCapacityError } from '../src/metadata/capacity';
import { seedOwnerFixture } from './setup-fixture';
import { filespaceDoName } from '../src/security/auth';
const bindings=env as Env;
describe('filespace metadata capacity',()=>{
 it('reports warning/admission headroom and validates operator thresholds',async()=>{
  await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()),(_instance,state)=>{
   const used=state.storage.sql.databaseSize;
   const capacity=new MetadataCapacity(state.storage.sql,{METADATA_WARNING_BYTES:String(used),METADATA_ADMISSION_BYTES:String(used+100)});
   expect(capacity.status()).toMatchObject({state:'warning',databaseBytes:used,headroomBytes:100});
   expect(()=>capacity.admit(100)).not.toThrow();expect(()=>capacity.admit(101)).toThrow('metadata_capacity:');
   expect(capacity.contributors().find(c=>c.table==='items')!.rows).toBeGreaterThanOrEqual(1);
   expect(()=>new MetadataCapacity(state.storage.sql,{METADATA_ADMISSION_BYTES:'9999999999'}).status()).toThrow('configuration');
   expect(()=>new MetadataCapacity(state.storage.sql,{METADATA_WARNING_BYTES:'NaN'}).status()).toThrow('configuration');
  });
  expect(isMetadataCapacityError(new Error('SQLITE_FULL: database or disk is full'))).toBe(true);
  expect(isMetadataCapacityError(new Error('unrelated SQL failure'))).toBe(false);
 });
 it('rejects growth before mutation while existing reads, exact retries and deletes remain available',async()=>{
  const fs=bindings.FILESPACE.getByName(crypto.randomUUID()),created=await fs.createItem('root','file',false,0);if(!('item'in created))throw Error('fixture');
  const item=created.item.id,blocks=[{chunkIdx:0,blockIdx:0,blockHash:'a',objectKey:'blocks/a',offset:0,length:1}];
  await fs.setBlockMap(item,blocks,{expectedVersion:created.item.version});
  await runInDurableObject(fs,async(instance,state)=>{
   const config=(instance as unknown as {env:Env}).env,old=config.METADATA_ADMISSION_BYTES;config.METADATA_ADMISSION_BYTES=String(state.storage.sql.databaseSize);
   try {
    const before=await instance.getItem(item);
    expect(await instance.createItem('root','rejected',false,0)).toEqual({capacity:true});
    expect(await instance.getItem(item)).toEqual(before);
    expect(await instance.getBlockMap(item)).toEqual(blocks);
    expect(await instance.setBlockMap(item,blocks,{expectedVersion:created.item.version})).toEqual(before);
    await expect(instance.setBlockMap(item,[],{expectedVersion:before!.version})).rejects.toThrow('metadata_capacity:');
    await instance.deleteItem(item);expect(await instance.getItem(item)).toBeNull();
   } finally {config.METADATA_ADMISSION_BYTES=old;}
  });
 });
 it('maps SQLite full across the RPC boundary to HTTP 507 and keeps capacity reports admin-only',async()=>{
  const org=`capacity-${crypto.randomUUID()}`,owner=await seedOwnerFixture(org),headers={authorization:`Bearer ${owner.token}`,'content-type':'application/json'};
  await SELF.fetch(`https://test/v1/orgs/${org}/spaces`,{method:'POST',headers,body:JSON.stringify({spaceId:'s',name:'S',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''})});
  const fs=bindings.FILESPACE.getByName(filespaceDoName(org,'s'));
  await runInDurableObject(fs,(_instance,state)=>{state.storage.sql.exec("CREATE TRIGGER injected_full BEFORE INSERT ON items BEGIN SELECT RAISE(ABORT,'SQLITE_FULL: database or disk is full'); END;");});
  const response=await SELF.fetch('https://test/v1/filespaces/s/items',{method:'POST',headers,body:JSON.stringify({parent:'root',name:'fail',isDir:false,size:0})});
  expect(response.status).toBe(507);expect(await response.json()).toMatchObject({error:'metadata_capacity'});
  expect((await SELF.fetch('https://test/v1/filespaces/s/capacity?contributors=1',{headers})).status).toBe(200);
  expect(await fs.metadataCapacityFor({type:'user',id:'member',orgRole:'standard'})).toEqual({error:'forbidden'});
 });
});
