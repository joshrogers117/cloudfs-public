// SPDX-License-Identifier: AGPL-3.0-or-later
import {env,runInDurableObject} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
import type {Env} from '../src/env';
import {NamespaceStore} from '../src/metadata/namespace';
const owner={type:'user' as const,id:'owner',orgRole:'owner' as const},bs=1<<20;
const block=(i:number)=>({chunkIdx:i,blockIdx:0,blockHash:'a'.repeat(64),objectKey:'blocks/s/a',offset:i*bs,length:bs});
describe('demand-driven manifest extents',()=>{
 it('seeks to the tail of a 64 GiB file with bounded SQL work and the absolute encryption index',async()=>{
  await runInDurableObject((env as Env).FILESPACE.getByName(crypto.randomUUID()),async(instance,state)=>{
   const ns=new NamespaceStore(state.storage.sql);ns.put('root','large',false,0,{id:'file'});
   ns.setBlockMap('file',Array.from({length:65536},(_,i)=>block(i)),{blockSize:bs});
   const version=ns.getItem('file')!.contentVersion;
   const access=instance as unknown as {sql:SqlStorage},original=access.sql,cursors:SqlStorageCursor<Record<string,SqlStorageValue>>[]=[];
   access.sql=new Proxy(original,{get(t,k){if(k==='exec')return(...args:Parameters<SqlStorage['exec']>)=>{const c=t.exec(...args);cursors.push(c);return c};return Reflect.get(t,k,t)}});
   try {
    const result=await instance.fileManifestExtentFor(owner,'file',65535*bs+17,64,version);
    expect(result).toMatchObject({format:2,firstBlockIndex:65535,blocks:[block(65535)],nextOffset:null});
    expect(cursors.reduce((n,c)=>n+c.rowsRead,0)).toBeLessThan(20);
   }finally{access.sql=original}
   expect(await instance.fileManifestExtentFor(owner,'file',0,1,'stale')).toMatchObject({error:'version_conflict'});
   expect(await instance.fileManifestExtentFor({...owner,orgRole:'standard'},'file',0,1,version)).toEqual({error:'forbidden'});
   expect(await instance.fileManifestExtentFor(owner,'file',65536*bs,1,version)).toMatchObject({blocks:[]});
   expect(await instance.fileManifestExtentFor(owner,'file',0,33*bs,version)).toEqual({error:'invalid_range'});
  });
 });
 it('bounds tiny-block pages, includes crossing boundaries, and fails on missing extents',async()=>{
  await runInDurableObject((env as Env).FILESPACE.getByName(crypto.randomUUID()),async(instance,state)=>{
   const ns=new NamespaceStore(state.storage.sql);ns.put('root','legacy',false,0,{id:'file'});
   ns.setBlockMap('file',Array.from({length:2000},(_,i)=>({...block(i),blockIdx:9,offset:i*3,length:3})));
   const v=ns.getItem('file')!.contentVersion;
   expect(await instance.fileManifestExtentFor(owner,'file',4,4000,v)).toMatchObject({firstBlockIndex:1,nextOffset:3075});
   const tail=await instance.fileManifestExtentFor(owner,'file',5998,2,v);
   expect(tail).toMatchObject({firstBlockIndex:1999,blocks:[{offset:5997,length:3}]});
   state.storage.sql.exec('DELETE FROM blocks WHERE item_id=? AND offset=?;','file',5997);
   expect(await instance.fileManifestExtentFor(owner,'file',5998,2,v)).toEqual({error:'invalid_manifest'});
  });
 });
});
