// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { MAX_STREAM_BODY_BYTES } from '../src/metadata/stream-limits';
import { requestBoundary } from '../src/request-boundary';
import { filespaceDoName } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';
const e=env as Env;
async function fixture() {
 const orgId=`stream-limit-${crypto.randomUUID()}`, owner=await seedOwnerFixture(orgId), spaceId='streams';
 const created=await SELF.fetch(`https://test/v1/orgs/${orgId}/spaces`,{method:'POST',headers:{authorization:`Bearer ${owner.token}`,'content-type':'application/json'},body:JSON.stringify({spaceId,name:'Streams',bucketProvider:'r2',bucketName:'bucket',keyPrefix:''})});
 expect(created.status).toBe(201);
 const fs=e.FILESPACE.getByName(filespaceDoName(orgId,spaceId)), result=await fs.createItem('root','clip.mov',false,0);
 if(!('item' in result))throw new Error('fixture item');
 const principal={type:'user' as const,id:owner.userId,orgRole:'owner' as const};
 const url=`https://test/v1/filespaces/${spaceId}/items/${result.item.id}/streams/AFP_Resource`;
 return{fs,item:result.item,principal,url,headers:{authorization:`Bearer ${owner.token}`,'content-type':'application/octet-stream'}};
}
describe('named-stream storage ceiling',()=>{
 it('rejects 2MiB at the request boundary before routing or touching SQL',async()=>{
  let routed=false;
  const response=await requestBoundary(new Request('https://test/v1/filespaces/f/items/i/streams/AFP_Resource',{method:'PUT',body:new Uint8Array(2*1024*1024)}),async()=>{routed=true;return new Response('unexpected');});
  expect(response.status).toBe(413);expect(await response.json()).toEqual({error:'body_too_large',maxBytes:MAX_STREAM_BODY_BYTES});expect(routed).toBe(false);
 });
 it('returns413 through the gateway and a typed directRPC error without replacing the existing stream',async()=>{
  const f=await fixture(),original=new Uint8Array([1,2,3,4]);
  expect(await f.fs.putStreamFor(f.principal,f.item.id,'AFP_Resource',original,original.length)).toEqual({size:original.length});
  const before=await f.fs.getItem(f.item.id),oversized=new Uint8Array(2*1024*1024);
  const response=await SELF.fetch(f.url,{method:'PUT',headers:f.headers,body:oversized});expect(response.status).toBe(413);
  expect(await f.fs.putStreamFor(f.principal,f.item.id,'AFP_Resource',oversized,oversized.length)).toEqual({tooLarge:true,maxBytes:MAX_STREAM_BODY_BYTES});
  expect(await f.fs.getStreamFor(f.principal,f.item.id,'AFP_Resource')).toEqual(original);expect((await f.fs.getItem(f.item.id))?.updatedSeq).toBe(before?.updatedSeq);
 });
 it('persists and decrypts a 1.4MiB encrypted stream exactly',async()=>{
  const f=await fixture(),plain=new Uint8Array(Math.floor(1.4*1024*1024));for(let i=0;i<plain.length;i++)plain[i]=i%251;
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']) as CryptoKey,iv=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,plain));
  const response=await SELF.fetch(`${f.url}?size=${plain.length}`,{method:'PUT',headers:f.headers,body:encrypted});expect(response.status).toBe(200);
  expect(await response.json()).toEqual({size:plain.length});
  const read=await SELF.fetch(f.url,{headers:f.headers});expect(read.status).toBe(200);
  const bytes=await read.arrayBuffer();expect(new Uint8Array(bytes).every((byte,index)=>byte===encrypted[index])).toBe(true);expect(bytes.byteLength).toBe(encrypted.byteLength);
  const recovered=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv},key,bytes));expect(recovered.length).toBe(plain.length);expect(recovered.every((byte,index)=>byte===plain[index])).toBe(true);
 });
});
