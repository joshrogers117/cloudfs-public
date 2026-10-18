// SPDX-License-Identifier: AGPL-3.0-or-later
import { encryptedBlockFixture } from './encrypted-block-fixture';
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import type { Env } from '../src/env';
import { probeStorageIntegrity, storageIdentity, verifyStorageObjects } from '../src/storage-object-verifier';
import { requiredUploadHeaders, type StorageConfig } from '../src/storage';
const hex = (bytes:Uint8Array) => [...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');
const bytes = encryptedBlockFixture(), hash = hex(sha256(bytes));
const block = {objectKey:`blocks/test/${hash}`,blockHash:hash,length:4};
const cfg: StorageConfig = {endpoint:'https://verification.test',bucket:'bucket',region:'auto',accessKeyId:'test',secretAccessKey:'test-not-secret'};
const headers = {'content-length':'73','x-amz-checksum-sha256':requiredUploadHeaders(block.objectKey)['x-amz-checksum-sha256']};
function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return {promise, release};
}
const indexedBlocks = (count:number) => Array.from({length:count},(_,index)=>({...block,objectKey:`blocks/test/${index}/${hash}`}));
const objectIndex = (input:RequestInfo | URL) => Number(new URL(String(input)).pathname.split('/').at(-2));
describe('object-store durability verification',()=>{
  it('rejects hash-valid plaintext and malformed envelopes on both checksum and streaming paths',async()=>{
    const raw = new Uint8Array(100).fill(65);
    const badFlags = encryptedBlockFixture(); badFlags[4] = 2;
    const badLength = encryptedBlockFixture(); new DataView(badLength.buffer).setUint32(5,3);
    const shortened = encryptedBlockFixture().slice(0,-1);
    for (const [payload,length] of [[raw,100],[badFlags,4],[badLength,4],[shortened,4]] as const) {
      const digest = hex(sha256(payload)), input = {objectKey:`blocks/test/${digest}`,blockHash:digest,length};
      for (const providerChecksum of [true,false]) {
        const responseHeaders:Record<string,string> = {'content-length':String(payload.length)};
        if (providerChecksum) responseHeaders['x-amz-checksum-sha256'] = btoa(String.fromCharCode(...sha256(payload)));
        await expect(verifyStorageObjects(cfg,[input],async(_url,init)=>init?.method==='HEAD'
          ? new Response(null,{headers:responseHeaders}) : new Response(payload))).rejects.toBeDefined();
      }
    }
  });
  it('checks a conditional nine-byte range, accepts both envelope generations, and cancels an ignored range',async()=>{
    for (const magic of ['CFB2','CFB3'] as const) {
      const payload=encryptedBlockFixture(4,magic), digest=hex(sha256(payload));
      const input={...block,objectKey:`blocks/test/${digest}`,blockHash:digest};
      let canceled=false;
      await expect(verifyStorageObjects(cfg,[input],async(_url,init)=>{
        if(init?.method==='HEAD')return new Response(null,{headers:{'content-length':'73',etag:'"version-one"',
          'x-amz-checksum-sha256':btoa(String.fromCharCode(...sha256(payload)))}});
        const h=new Headers(init?.headers);
        expect(h.get('range')).toBe('bytes=0-8');expect(h.get('if-match')).toBe('"version-one"');
        return new Response(new ReadableStream({start(c){c.enqueue(payload);},cancel(){canceled=true;}}));
      })).resolves.toHaveLength(1);
      expect(canceled).toBe(true);
    }
    for(const response of [new Response(bytes.slice(0,8)),new Response(bytes.slice(0,9),{status:206,headers:{'content-range':'bytes 1-9/73'}}),
      new Response(null,{status:412})]) {
      await expect(verifyStorageObjects(cfg,[block],async(_url,init)=>init?.method==='HEAD'
        ?new Response(null,{headers}):response)).rejects.toBeDefined();
    }
  });
  it('reverifies receipts issued before envelope validation without invalidating the old receipt row',async()=>{
    const stub=(env as Env).FILESPACE.getByName(`verify-upgrade-${crypto.randomUUID()}`);
    const oldIdentity=JSON.stringify([cfg.endpoint,cfg.bucket,cfg.region,true]);
    const manifest=[{...block,chunkIdx:0,blockIdx:0,offset:0}];
    await stub.recordVerifiedObjects([{...block,ciphertextSize:73}],oldIdentity);
    expect(await stub.unverifiedObjects(manifest,storageIdentity(cfg))).toHaveLength(1);
    await runInDurableObject(stub,async(instance)=>{
      const original=globalThis.fetch;
      globalThis.fetch=async(_url,init)=>init?.method==='HEAD'?new Response(null,{headers}):new Response(bytes);
      try {expect(await instance.verifyObjects([block],cfg)).toEqual({verified:1});} finally {globalThis.fetch=original;}
    });
    expect(await stub.unverifiedObjects(manifest,storageIdentity(cfg))).toEqual([]);
    expect(await stub.unverifiedObjects(manifest,oldIdentity)).toEqual([]);
  });
  it('checks server SHA-256 and byte bounds; missing, truncated, untrusted checksum and failed HEAD never pass',async()=>{
    const valid = await verifyStorageObjects(cfg,[block],async(_url,init)=>init?.method==='GET'?new Response(bytes):new Response(null,{headers}));
    expect(valid[0].ciphertextSize).toBe(73);
    for(const response of [new Response(null,{status:404}),new Response(null,{status:503}),new Response(null,{headers:{...headers,'content-length':'0'}}),
      new Response(null,{headers:{...headers,'content-length':'74'}}),new Response(null,{headers:{...headers,'x-amz-checksum-sha256':btoa('wrong')}})]) {
      let failed=false;try{await verifyStorageObjects(cfg,[block],async()=>response);}catch{failed=true;}expect(failed).toBe(true);
    }
  });
  it('hashes checksumless legacy ciphertext incrementally and rejects wrong or changed bytes',async()=>{
    for(const [payload,accept] of [[bytes,true],[new Uint8Array([1,2,3,5]),false],[new Uint8Array([1,2]),false],[new Uint8Array(5),false]] as const) {
      let calls=0,failed=false;
      try {await verifyStorageObjects(cfg,[block],async(_url,init)=>{
        calls++;return init?.method==='HEAD'?new Response(null,{headers:{'content-length':'73'}}):new Response(payload);
      });}catch{failed=true;}
      expect(calls).toBe(2);expect(failed).toBe(!accept);
    }
  });
  it('releases a failed legacy GET body before returning a verification failure',async()=>{
    let canceled=false;
    await expect(verifyStorageObjects(cfg,[block],async(_url,init)=>init?.method==='HEAD'
      ? new Response(null,{headers:{'content-length':'73'}})
      : new Response(new ReadableStream({cancel(){canceled=true;}}),{status:503})
    )).rejects.toMatchObject({reason:'object verification GET failed'});
    expect(canceled).toBe(true);
  });
  it('keeps at most six concurrent object requests and rejects oversized batches before network I/O',async()=>{
    let active=0,peak=0,calls=0;
    const fetcher:typeof fetch=async(_url,init)=>{if(init?.method==='GET')return new Response(bytes);active++;calls++;peak=Math.max(peak,active);await new Promise(resolve=>setTimeout(resolve,1));active--;return new Response(null,{headers});};
    await verifyStorageObjects(cfg,Array.from({length:25},()=>block),fetcher);
    expect(peak).toBe(6);expect(calls).toBe(25);
    try{await verifyStorageObjects(cfg,Array.from({length:129},()=>block),fetcher);}catch{/* expected */}
    expect(calls).toBe(25);
  });
  it('refills each free slot while an earlier object is slow and returns the original object order',async()=>{
    const blocks=indexedBlocks(25), gates=blocks.map(()=>gate());
    let active=0,peak=0,started=0,finished=0,settled=false;
    const work=verifyStorageObjects(cfg,blocks,async(input,init)=>{
      if(init?.method==='GET')return new Response(bytes);
      const index=objectIndex(input);started++;active++;peak=Math.max(peak,active);
      await gates[index].promise;active--;finished++;
      return new Response(null,{headers});
    }).finally(()=>{settled=true;});
    try {
      await expect.poll(()=>started).toBe(6);
      gates[1].release();
      // This seventh request cannot begin with the old six-request wave barrier.
      await expect.poll(()=>started).toBe(7);
      expect(active).toBe(6);
      for(let index=2;index<gates.length;index++)gates[index].release();
      await expect.poll(()=>finished).toBe(24);
      expect(started).toBe(25);expect(settled).toBe(false);expect(peak).toBe(6);
      gates[0].release();
      expect((await work).map(value=>value.objectKey)).toEqual(blocks.map(value=>value.objectKey));
    } finally {for(const held of gates)held.release();await work.catch(()=>{});}
  });
  it('stops admission after failure and drains all started verifications before rejecting',async()=>{
    const blocks=indexedBlocks(25), gates=blocks.map(()=>gate());
    let started=0,active=0,settled=false;
    const work=verifyStorageObjects(cfg,blocks,async(input,init)=>{
      if(init?.method==='GET')return new Response(bytes);
      const index=objectIndex(input);started++;active++;
      await gates[index].promise;active--;
      return index===0?new Response(null,{status:404}):new Response(null,{headers});
    }).then(value=>({value}),error=>({error})).finally(()=>{settled=true;});
    try {
      await expect.poll(()=>started).toBe(6);
      gates[0].release();
      // A macrotask barrier lets the failed response traverse the promise chain;
      // the other five requests stay explicitly held, not delayed by a timer.
      await new Promise(resolve=>setTimeout(resolve,0));
      expect(active).toBe(5);expect(settled).toBe(false);expect(started).toBe(6);
      for(let index=1;index<6;index++)gates[index].release();
      expect(await work).toMatchObject({error:{reason:'object missing'}});
      expect(active).toBe(0);expect(started).toBe(6);
    } finally {for(const held of gates)held.release();await work;}
  });
  it('retains each slot through legacy streaming verification and signs HEAD and GET with temporary credentials',async()=>{
    const blocks=indexedBlocks(13), gates=blocks.map(()=>gate());
    let heads=0,gets=0,activeBodies=0,peakBodies=0;
    const work=verifyStorageObjects({...cfg,sessionToken:'temporary-verifier-token'},blocks,async(input,init)=>{
      expect(new Headers(init?.headers).get('x-amz-security-token')).toBe('temporary-verifier-token');
      const index=objectIndex(input);
      if(init?.method==='HEAD'){heads++;return new Response(null,{headers:{'content-length':'73'}});}
      expect(init?.method).toBe('GET');gets++;activeBodies++;peakBodies=Math.max(peakBodies,activeBodies);
      return new Response(new ReadableStream<Uint8Array>({async pull(controller){
        await gates[index].promise;controller.enqueue(bytes);controller.close();activeBodies--;
      }},{highWaterMark:0}));
    });
    try {
      await expect.poll(()=>gets).toBe(6);
      expect(heads).toBe(6);expect(activeBodies).toBe(6);
      gates[1].release();
      await expect.poll(()=>gets).toBe(7);
      expect(heads).toBe(7);expect(activeBodies).toBe(6);
      for(const held of gates)held.release();
      expect(await work).toHaveLength(13);
      expect(peakBodies).toBe(6);expect(activeBodies).toBe(0);expect(heads).toBe(13);expect(gets).toBe(13);
    } finally {for(const held of gates)held.release();await work.catch(()=>{});}
  });
  it('persists receipts only after verified bytes and binds them to storage, hash, and logical length',async()=>{
    const stub=(env as Env).FILESPACE.getByName(`verify-${crypto.randomUUID()}`), identity=storageIdentity(cfg);
    const manifest=[{...block,chunkIdx:0,blockIdx:0,offset:0}];
    expect(await stub.unverifiedObjects(manifest,identity)).toHaveLength(1);
    await runInDurableObject(stub,async(instance)=>{
      const original=globalThis.fetch; globalThis.fetch=async(_url,init)=>init?.method==='GET'?new Response(bytes):new Response(null,{headers});
      try {
        expect(await instance.verifyObjects([block],cfg)).toEqual({verified:1});
        expect(await instance.verifyObjects([{...block,length:5}],cfg)).toMatchObject({error:'object_verification_failed'});
      } finally {globalThis.fetch=original;}
    });
    expect(await stub.unverifiedObjects(manifest,identity)).toEqual([]);
    expect(await stub.unverifiedObjects(manifest,storageIdentity({...cfg,bucket:'another'}))).toHaveLength(1);
    await runInDurableObject(stub,async(instance)=>{
      let rejected=false;
      try {await instance.unverifiedObjects([{...manifest[0],length:5}],identity);}catch{rejected=true;}
      expect(rejected).toBe(true);
    });
    await runInDurableObject(stub,(_instance,state)=>expect(Number(state.storage.sql.exec('SELECT ciphertext_size FROM verified_objects;').one().ciphertext_size)).toBe(73));
  });
  it('interleaved verification cannot overwrite the first immutable receipt',async()=>{
    const stub=(env as Env).FILESPACE.getByName(`verify-race-${crypto.randomUUID()}`);
    await runInDurableObject(stub,async(instance,state)=>{
      let enter!:()=>void,release!:()=>void,calls=0;
      const entered=new Promise<void>(resolve=>{enter=resolve;}),held=new Promise<void>(resolve=>{release=resolve;});
      const original=globalThis.fetch;
      globalThis.fetch=async(_url,init)=>{if(init?.method==='GET')return new Response(bytes);if(calls++===0){enter();await held;}return new Response(null,{headers});};
      try {
        const late=instance.verifyObjects([{...block,length:5}],cfg);
        await entered;
        expect(await instance.verifyObjects([block],cfg)).toEqual({verified:1});
        release();
        expect(await late).toMatchObject({error:'object_verification_failed'});
        expect(Number(state.storage.sql.exec('SELECT plaintext_size FROM verified_objects;').one().plaintext_size)).toBe(4);
      }finally{release();globalThis.fetch=original;}
    });
  });
  it('a failed verification batch publishes no partial receipt or manifest',async()=>{
    const stub=(env as Env).FILESPACE.getByName(`verify-fail-${crypto.randomUUID()}`);
    await runInDurableObject(stub,async(instance)=>{
      let verified=0;
      const original=globalThis.fetch;
      globalThis.fetch=async(input,init)=>{
        if(init?.method==='GET')return new Response(bytes);
        if(objectIndex(input)===7)return new Response(null,{status:404});
        verified++;return new Response(null,{headers});
      };
      try {
        expect(await instance.verifyObjects(indexedBlocks(13),cfg)).toMatchObject({error:'object_verification_failed'});
        expect(verified).toBeGreaterThanOrEqual(6);
      } finally {globalThis.fetch=original;}
    });
    await runInDurableObject(stub,(_instance,state)=>expect(state.storage.sql.exec('SELECT * FROM verified_objects;').toArray()).toEqual([]));
  });
  it('validates trusted receipt batches and rolls back every new row on an immutable conflict',async()=>{
    const stub=(env as Env).FILESPACE.getByName(`receipt-${crypto.randomUUID()}`), identity=storageIdentity(cfg);
    const verified={...block,ciphertextSize:73};
    expect(await stub.recordVerifiedObjects([verified],identity)).toEqual({verified:1});
    const other={...verified,objectKey:`blocks/other/${block.blockHash}`};
    expect(await stub.recordVerifiedObjects([other,{...verified,length:5}],identity)).toMatchObject({error:'object_verification_failed'});
    for(const invalid of [Array(129).fill(verified),[{...other,ciphertextSize:0}],[{...other,ciphertextSize:74}],
      [{...other,blockHash:'invalid'}],[{...other,length:0}]]) {
      expect(await stub.recordVerifiedObjects(invalid,identity)).toMatchObject({error:'object_verification_failed'});
    }
    expect(await stub.recordVerifiedObjects([other],'')).toMatchObject({error:'object_verification_failed'});
    await runInDurableObject(stub,(_instance,state)=>expect(state.storage.sql.exec('SELECT object_key FROM verified_objects;').toArray()).toEqual([{object_key:block.objectKey}]));
    expect(await stub.unverifiedObjects([{...block,chunkIdx:0,blockIdx:0,offset:0}],storageIdentity({...cfg,bucket:'different'}))).toHaveLength(1);
    await stub.markDeleted();
    expect(await stub.recordVerifiedObjects([other],identity)).toMatchObject({error:'object_verification_failed'});
  });
});

describe('storage readiness write throttling',()=>{
  function fixture(stages: Array<Array<number | [number,string]>>) {
    const delays:number[]=[], attempts=[0,0,0], deleted:string[]=[], successfulKeyRequests:string[]=[];
    let stage=0, accepted:Uint8Array|undefined, acceptedChecksum='', heads=0;
    const fetcher:typeof fetch=async(input,init)=>{
      const url=String(input), method=init?.method;
      if(method==='DELETE'){deleted.push(new URL(url).pathname);return new Response(null,{status:204});}
      if(method==='HEAD'){
        heads++;
        return new Response(null,{headers:{'content-length':String(accepted!.length),'x-amz-checksum-sha256':acceptedChecksum}});
      }
      if(method==='GET')return new Response(accepted);
      expect(method).toBe('PUT');
      const current=stage, headers=new Headers(init?.headers), payload=new Uint8Array(init?.body as Uint8Array);
      expect(headers.get('if-none-match')).toBe('*');
      expect(headers.get('x-amz-checksum-sha256')).not.toBeNull();
      if(current===0)expect(btoa(String.fromCharCode(...sha256(payload)))).not.toBe(headers.get('x-amz-checksum-sha256'));
      else {
        successfulKeyRequests.push(url);
        expect(btoa(String.fromCharCode(...sha256(payload)))).toBe(headers.get('x-amz-checksum-sha256'));
      }
      const configured=stages[current][attempts[current]++];
      expect(configured).toBeDefined();
      const [status,retryAfter]=typeof configured==='number'?[configured,undefined]:configured;
      if(status!==429)stage++;
      if(current===1 && status===200){accepted=payload;acceptedChecksum=headers.get('x-amz-checksum-sha256')!;}
      return new Response(null,{status,headers:retryAfter?{'retry-after':retryAfter}:{}});
    };
    return {delays,attempts,deleted,successfulKeyRequests,heads:()=>heads,
      run:()=>probeStorageIntegrity(cfg,'integrity-probe',fetcher,async milliseconds=>{delays.push(milliseconds);})};
  }
  it('retries each throttled PUT with bounded delays and still proves checksum rejection, immutable retry and exact bytes',async()=>{
    const test=fixture([[[429,'0'],400],[[429,'2'],200],[[429,'999'],429,412]]);
    expect(await test.run()).toEqual({ok:true});
    expect(test.attempts).toEqual([2,2,3]);
    expect(test.delays).toEqual([1_000,2_000,3_000,1_000]);
    expect(new Set(test.successfulKeyRequests).size).toBe(1); // Retry exact signed URL/body.
    expect(test.heads()).toBe(1);
    expect(test.deleted).toHaveLength(2);
    expect(new Set(test.deleted).size).toBe(2);
    expect(test.deleted.every(path=>path.startsWith('/bucket/integrity-probe/'))).toBe(true);
  });
  it('requires eventual 412 and fails closed on exhausted throttling or any wrong final retry status',async()=>{
    for(const final of [[429,429,429],[429,200],[429,400],[429,503]]){
      const test=fixture([[400],[200],final]);
      expect(await test.run()).toEqual({ok:false,reason:'storage does not enforce conditional immutable uploads'});
      expect(test.attempts[2]).toBe(final.length);
      expect(test.delays).toEqual(Array(final.length-1).fill(1_000));
      expect(test.heads()).toBe(0);
      expect(test.deleted).toHaveLength(2);
    }
  });
  it('never interprets throttling or an accepted corrupt payload as checksum rejection',async()=>{
    for(const first of [[429,429,429],[429,200],[503]]){
      const test=fixture([first,[200],[412]]);
      expect(await test.run()).toEqual({ok:false,reason:'storage does not reject incorrect signed SHA-256'});
      expect(test.attempts).toEqual([first.length,0,0]);
      expect(test.heads()).toBe(0);
      expect(test.deleted).toHaveLength(2);
    }
  });
});
