// SPDX-License-Identifier: AGPL-3.0-or-later
import { encryptedBlockFixture } from './encrypted-block-fixture';
import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import type { Env } from '../src/env';
import { defaultStorageConfig, type StorageConfig } from '../src/storage';
import { nativeVerificationBucket, verifyStorageObjects } from '../src/storage-object-verifier';

const payload = encryptedBlockFixture();
const checksum = sha256(payload);
const hash = [...checksum].map(value=>value.toString(16).padStart(2,'0')).join('');
const block = {objectKey:`blocks/native/${hash}`,blockHash:hash,length:4};
const endpoint = `https://${'a'.repeat(32)}.r2.cloudflarestorage.com`;
const configured = ():Env => ({...(env as Env),S3_ENDPOINT:endpoint,S3_BUCKET:'cloudfs-data',S3_REGION:'auto',
  S3_ACCESS_KEY_ID:'default-key',S3_SECRET_ACCESS_KEY:'default-secret',S3_SESSION_TOKEN:'default-session',
  DATA_BUCKET_ENDPOINT:endpoint,DATA_BUCKET_NAME:'cloudfs-data'});
const noS3:typeof fetch = async()=>{throw new Error('Unexpected public S3 request');};
const head = (patch:Partial<R2Object> = {}):R2Object => ({key:block.objectKey,size:payload.length,
  checksums:{sha256:checksum.buffer as ArrayBuffer},...patch} as R2Object);
function bucketWith(object:R2Object|null, get?:()=>Promise<R2ObjectBody|null>):Pick<R2Bucket,'head'|'get'> {
  return {head:async()=>object,get:get??(async()=>{throw new Error('Unexpected legacy GET');})} as Pick<R2Bucket,'head'|'get'>;
}

describe('native default-bucket verification',()=>{
  it('rejects hash-valid plaintext stored in R2 even with a provider checksum',async()=>{
    const e=configured(), raw=new Uint8Array(100).fill(65), digest=sha256(raw);
    const hash=[...digest].map(b=>b.toString(16).padStart(2,'0')).join('');
    const key=`native-plaintext-${crypto.randomUUID()}/${hash}`;
    await e.DATA_BUCKET!.put(key,raw,{sha256:digest});
    try {
      await expect(verifyStorageObjects(defaultStorageConfig(e),[{objectKey:key,blockHash:hash,length:100}],noS3,e.DATA_BUCKET!))
        .rejects.toMatchObject({reason:'invalid encrypted block envelope'});
    } finally {await e.DATA_BUCKET!.delete(key);}
  });
  it('uses provider SHA-256 from an actual R2 binding without a public S3 request',async()=>{
    const e=configured(), bucket=e.DATA_BUCKET!, key=`native-${crypto.randomUUID()}/${hash}`;
    await bucket.put(key,payload,{sha256:checksum});
    try {
      expect((await bucket.head(key))?.checksums.sha256).toBeDefined();
      const config=defaultStorageConfig(e);
      expect(nativeVerificationBucket(e,config)).toBe(bucket);
      expect(await verifyStorageObjects(config,[{...block,objectKey:key}],noS3,nativeVerificationBucket(e,config)))
        .toEqual([{...block,objectKey:key,ciphertextSize:73}]);
    } finally {await bucket.delete(key);}
  });
  it('selects native access only for the exact explicit mapping and deployment credential identity',()=>{
    const e=configured(), config=defaultStorageConfig(e);
    for(const patch of [
      {credentialSource:undefined}, {endpoint:`https://${'b'.repeat(32)}.r2.cloudflarestorage.com`},
      {bucket:'other'}, {region:'other'}, {forcePathStyle:false}, {accessKeyId:'other'},
      {secretAccessKey:'other'}, {sessionToken:'other'},
    ] satisfies Partial<StorageConfig>[])expect(nativeVerificationBucket(e,{...config,...patch})).toBeUndefined();
    for(const patch of [
      {DATA_BUCKET:undefined}, {DATA_BUCKET_ENDPOINT:undefined}, {DATA_BUCKET_NAME:undefined},
      {DATA_BUCKET_NAME:'other'}, {DATA_BUCKET_ENDPOINT:`https://${'b'.repeat(32)}.r2.cloudflarestorage.com`},
      {S3_BUCKET:'other'}, {S3_ENDPOINT:'https://s3.us-east-1.amazonaws.com'},
    ] satisfies Partial<Env>[])expect(nativeVerificationBucket({...e,...patch},config)).toBeUndefined();
    expect(nativeVerificationBucket({...e,DATA_BUCKET_ENDPOINT:`${endpoint}/`},{...config,endpoint:`${endpoint}/`})).toBe(e.DATA_BUCKET);
    const external={...e,DATA_BUCKET_ENDPOINT:'https://storage.test',S3_ENDPOINT:'https://storage.test'};
    expect(nativeVerificationBucket(external,{...config,endpoint:'https://storage.test'})).toBeUndefined();
  });
  it('keeps signed S3 verification for a mismatched filespace even when the default binding is present',async()=>{
    const e=configured(), config={...defaultStorageConfig(e),bucket:'different'};
    let calls=0;
    expect(await verifyStorageObjects(config,[block],async(input,init)=>{
      if(init?.method==='GET')return new Response(payload);
      calls++;expect(new URL(String(input)).pathname).toContain('/different/');expect(init?.method).toBe('HEAD');
      return new Response(null,{headers:{'content-length':'73','x-amz-checksum-sha256':btoa(String.fromCharCode(...checksum))}});
    },nativeVerificationBucket(e,config))).toHaveLength(1);
    expect(calls).toBe(1);
  });
  it('rejects missing objects, corrupt provider checksums, wrong identity and invalid sizes without trusting ETags',async()=>{
    const config=defaultStorageConfig(configured());
    for(const object of [null,head({checksums:{sha256:new Uint8Array(32).buffer} as R2Checksums}),
      head({key:'wrong'}),head({size:0}),head({size:74}),head({size:NaN}),head({size:1.5})]) {
      await expect(verifyStorageObjects(config,[block],noS3,bucketWith(object))).rejects.toBeDefined();
    }
  });
  it('fully hashes native legacy objects when SHA-256 is absent, regardless of ETag or custom metadata',async()=>{
    const config=defaultStorageConfig(configured());
    for(const [body,accept] of [[payload,true],[new Uint8Array([1,2,3,5]),false],[new Uint8Array(3),false],[new Uint8Array(5),false]] as const) {
      let gets=0;
      const object=head({checksums:{} as R2Checksums,etag:hash,customMetadata:{sha256:hash}});
      const bucket=bucketWith(object,async()=>{gets++;return {...object,body:new Response(body).body!} as R2ObjectBody;});
      const result=verifyStorageObjects(config,[block],noS3,bucket);
      if(accept)expect(await result).toHaveLength(1);else await expect(result).rejects.toBeDefined();
      expect(gets).toBe(1);
    }
  });
  it('cancels a changed legacy object before reading its body',async()=>{
    const config=defaultStorageConfig(configured()), object=head({checksums:{} as R2Checksums});
    let canceled=false,read=false;
    const bucket=bucketWith(object,async()=>({...object,size:5,body:new ReadableStream({
      pull(){read=true;},cancel(){canceled=true;},
    },{highWaterMark:0})} as R2ObjectBody));
    await expect(verifyStorageObjects(config,[block],noS3,bucket)).rejects.toMatchObject({reason:'object size or identity changed during verification'});
    expect(canceled).toBe(true);expect(read).toBe(false);
  });
  it('keeps native verification at six active operations and rejects an oversized batch before I/O',async()=>{
    const config=defaultStorageConfig(configured());let active=0,peak=0,calls=0;
    const bucket={head:async()=>{calls++;active++;peak=Math.max(peak,active);
      await new Promise(resolve=>setTimeout(resolve,1));active--;return head();},get:async()=>({...head(),body:new Response(payload).body!} as R2ObjectBody)} as Pick<R2Bucket,'head'|'get'>;
    expect(await verifyStorageObjects(config,Array.from({length:25},()=>block),noS3,bucket)).toHaveLength(25);
    expect(peak).toBe(6);expect(active).toBe(0);
    await expect(verifyStorageObjects(config,Array.from({length:129},()=>block),noS3,bucket)).rejects.toBeDefined();
    expect(calls).toBe(25);
  });
});
