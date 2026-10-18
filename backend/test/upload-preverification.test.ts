// SPDX-License-Identifier: AGPL-3.0-or-later
import { encryptedBlockFixture } from './encrypted-block-fixture';
import { createExecutionContext, env, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import worker from '../src/index';
import type { Env } from '../src/env';
import { defaultStorageConfig } from '../src/storage';
import { storageIdentity } from '../src/storage-object-verifier';
import { uploadVerificationManifest } from '../src/upload-verification';
import { filespaceDoName, mintToken } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';

const payload = encryptedBlockFixture(), digest = sha256(payload);
const hash = [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
const endpoint = `https://${'a'.repeat(32)}.r2.cloudflarestorage.com`;
async function fixture() {
  const orgId = `preverify-${crypto.randomUUID()}`, spaceId = 'files';
  const owner = await seedOwnerFixture(orgId), base = env as Env;
  const config = {S3_ENDPOINT:endpoint,S3_BUCKET:'cloudfs-data',S3_REGION:'auto',
    DATA_BUCKET_ENDPOINT:endpoint,DATA_BUCKET_NAME:'cloudfs-data',STORAGE_VERIFY_UPLOADS:'1'};
  const bindings = {...base,...config};
  const stub = base.FILESPACE.getByName(filespaceDoName(orgId,spaceId));
  await runInDurableObject(stub,instance=>{ Object.assign((instance as unknown as {env:Env}).env,config); });
  const result = await stub.createItem('root','clip.mov',false,0);
  if (!('item' in result)) throw new Error('fixture creation');
  const item = result.item;
  const block = {objectKey:`blocks/${orgId}::${spaceId}/${hash}`,blockHash:hash,length:4};
  const request = async (blocks:unknown, token=owner.token, method='POST', suffix='/verify', extra={}) => {
    const ctx = createExecutionContext();
    const response = await worker.fetch(new Request(`https://gw.local/v1/filespaces/${spaceId}/blocks/${item.id}${suffix}`,{
      method,headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({blocks,...extra}),
    }),bindings,ctx);
    await waitOnExecutionContext(ctx);
    return response;
  };
  return {orgId,spaceId,owner,bindings,stub,item,block,request};
}

describe('completed upload verification pipeline',()=>{
  it('bounds and validates unordered upload identities without trusting file coordinates',()=>{
    const block={objectKey:`blocks/test/${hash}`,blockHash:hash,length:4};
    expect(uploadVerificationManifest([{...block,offset:1000,chunkIdx:99}])[0]).toMatchObject({offset:0,chunkIdx:0});
    for(const input of [null,[],Array(129).fill(block),[{...block,length:0}],[{...block,blockHash:'bad'}],
      [block,{...block,length:5}],[{...block,objectKey:`blocks/\u0000/${hash}`}],[{...block,length:Number.MAX_SAFE_INTEGER},block]]) {
      expect(()=>uploadVerificationManifest(input)).toThrow();
    }
  });
  it('stores real R2 receipts without publishing bytes, then preserves final version conflict checks',async()=>{
    const f=await fixture();
    await f.bindings.DATA_BUCKET!.put(f.block.objectKey,payload,{sha256:digest});
    const bucket=f.bindings.DATA_BUCKET!;
    let gatewayHeads=0;
    // Only the gateway's binding is replaced; the DO keeps its real binding.
    f.bindings.DATA_BUCKET={head:async(key:string)=>{gatewayHeads++;return bucket.head(key);},
      get:bucket.get.bind(bucket)} as R2Bucket;
    try {
      const before=await f.stub.getItem(f.item.id);
      expect((await f.request([f.block])).status).toBe(200);
      expect(await (await f.request([f.block])).json()).toEqual({verified:1});
      expect(gatewayHeads).toBe(1); // One gateway HEAD, cached receipt on retry.
      expect(await f.stub.getItem(f.item.id)).toEqual(before);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual([]);
      const manifest=uploadVerificationManifest([f.block]);
      expect(await f.stub.unverifiedObjects(manifest,storageIdentity(defaultStorageConfig(f.bindings)))).toEqual([]);
      const conflict=await f.request(manifest,f.owner.token,'PUT','',{expectedVersion:f.item.version!+1});
      expect(conflict.status).toBe(409);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual([]);
      expect((await f.request(manifest,f.owner.token,'PUT','',{expectedVersion:f.item.version})).status).toBe(200);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual(manifest);
    } finally {await bucket.delete(f.block.objectKey);}
  });
  it('rejects missing or corrupt objects and leaves the file unpublished',async()=>{
    const f=await fixture();
    // Client-supplied "proof" fields must never create a trusted receipt.
    expect((await f.request([{...f.block,ciphertextSize:73,verified:true,proof:hash}],f.owner.token,'POST','/verify',{verified:1})).status).toBe(503);
    const wrong=new Uint8Array([4,3,2,1]);
    await f.bindings.DATA_BUCKET!.put(f.block.objectKey,wrong,{sha256:sha256(wrong)});
    try {
      expect((await f.request([f.block])).status).toBe(503);
      expect(await f.stub.unverifiedObjects(uploadVerificationManifest([f.block]),storageIdentity(defaultStorageConfig(f.bindings)))).toHaveLength(1);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual([]);
    } finally {await f.bindings.DATA_BUCKET!.delete(f.block.objectKey);}
  });
  it('does not publish any new receipt from a mixed valid and corrupt batch',async()=>{
    const f=await fixture(), badHash='b'.repeat(64);
    const bad={...f.block,objectKey:`blocks/${f.orgId}::${f.spaceId}/${badHash}`,blockHash:badHash};
    await f.bindings.DATA_BUCKET!.put(f.block.objectKey,payload,{sha256:digest});
    await f.bindings.DATA_BUCKET!.put(bad.objectKey,payload,{sha256:digest});
    try {
      expect((await f.request([f.block,bad])).status).toBe(503);
      expect(await f.stub.unverifiedObjects(uploadVerificationManifest([f.block,bad]),storageIdentity(defaultStorageConfig(f.bindings)))).toHaveLength(2);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual([]);
    } finally {await f.bindings.DATA_BUCKET!.delete([f.block.objectKey,bad.objectKey]);}
  });
  it('requires write scope, item access and in-filespace object identity before touching storage',async()=>{
    const f=await fixture();
    const readOnly=await mintToken(f.bindings.AUTH_SIGNING_SECRET,{sub:f.owner.userId,type:'session',orgId:f.orgId,scopes:['fs:read'],ttlSeconds:900});
    expect((await f.request([f.block],readOnly)).status).toBe(403);
    const member=await f.bindings.ORG_DO.getByName(f.orgId).createUser({orgId:f.orgId,email:'member@test.local',displayName:'Member',role:'standard'});
    const memberToken=await mintToken(f.bindings.AUTH_SIGNING_SECRET,{sub:member.id,type:'session',orgId:f.orgId,scopes:['fs:write'],ttlSeconds:900});
    expect((await f.request([f.block],memberToken)).status).toBe(403);
    expect((await f.request([{...f.block,objectKey:`blocks/other/${hash}`}])).status).toBe(400);
    expect((await f.request(Array(129).fill(f.block))).status).toBe(400);
  });
  it('requires the uploading member’s claim and rechecks revoked access after an early receipt',async()=>{
    const f=await fixture();
    const member=await f.bindings.ORG_DO.getByName(f.orgId).createUser({orgId:f.orgId,email:'writer@test.local',displayName:'Writer',role:'standard'});
    const memberToken=await mintToken(f.bindings.AUTH_SIGNING_SECRET,{sub:member.id,type:'session',orgId:f.orgId,scopes:['fs:write'],ttlSeconds:900});
    const principal={type:'user' as const,id:member.id,orgRole:'standard' as const};
    await f.stub.grantAccess({spaceId:f.spaceId,inodeId:f.item.id,principalType:'user',principalId:member.id,level:'edit'},f.owner.userId);
    expect((await f.request([f.block],memberToken)).status).toBe(403);
    expect(await f.stub.prepareObjectUpload(principal,f.block.objectKey,f.item.id)).toMatchObject({error:null});
    await f.bindings.DATA_BUCKET!.put(f.block.objectKey,payload,{sha256:digest});
    try {
      expect((await f.request([f.block],memberToken)).status).toBe(200);
      await f.stub.revokeAccess(f.item.id,'user',member.id);
      const manifest=uploadVerificationManifest([f.block]);
      expect((await f.request(manifest,memberToken,'PUT','',{expectedVersion:f.item.version})).status).toBe(403);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual([]);
    } finally {await f.bindings.DATA_BUCKET!.delete(f.block.objectKey);}
  });
});
