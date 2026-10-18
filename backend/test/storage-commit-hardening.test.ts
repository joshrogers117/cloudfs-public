// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it, vi } from 'vitest';
import type { Env } from '../src/env';
import type { Block, Item } from '../src/metadata/types';
import { NamespaceStore } from '../src/metadata/namespace';
import { UploadCoordinator } from '../src/metadata/uploads';
import { presignBatchForSpace } from '../src/presign';
import { objectUrl, presignWith, type StorageConfig } from '../src/storage';

const e = env as Env;
const fresh = () => e.FILESPACE.getByName(`commit-review-${crypto.randomUUID()}`);
const block = (n: number, over: Partial<Block> = {}): Block => ({ chunkIdx: 0, blockIdx: n, objectKey: `blocks/test/${n}`, blockHash: `hash-${n}`, offset: n * 100, length: 100, ...over });
async function fixture() {
  const stub = fresh(), result = await stub.createItem('root', 'clip', false, 0);
  if (!('item' in result)) throw new Error('fixture');
  return { stub, item: result.item };
}
const cfg: StorageConfig = { endpoint: 'https://s3.example.test', bucket: 'test', region: 'auto', accessKeyId: 'example', secretAccessKey: 'not-a-real-secret' };

describe('manifest publication validates before mutation and rolls back faults', () => {
  it('rejects malformed, duplicate, unordered and overflowing manifests without touching the old image', async () => {
    const { stub, item } = await fixture();
    const original = await stub.setBlockMap(item.id, [block(0)], { expectedVersion: item.version }) as Item;
    const bad: unknown[] = [null, {}, [block(0), block(0)], [block(0), block(1, {offset: 0})],
      [block(0, {offset: 1})], [block(0, {length: -1})], [block(0, {blockIdx: 0.5})],
      [block(0, {length: Number.MAX_SAFE_INTEGER}), block(1, {offset: Number.MAX_SAFE_INTEGER})],
      [block(0), block(1, {objectKey: block(0).objectKey})],
      [block(0),block(1),block(2,{objectKey:block(0).objectKey,blockHash:block(0).blockHash,length:50})]];
    for (const input of bad) {
      const result = await stub.setBlockMap(item.id, input as Block[], { expectedVersion: original.version });
      expect(result).toHaveProperty('invalidManifest', true);
      expect(await stub.getItem(item.id)).toEqual(original);
      expect(await stub.getBlockMap(item.id)).toEqual([block(0)]);
    }
    expect(await stub.setBlockMap('root', [block(0)])).toHaveProperty('invalidManifest', true);
  });

  it('refuses known key/hash aliases and preserves snapshots, history and reference counts', async () => {
    const { stub, item } = await fixture();
    await stub.setBlockMap(item.id, [block(0)]);
    for (const forged of [block(0, {blockHash: 'forged'}), block(0, {objectKey: 'blocks/test/different'})]) {
      expect(await stub.setBlockMap(item.id, [forged])).toHaveProperty('invalidManifest', true);
    }
    await runInDurableObject(stub, (_instance, state) => {
      expect(Number(state.storage.sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?;', block(0).blockHash).one().refcount)).toBe(1);
      expect(state.storage.sql.exec('SELECT * FROM retained_blocks;').toArray()).toEqual([]);
    });
  });

  it('the DO transaction rolls back an injected failure after old references are removed', async () => {
    const { stub, item } = await fixture();
    const original = await stub.setBlockMap(item.id, [block(0)]) as Item;
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(`CREATE TRIGGER fail_block BEFORE INSERT ON blocks WHEN NEW.block_hash='fail'
        BEGIN SELECT RAISE(ABORT,'injected storage fault'); END;`);
    });
    await runInDurableObject(stub, async (instance) => {
      let caught = '';
      try { await instance.setBlockMap(item.id, [block(0, {objectKey: 'blocks/test/fail', blockHash: 'fail'})]); }
      catch (error) { caught = String(error); }
      expect(caught).toContain('injected storage fault');
    });
    expect(await stub.getItem(item.id)).toEqual(original);
    expect(await stub.getBlockMap(item.id)).toEqual([block(0)]);
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      expect(sql.exec('SELECT * FROM retained_blocks;').toArray()).toEqual([]);
      expect(sql.exec("SELECT * FROM known_objects WHERE block_hash='fail';").toArray()).toEqual([]);
      expect(Number(sql.exec('SELECT refcount FROM block_refs;').one().refcount)).toBe(1);
    });
  });

  it('a lost commit reply retries without another version bump, but a changed stale request conflicts', async () => {
    const { stub, item } = await fixture();
    const committed = await stub.setBlockMap(item.id, [block(0)], { expectedVersion: item.version });
    expect(await stub.setBlockMap(item.id, [block(0)], { expectedVersion: item.version })).toEqual(committed);
    expect(await stub.setBlockMap(item.id, [block(0, {objectKey: 'blocks/test/changed', blockHash: 'changed'})], { expectedVersion: item.version })).toHaveProperty('conflict', true);
  });

  it('large repeated manifests preserve exact ref multiplicity using bounded SQL batches', async () => {
    const { stub, item } = await fixture();
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql; let statements = 0;
      const counted = { exec: (...args: Parameters<SqlStorage['exec']>) => { statements++; return sql.exec(...args); } } as SqlStorage;
      const ns = new NamespaceStore(counted);
      const blocks = Array.from({length: 1024}, (_, i) => block(i, {objectKey: 'blocks/test/shared', blockHash: 'shared'}));
      state.storage.transactionSync(() => ns.setBlockMap(item.id, blocks));
      expect(statements).toBeLessThan(50); // used to exceed four statements per block
      expect(Number(sql.exec("SELECT refcount FROM block_refs WHERE block_hash='shared';").one().refcount)).toBe(1024);
      expect(ns.getBlockMap(item.id)).toEqual(blocks);
      state.storage.transactionSync(() => ns.setBlockMap(item.id, blocks.slice(0, 2)));
      expect(Number(sql.exec("SELECT refcount FROM block_refs WHERE block_hash='shared';").one().refcount)).toBe(2);
    });
  });
});

describe('multipart session identity and retry safety', () => {
  it('resumes identical sessions and refuses id reuse, wrong part geometry and completed reset', async () => {
    const stub = fresh();
    await runInDurableObject(stub, (_instance, state) => {
      const uploads = new UploadCoordinator(state.storage.sql), options = {uploadId:'u', itemId:'i', key:'blocks/u', totalSize:250, partSize:100};
      uploads.begin(options); uploads.recordPart('u', 1, 'a', 100);
      expect(uploads.begin(options).uploadedParts).toHaveLength(1);
      expect(() => uploads.begin({...options, itemId:'another'})).toThrow('upload_conflict');
      for (const [number, size] of [[0,100],[4,50],[2,99],[3,100]]) expect(() => uploads.recordPart('u', number, 'b', size)).toThrow('upload_invalid');
      uploads.recordPart('u', 2, 'b', 100); uploads.recordPart('u', 3, 'c', 50);
      expect(uploads.complete('u', 'final')).toEqual({completed:true});
      expect(uploads.complete('u', 'final')).toEqual({completed:true});
      expect(uploads.begin(options).state).toBe('completed');
      expect(() => uploads.abort('u')).toThrow('upload_conflict');
    });
  });
  it('aborted sessions never inherit parts and malformed old records cannot report complete', async () => {
    const stub = fresh();
    await runInDurableObject(stub, (_instance, state) => {
      const uploads = new UploadCoordinator(state.storage.sql), options = {uploadId:'u', itemId:'i', key:'blocks/u', totalSize:100, partSize:100};
      uploads.begin(options); uploads.recordPart('u', 1, 'a', 100); uploads.abort('u');
      expect(() => uploads.begin(options)).toThrow('upload_conflict');
      expect(() => uploads.complete('u', 'final')).toThrow('upload_conflict');
      state.storage.sql.exec(`INSERT INTO upload_parts VALUES ('fresh',1,'stale',100,NULL);`);
      expect(uploads.begin({...options,uploadId:'fresh'}).uploadedParts).toEqual([]);
      state.storage.sql.exec(`INSERT INTO upload_parts VALUES ('fresh',1,'too-short',1,NULL);`);
      expect(uploads.complete('fresh', 'final')).toEqual({completed:false, missing:[1]});
      expect(() => uploads.begin({...options, uploadId:'huge', totalSize:Number.MAX_SAFE_INTEGER, partSize:1})).toThrow('upload_invalid');
    });
  });
});

describe('signed object identity and batch credential cost', () => {
  it('encoded traversal, query, fragment and backslash remain literal in the authorized key', async () => {
    for (const key of ['blocks/org::fs/%2e%2e/%2e%2e/other', 'blocks/org::fs/a?acl', 'blocks/org::fs/a#fragment', 'blocks/org::fs/a\\b', 'blocks/org::fs/a+b']) {
      for (const forcePathStyle of [true,false]) {
        const url = new URL(objectUrl({...cfg,forcePathStyle}, key));
        expect(decodeURIComponent(url.pathname)).toBe(`${forcePathStyle ? '/test' : ''}/${key}`);
        expect(url.search).toBe(''); expect(url.hash).toBe('');
        const signed = new URL(await presignWith({...cfg,forcePathStyle}, key, 'PUT', 300));
        expect(decodeURIComponent(signed.pathname)).toBe(`${forcePathStyle ? '/test' : ''}/${key}`);
      }
    }
  });
  it('an authorized 256-key batch resolves managed credentials exactly once with ordered per-key results', async () => {
    const resolver = vi.fn(async () => ({accessKeyId:'example', secretAccessKey:'not-a-real-secret'}));
    const entries = Array.from({length:256}, (_, i) => ({key:`blocks/org::fs/${i}`,method:i===100?'DELETE':'GET'}));
    const results = await presignBatchForSpace(e, {endpoint:cfg.endpoint,bucket:cfg.bucket,credentialRef:'managed'}, entries, 300, resolver);
    expect(resolver).toHaveBeenCalledTimes(1);
    expect(results.map(r => r.key)).toEqual(entries.map(r => r.key));
    expect(results.filter(r => r.url)).toHaveLength(255);
    expect(results[100].error).toContain('method not allowed');
  });
});

describe('storage verification and metadata rate classes remain independent',()=>{
  it('a metadata commit cannot clamp the upload verification bucket to the mutation capacity',async()=>{
    const stub=fresh(), principal='p:writer';
    const presignCapacity=(await stub.rateLimit('presign',principal,0)).limit;
    const mutationCapacity=(await stub.rateLimit('mutation',principal,0)).limit;
    expect(presignCapacity).toBeGreaterThan(mutationCapacity);
    expect((await stub.rateLimit('presign',principal,Math.floor(presignCapacity/5))).allowed).toBe(true);
    expect((await stub.rateLimit('mutation',principal)).allowed).toBe(true);
    const verify=await stub.rateLimit('presign',principal,mutationCapacity);
    expect(verify.allowed).toBe(true);
    expect((await stub.rateLimit('mutation',principal,mutationCapacity)).allowed).toBe(false);
    expect((await stub.rateLimit('presign',principal,1)).allowed).toBe(true);
  });
});
