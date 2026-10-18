// SPDX-License-Identifier: AGPL-3.0-or-later
import {env, runInDurableObject} from 'cloudflare:test';
import {describe, expect, it} from 'vitest';
import type {Env} from '../src/env';
import {NamespaceStore} from '../src/metadata/namespace';
import {SnapshotStore} from '../src/metadata/snapshots';

const bindings = env as Env;
const owner = {type:'user' as const, id:'owner', orgRole:'owner' as const};
describe('directory namespace timestamps and negative lookup invalidation', () => {
  it('publishes parent metadata and invalidates a primed Durable Object item cache on create/delete', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), async (fs, state) => {
      const ns = new NamespaceStore(state.storage.sql);
      const before = (await fs.getItem('root'))!;
      const result = await fs.createItem('root', 'new-child', false, 0);
      expect(result).toHaveProperty('item');
      if (!('item' in result)) throw new Error('create failed');
      const after = (await fs.getItem('root'))!;
      expect(after.modifiedAt!).toBeGreaterThan(before.modifiedAt ?? 0);
      expect(after.changedAt!).toBeGreaterThan(before.changedAt ?? 0);
      expect(after.version).toBe(before.version + 1);
      expect(after.updatedSeq).toBeGreaterThan(result.item.updatedSeq);
      expect(after.contentVersion).toBe(before.contentVersion);
      expect(await fs.deleteItem(result.item.id)).toEqual({deleted:true});
      expect((await fs.getItem('root'))!.modifiedAt!).toBeGreaterThan(after.modifiedAt!);
      expect(ns.getItem('root')!.version).toBe(after.version + 1);
    });
  });

  it('advances strictly with equal/backward clocks; content-only, no-op and rejected changes leave parent alone', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), (_fs, state) => {
      const ns = new NamespaceStore(state.storage.sql), dir = ns.put('root','folder',true,0);
      const future = Date.now() + 86_400_000;
      ns.setBasicInfo(dir.id,{modifiedAt:future,changedAt:future},dir.version);
      const a = ns.put(dir.id,'a',false,0);
      expect(ns.getItem(dir.id)!.modifiedAt).toBe(future+1);
      const b = ns.put(dir.id,'b',false,0);
      expect(ns.getItem(dir.id)!.modifiedAt).toBe(future+2);
      const parent = ns.getItem(dir.id);
      ns.put(dir.id,'a',false,123);
      ns.setBlockMap(a.id,[]);
      ns.rename(a.id,{name:'a'});
      expect(() => ns.put(dir.id,'c',false,0,{expectedVersion:1})).toThrow();
      expect(() => ns.rename(a.id,{name:'b'})).toThrow();
      expect(ns.remove(b.id,999)).toMatchObject({deleted:false});
      expect(ns.getItem(dir.id)).toEqual(parent);
    });
  });

  it('updates both move parents and the replacement parent inside the same rollback transaction', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), async (fs, state) => {
      const ns = new NamespaceStore(state.storage.sql), p = ns.put('root','p',true,0), q = ns.put('root','q',true,0);
      const a = ns.put(p.id,'source',false,0), b = ns.put(q.id,'target',false,0);
      const parents = [ns.getItem(p.id)!,ns.getItem(q.id)!];
      const root = ns.getItem('root');
      expect(await fs.renameItem(a.id,{parent:q.id,name:'target',expectedVersion:a.version,
        replace:{id:b.id,expectedVersion:b.version},principal:owner})).toHaveProperty('item');
      for (const parent of parents) expect(ns.getItem(parent.id)!.modifiedAt!).toBeGreaterThan(parent.modifiedAt!);
      expect(ns.getItem('root')).toEqual(root); // directory contents, not every ancestor
      const fresh = ns.put(p.id,'fresh',false,0), snapshot = [ns.getItem(p.id),ns.getItem(q.id)], seq = ns.currentSeq();
      state.storage.sql.exec("CREATE TRIGGER fail_move BEFORE UPDATE OF name ON items BEGIN SELECT RAISE(ABORT, 'injected'); END;");
      await expect(fs.renameItem(fresh.id,{parent:q.id,name:'target',expectedVersion:fresh.version,
        replace:{id:a.id,expectedVersion:ns.getItem(a.id)!.version},principal:owner})).rejects.toThrow('injected');
      expect([ns.getItem(p.id),ns.getItem(q.id)]).toEqual(snapshot);
      expect(ns.currentSeq()).toBe(seq);
      expect(ns.getItem(a.id)!.deleted).toBe(false);
    });
  });

  it('does not roll directory time backwards on an existing-directory upsert before another child create', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), (_fs, state) => {
      const ns = new NamespaceStore(state.storage.sql), dir = ns.put('root','folder',true,0);
      const future = Date.now() + 86_400_000;
      ns.setBasicInfo(dir.id,{modifiedAt:future,changedAt:future},dir.version);
      const root = ns.getItem('root');
      const updated = ns.put('root','folder',true,0);
      expect(updated.modifiedAt).toBe(future+1);
      expect(updated.changedAt).toBe(future+1);
      expect(ns.getItem('root')).toEqual(root); // no namespace entry changed
      ns.put(dir.id,'after-upsert',false,0);
      expect(ns.getItem(dir.id)!.modifiedAt).toBe(future+2);
    });
  });

  it('updates the surviving subtree parent once and never advances it for rejected/nonexistent deletes', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), async (fs, state) => {
      const ns = new NamespaceStore(state.storage.sql), p = ns.put('root','p',true,0), child = ns.put(p.id,'subtree',true,0);
      ns.put(child.id,'leaf',false,0);
      const parent = ns.getItem(p.id)!, root = ns.getItem('root');
      expect(await fs.deleteItem(child.id)).toMatchObject({deleted:false,reason:'directory_not_empty'});
      expect(ns.getItem(p.id)).toEqual(parent);
      expect(await fs.deleteSubtree(child.id,'owner')).toMatchObject({deleted:2});
      expect(ns.getItem(p.id)!.version).toBe(parent.version+1);
      expect(ns.getItem(p.id)!.modifiedAt!).toBeGreaterThan(parent.modifiedAt!);
      expect(ns.getItem('root')).toEqual(root);
      const after = ns.getItem(p.id);
      await fs.deleteItem(child.id); await fs.deleteSubtree(child.id,'owner');
      expect(ns.getItem(p.id)).toEqual(after);
    });
  });

  it('preserves strictly increasing restored directory times and touches parents of resurrected/moved snapshot entries', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), (_fs, state) => {
      const ns = new NamespaceStore(state.storage.sql), p = ns.put('root','p',true,0), q = ns.put('root','q',true,0);
      const file = ns.put(p.id,'file',false,0), gone = ns.put(p.id,'gone',false,0);
      const snapshots = new SnapshotStore(state.storage.sql,()=>ns.currentSeq(),ns);
      snapshots.create({id:'before'});
      ns.rename(file.id,{parent:q.id}); ns.remove(gone.id);
      ns.setBasicInfo(p.id,{modifiedAt:Date.now()+86_400_000},ns.getItem(p.id)!.version);
      const before = [ns.getItem(p.id)!,ns.getItem(q.id)!];
      state.storage.transactionSync(()=>snapshots.restore('before',p.id,{recursive:true}));
      for (const parent of before) expect(ns.getItem(parent.id)!.modifiedAt!).toBeGreaterThan(parent.modifiedAt!);
      expect(ns.getItem(file.id)).toMatchObject({parent:p.id,deleted:false});
      expect(ns.getItem(gone.id)!.deleted).toBe(false);
    });
  });

  it('keeps parent and child change-feed rows individually pageable and invalidates bulk-create parent metadata', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), async (fs, state) => {
      const ns = new NamespaceStore(state.storage.sql), p = ns.put('root','p',true,0);
      const before = ns.currentSeq(), a = ns.put(p.id,'a',false,0), b = ns.put(p.id,'b',false,0);
      const ids:string[] = []; let cursor = before;
      for (;;) {
        const page = ns.changesSince(cursor,1); ids.push(...page.items.map(i=>i.id));
        if (page.cursor === null) break; cursor = page.cursor;
      }
      expect(new Set(ids)).toEqual(new Set([a.id,b.id,p.id]));
      const parent = (await fs.getItem(p.id))!;
      await fs.seedChildren(p.id,'bulk-',2);
      expect((await fs.getItem(p.id))!.modifiedAt!).toBeGreaterThan(parent.modifiedAt!);
      const after = ns.getItem(p.id); await fs.seedChildren(p.id,'bulk-',2);
      expect(ns.getItem(p.id)).toEqual(after); // INSERT OR IGNORE introduced no name
    });
  });
});
