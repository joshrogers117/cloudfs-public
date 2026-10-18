// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { filespaceDoName } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';

async function fixture() {
  const orgId=`range-${crypto.randomUUID()}`, owner=await seedOwnerFixture(orgId);
  const e=env as Env, fs=e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId,'team')));
  const created=await fs.createItem('root','project.bin',false,0);
  if (!('item' in created)) throw new Error('fixture');
  const item=created.item, a=crypto.randomUUID(), b=crypto.randomUUID();
  const request=(client:string,path:string,body:unknown,method='POST')=>SELF.fetch(`https://gw.local/v1/filespaces/team${path}`,{
    method,headers:{Authorization:`Bearer ${owner.token}`,'content-type':'application/json','X-CloudFS-Client-ID':client},body:JSON.stringify(body)});
  const lock=async(client:string,handle:string,action:string,extra:Record<string,unknown>={}): Promise<Record<string,unknown>>=>{
    const res=await request(client,'/range-locks',{path:item.id,handle,action,...extra});
    return {status:res.status,...await res.json() as Record<string,unknown>};
  };
  return {fs,item,a,b,request,lock};
}
const range=(offset:string,length:string,exclusive=false)=>({offset,length,exclusive});

describe('distributed handle-owned byte ranges',()=>{
  it('allows shared co-holders and disjoint exclusive locks, but rejects every conflicting overlap',async()=>{
    const f=await fixture();
    const a=await f.lock(f.a,'a','acquire',{ranges:[range('0','100')]});
    const b=await f.lock(f.b,'b','acquire',{ranges:[range('50','100')]});
    expect(a.granted).toBe(true); expect(b.granted).toBe(true); expect(b.fence).not.toBe(a.fence);
    expect((await f.lock(f.b,'c','acquire',{ranges:[range('99','2',true)]})).granted).toBe(false);
    expect((await f.lock(f.b,'c','acquire',{ranges:[range('150','10',true)]})).granted).toBe(true);
    expect((await f.lock(f.a,'d','acquire',{ranges:[range('160','20',true)]})).granted).toBe(true);
    expect((await f.lock(f.a,'e','acquire',{ranges:[range('155','20')]})).granted).toBe(false);
    // Access checks distinguish locks from handles even on the same device.
    expect((await f.lock(f.b,'reader','check',{range:range('50','5')})).allowed).toBe(true);
    expect((await f.lock(f.b,'reader','check',{range:range('50','5',true)})).allowed).toBe(false);
    expect((await f.lock(f.a,'reader','check',{range:range('150','5')})).allowed).toBe(false);
    expect((await f.lock(f.b,'c','check',{range:range('150','5',true)})).allowed).toBe(true);
  });
  it('fails a multi-range acquisition atomically and unlocks only exact owned ranges',async()=>{
    const f=await fixture();
    const held=await f.lock(f.a,'a','acquire',{ranges:[range('100','10',true),range('200','10',true)]});
    expect((await f.lock(f.b,'b','acquire',{ranges:[range('0','10',true),range('105','2',true)]})).granted).toBe(false);
    expect((await f.lock(f.a,'c','acquire',{ranges:[range('0','10',true)]})).granted).toBe(true);
    expect((await f.lock(f.a,'a','release',{fence:held.fence,ranges:[range('100','10'),range('201','1')]})).released).toBe(false);
    expect((await f.lock(f.b,'b','check',{range:range('100','1')})).allowed).toBe(false);
    expect((await f.lock(f.b,'a','release',{fence:held.fence})).released).toBe(true); // idempotent absent handle, never owner's record
    expect((await f.lock(f.b,'b','check',{range:range('100','1')})).allowed).toBe(false);
    expect((await f.lock(f.a,'a','release',{fence:held.fence,ranges:[range('100','10')]})).released).toBe(true);
    expect((await f.lock(f.b,'b','check',{range:range('100','1')})).allowed).toBe(true);
    expect((await f.lock(f.b,'b','check',{range:range('200','1')})).allowed).toBe(false);
    expect((await f.lock(f.a,'a','release',{fence:held.fence})).released).toBe(true);
    expect((await f.lock(f.b,'b','check',{range:range('200','1')})).allowed).toBe(true);
  });
  it('denies owner writes through shared locks while preserving owner reads, exclusive writes and idempotent transport acquisition',async()=>{
    const f=await fixture();
    const initial=await f.lock(f.a,'owner','acquire',{ranges:[range('0','100'),range('200','100',true)]});
    expect(initial.granted).toBe(true);
    const retried=await f.lock(f.a,'owner','acquire',{fence:initial.fence,ranges:[range('0','100')]});
    expect(retried.granted).toBe(true); expect(retried.fence).toBe(initial.fence);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('0','100')})).allowed).toBe(true);
    expect(await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('99','2',true)}))
      .toMatchObject({allowed:false,reason:'shared-lock'});
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('100','100',true)})).allowed).toBe(true);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('200','100',true)})).allowed).toBe(true);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('200','100')})).allowed).toBe(true);
    expect((await f.lock(f.a,'other-handle','check',{range:range('0','1',true)})).allowed).toBe(false);
    expect((await f.lock(f.b,'other-client','check',{range:range('200','1')})).allowed).toBe(false);
    // A same-handle shared overlap restricts even its existing exclusive range.
    expect((await f.lock(f.a,'owner','acquire',{fence:initial.fence,ranges:[range('250','100')]})).granted).toBe(true);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('250','1',true)})).allowed).toBe(false);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('250','1')})).allowed).toBe(true);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('249','1',true)})).allowed).toBe(true);
    // The HTTP authority stores a union, not SMB acquisition multiplicity.
    // Native code releases this unique range only after its last local unlock.
    expect((await f.lock(f.a,'owner','release',{fence:initial.fence,ranges:[range('0','100')]})).released).toBe(true);
    expect((await f.lock(f.a,'owner','check',{fence:initial.fence,range:range('0','100',true)})).allowed).toBe(true);
  });
  it('expires crashed handles and fences delayed renewal, acquire, access and close',async()=>{
    const f=await fixture();
    const old=await f.lock(f.a,'a','acquire',{ranges:[range('0','100',true)]});
    await runInDurableObject(f.fs,async(_instance,state)=>{state.storage.sql.exec('UPDATE range_locks SET expires_at=0');});
    expect((await f.lock(f.a,'a','renew',{fence:old.fence})).granted).toBe(false);
    expect((await f.lock(f.a,'a','acquire',{fence:old.fence,ranges:[range('200','10')]})).granted).toBe(false);
    const next=await f.lock(f.a,'a','acquire',{ranges:[range('0','100',true)]});
    expect(next.granted).toBe(true); expect(Number(next.fence)).toBeGreaterThan(Number(old.fence));
    expect((await f.lock(f.a,'a','check',{fence:old.fence,range:range('0','1')})).allowed).toBe(false);
    expect((await f.lock(f.a,'a','release',{fence:old.fence})).released).toBe(false);
    expect((await f.lock(f.b,'b','acquire',{ranges:[range('0','1')]})).granted).toBe(false);
    expect((await f.lock(f.a,'a','renew',{fence:next.fence})).fence).toBe(next.fence);
  });
  it('preserves whole-file publication serialization and blocks metadata clobbers',async()=>{
    const f=await fixture();
    const shared=await f.lock(f.a,'a','acquire',{ranges:[range('0','10')]});
    expect((await (await f.request(f.b,'/locks',{path:f.item.id})).json() as {granted:boolean}).granted).toBe(false);
    for (const [path,method,body] of [
      [`/items/${f.item.id}`,'PATCH',{name:'clobber.bin'}],
      [`/blocks?item=${f.item.id}`,'PUT',{blocks:[],fence:shared.fence}],
    ] as const) expect((await f.request(f.b,path,body,method)).status).toBe(409);
    // A range fence itself can never be presented as publication authority.
    expect((await f.request(f.a,`/blocks?item=${f.item.id}`,{blocks:[],fence:shared.fence},'PUT')).status).toBe(409);
    await f.lock(f.a,'a','release',{fence:shared.fence});
    const writer=await (await f.request(f.b,'/locks',{path:f.item.id})).json() as {granted:boolean};
    expect(writer.granted).toBe(true);
    expect((await f.lock(f.a,'a','acquire',{ranges:[range('200','10')]})).granted).toBe(false);
  });
  it('preserves exact UInt64 boundaries and rejects overflow, noncanonical strings and unbounded batches',async()=>{
    const f=await fixture();
    expect((await f.lock(f.a,'a','acquire',{ranges:[range('18446744073709551614','1',true)]})).granted).toBe(true);
    expect((await f.lock(f.b,'b','acquire',{ranges:[range('18446744073709551614','1')]})).granted).toBe(false);
    for (const r of [range('18446744073709551615','1'),range('01','1'),range('-1','1'),{offset:1,length:1,exclusive:true}])
      expect((await f.lock(f.a,'x','acquire',{ranges:[r]})).status).toBe(400);
    expect((await f.lock(f.a,'x','acquire',{ranges:Array(65).fill(range('0','1'))})).status).toBe(400);
  });
  it('does not grant write publication to the legacy shared lease API',async()=>{
    const f=await fixture();
    const shared=await (await f.request(f.a,'/locks',{path:f.item.id,mode:'shared'})).json() as {fence:number};
    expect((await f.request(f.a,`/blocks?item=${f.item.id}`,{blocks:[],fence:shared.fence},'PUT')).status).toBe(409);
  });
  it('allows read-granted shared locks and denies renewal/I/O after access revocation',async()=>{
    const f=await fixture();
    const reader={type:'user' as const,id:'reader',orgRole:'standard' as const};
    await f.fs.grantAccess({spaceId:'team',inodeId:'root',principalType:'user',principalId:reader.id,level:'read'},'owner');
    const shared=await f.fs.acquireRangesFor(reader,f.item.id,'reader-client','read-handle',[range('0','100')],60000);
    expect(shared.granted).toBe(true);
    expect((await f.fs.acquireRangesFor(reader,f.item.id,'reader-client','exclusive',[range('200','100',true)],60000)).reason).toBe('forbidden');
    expect((await f.fs.renewRangesFor(reader,f.item.id,'reader-client','read-handle',shared.fence!,60000,false)).granted).toBe(true);
    await f.fs.revokeAccess('root','user',reader.id);
    expect((await f.fs.renewRangesFor(reader,f.item.id,'reader-client','read-handle',shared.fence!,60000,false)).reason).toBe('forbidden');
    expect((await f.fs.rangeAccessFor(reader,f.item.id,'reader-client','read-handle',range('0','1'),shared.fence)).reason).toBe('forbidden');
    expect((await f.fs.releaseRanges(f.item.id,'reader-client','read-handle',shared.fence!)).released).toBe(true);
  });

  it('positive read permits block exclusive grants, expire, and cannot starve a waiting locker',async()=>{
    const f=await fixture();
    const permit=await f.lock(f.a,'reader','check',{range:range('0','100')});
    expect(permit.allowed).toBe(true); expect(permit.permitTtlMs).toBe(1000);
    expect((await f.lock(f.b,'locker','acquire',{ranges:[range('500','10',true)]})).granted).toBe(false);
    // A waiter stops permit renewal. Direct nonconflicting reads are still legal.
    const repeat=await f.lock(f.a,'reader','check',{range:range('0','100')});
    expect(repeat.allowed).toBe(true); expect(repeat.permitTtlMs).toBeUndefined();
    await runInDurableObject(f.fs,async(_instance,state)=>{state.storage.sql.exec('UPDATE read_permits SET expires_at=0');});
    const acquired=await f.lock(f.b,'locker','acquire',{ranges:[range('500','10',true)]});
    expect(acquired.granted).toBe(true);
    expect((await f.lock(f.a,'reader','check',{range:range('500','1')})).allowed).toBe(false);
    const disjoint=await f.lock(f.a,'reader','check',{range:range('0','1')});
    expect(disjoint.allowed).toBe(true); expect(disjoint.permitTtlMs).toBeUndefined();
  });
  it('read permits allow ordinary writer leases and close releases only its own generation',async()=>{
    const f=await fixture();
    const first=await f.lock(f.a,'reader','check',{range:range('0','1')});
    // Reads have always been permitted while another client edits. The read
    // permit blocks explicit exclusive LOCK, not ordinary writer publication.
    expect((await (await f.request(f.b,'/locks',{path:f.item.id})).json() as {granted:boolean}).granted).toBe(true);
    await runInDurableObject(f.fs,async(_instance,state)=>{state.storage.sql.exec('UPDATE read_permits SET expires_at=0');state.storage.sql.exec('DELETE FROM locks');});
    const second=await f.lock(f.a,'reader','check',{range:range('0','1')});
    expect(Number(second.permitFence)).toBeGreaterThan(Number(first.permitFence));
    await f.lock(f.a,'reader','release-read',{fence:first.permitFence});
    expect((await f.lock(f.b,'locker','acquire',{ranges:[range('0','1',true)]})).granted).toBe(false);
    await f.lock(f.a,'reader','release-read',{fence:second.permitFence});
    expect((await f.lock(f.b,'locker','acquire',{ranges:[range('0','1',true)]})).granted).toBe(true);
  });

  it('shared additions cannot renew retained exclusive authority after write ACL or scope is removed',async()=>{
    const f=await fixture(), editor={type:'user' as const,id:'editor',orgRole:'standard' as const};
    await f.fs.grantAccess({spaceId:'team',inodeId:'root',principalType:'user',principalId:editor.id,level:'edit'},'owner');
    const first=await f.fs.acquireRangesFor(editor,f.item.id,'editor-client','h',[range('0','10',true)],60000);
    expect(first.granted).toBe(true);
    expect((await f.fs.acquireRangesFor(editor,f.item.id,'editor-client','h',[range('20','10')],60000,first.fence,false)).reason).toBe('forbidden');
    await f.fs.revokeAccess('root','user',editor.id);
    await f.fs.grantAccess({spaceId:'team',inodeId:'root',principalType:'user',principalId:editor.id,level:'read'},'owner');
    expect((await f.fs.acquireRangesFor(editor,f.item.id,'editor-client','h',[range('20','10')],60000,first.fence)).reason).toBe('forbidden');
    expect((await f.fs.renewRangesFor(editor,f.item.id,'editor-client','h',first.fence!,60000)).reason).toBe('forbidden');
    expect((await f.fs.releaseRanges(f.item.id,'editor-client','h',first.fence!)).released).toBe(true);
    expect((await f.fs.acquireRangesFor(editor,f.item.id,'editor-client','new',[range('20','10')],60000,undefined,false)).granted).toBe(true);
  });

  it('throttles range mutation work independently from reads and always allows cleanup',async()=>{
    const f=await fixture();
    const held=await f.lock(f.a,'h','acquire',{ranges:[range('0','10')]});
    expect(held.granted).toBe(true);
    await runInDurableObject(f.fs,async(_instance,state)=>{
      state.storage.sql.exec("UPDATE rate_buckets SET tokens=0,updated_at=? WHERE key LIKE 'mutation:%'",Date.now()+60000);
    });
    expect((await f.lock(f.a,'h','acquire',{ranges:[range('20','10')],fence:held.fence})).status).toBe(429);
    expect((await f.lock(f.a,'h','renew',{fence:held.fence})).status).toBe(429);
    expect((await f.lock(f.a,'h','check',{range:range('0','1'),fence:held.fence})).allowed).toBe(true);
    expect((await f.lock(f.a,'h','release',{fence:held.fence})).released).toBe(true);
  });

});
