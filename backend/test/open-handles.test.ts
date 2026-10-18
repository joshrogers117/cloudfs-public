// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { NamespaceStore } from '../src/metadata/namespace';
import { OpenHandleStore, OPEN_HANDLE_DELETE, OPEN_HANDLE_MAX_PER_OWNER, OPEN_HANDLE_READ, OPEN_HANDLE_WRITE } from '../src/metadata/open-handles';
import type { FilespaceDO } from '../src/filespace-do';
import { DoAclStore } from '../src/metadata/acl-store';
import type { Principal } from '../src/permissions';

const bindings=env as Env;
const block=(hash:string)=>({chunkIdx:0,blockIdx:0,blockHash:hash,objectKey:`blocks/${hash}`,offset:0,length:16});
const fresh=()=>bindings.FILESPACE.getByName(`open-${crypto.randomUUID()}`);

describe('durable open inode handles',()=>{
  it('keeps ordinary deletion eager when no handle is active',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const ns=new NamespaceStore(state.storage.sql),item=ns.put('root','plain',false,16);
      ns.setBlockMap(item.id,[block('plain')]);
      expect(ns.remove(item.id).deleted).toBe(true);
      expect(ns.getBlockMap(item.id)).toEqual([]);
      expect(Number(state.storage.sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','plain').one().refcount)).toBe(0);
    });
  });

  it('retains a replaced destination inode until its final handle closes',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
      const source=ns.put('root','new.tmp',false,16),destination=ns.put('root','project',false,16);
      ns.setBlockMap(source.id,[block('new-image')]);ns.setBlockMap(destination.id,[block('old-image')]);
      const now=Date.now(),opened=handles.acquire({handleId:crypto.randomUUID(),owner:'u:d',inodeId:destination.id,
        accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,expiresAt:now+60_000},now);
      expect(opened.granted).toBe(true);
      const renamed=ns.rename(source.id,{name:'project',expectedVersion:ns.getItem(source.id)!.version,
        replace:{id:destination.id,expectedVersion:ns.getItem(destination.id)!.version}});
      expect(renamed.id).toBe(source.id);expect(ns.liveSiblingByName('root','project')?.id).toBe(source.id);
      expect(ns.getItem(destination.id)?.deleted).toBe(true);
      expect(ns.getBlockMap(destination.id)).toHaveLength(1);
      expect(Number(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','old-image').one().refcount)).toBe(1);
      const closed=handles.close(opened.granted?opened.handle.handleId:'', 'u:d');
      expect(closed).toMatchObject({closed:true,inodeId:destination.id});
      expect(ns.reclaimUnopenedPayload(destination.id)).toBe(true);
      expect(ns.getBlockMap(destination.id)).toEqual([]);
      expect(Number(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','old-image').one().refcount)).toBe(0);
    });
  });

  it('releases retained payload when the last handle expires in a bounded reap',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
      const item=ns.put('root','expires',false,16);ns.setBlockMap(item.id,[block('expires')]);
      const now=Date.now(),expiry=now+1_000,handleId=crypto.randomUUID();
      expect(handles.acquire({handleId,owner:'u:d',inodeId:item.id,accessMask:OPEN_HANDLE_READ,shareMask:7,expiresAt:expiry},now).granted).toBe(true);
      ns.remove(item.id);
      expect(ns.getBlockMap(item.id)).toHaveLength(1);
      expect(handles.reapCandidates(expiry-1)).toEqual([]);
      expect(handles.acquire({handleId,owner:'u:d',inodeId:item.id,accessMask:OPEN_HANDLE_READ,shareMask:7,
        expiresAt:expiry+1_000},expiry)).toMatchObject({granted:false,reason:'expired'});
      const expired=handles.reapCandidates(expiry);
      expect(expired).toEqual([item.id]);
      expect(ns.reclaimUnopenedPayload(item.id,expiry)).toBe(true);
      expect(ns.reclaimUnopenedPayload(item.id,expiry)).toBe(false);
      expect(ns.getBlockMap(item.id)).toEqual([]);
      expect(handles.nextExpiry()).toBeNull();
    });
  });

  it('reclaims restored tombstones in bounded alarm work after volatile handles are omitted',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
      const now=Date.now(),first=ns.put('root','restored-a',false,16),second=ns.put('root','restored-b',false,16);
      ns.setBlockMap(first.id,[block('restored-a')]);ns.setBlockMap(second.id,[block('restored-b')]);
      ns.putStream(first.id,'AFP_AfpInfo',new Uint8Array([1,2,3]));
      for (const item of [first,second]) {
        handles.acquire({handleId:crypto.randomUUID(),owner:'u:d',inodeId:item.id,accessMask:OPEN_HANDLE_READ,
          shareMask:7,expiresAt:now+60_000},now);
        expect(ns.remove(item.id).deleted).toBe(true);
      }
      expect(ns.getBlockMap(first.id)).toHaveLength(1);
      // Restore promotes tombstones but excludes open_handles. Arm the persisted
      // post-restore sweep as backupRestoreCommit does, then run one DO alarm.
      sql.exec('DELETE FROM open_handles;');
      sql.exec("INSERT INTO meta(key,value) VALUES('restore_open_cleanup',1) ON CONFLICT(key) DO UPDATE SET value=1;");
      await fs.alarm();
      expect(ns.getBlockMap(first.id)).toEqual([]);
      expect(ns.getBlockMap(second.id)).toEqual([]);
      expect(ns.getStream(first.id,'AFP_AfpInfo')).toBeNull();
      expect(Number(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','restored-a').one().refcount)).toBe(0);
      expect(Number(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?','restored-b').one().refcount)).toBe(0);
      expect(Number(sql.exec("SELECT value FROM meta WHERE key='restore_open_cleanup'").one().value)).toBe(0);
    });
  });

  it('retains only opened members of a recursively deleted subtree',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
      const folder=ns.put('root','folder',true,0),opened=ns.put(folder.id,'opened',false,16),closed=ns.put(folder.id,'closed',false,16);
      ns.setBlockMap(opened.id,[block('opened')]);ns.setBlockMap(closed.id,[block('closed')]);
      const now=Date.now();handles.acquire({handleId:crypto.randomUUID(),owner:'u:d',inodeId:opened.id,
        accessMask:OPEN_HANDLE_READ,shareMask:7,expiresAt:now+60_000},now);
      expect(ns.removeSubtree(folder.id).deleted).toHaveLength(3);
      expect(ns.getBlockMap(opened.id)).toHaveLength(1);
      expect(ns.getBlockMap(closed.id)).toEqual([]);
      expect(ns.getItem(folder.id)?.deleted).toBe(true);
    });
  });

  it('enforces two-way sharing compatibility, stable retries, expiry and owner isolation',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const ns=new NamespaceStore(state.storage.sql),handles=new OpenHandleStore(state.storage.sql),item=ns.put('root','shared',false,0);
      const now=Date.now(),firstId=crypto.randomUUID(),expiresAt=now+60_000;
      const first=handles.acquire({handleId:firstId,owner:'u:device-a',inodeId:item.id,accessMask:OPEN_HANDLE_READ,
        shareMask:OPEN_HANDLE_READ,expiresAt},now);
      expect(first.granted).toBe(true);
      expect(handles.acquire({handleId:firstId,owner:'u:device-a',inodeId:item.id,accessMask:7,shareMask:7,expiresAt},now+10))
        .toMatchObject({granted:false,reason:'handle_conflict'});
      const retry=handles.acquire({handleId:firstId,owner:'u:device-a',inodeId:item.id,accessMask:OPEN_HANDLE_READ,
        shareMask:OPEN_HANDLE_READ,expiresAt},now+10);
      expect(retry).toMatchObject({granted:true,reused:true,handle:{expiresAt}});
      expect(handles.acquire({handleId:crypto.randomUUID(),owner:'u:device-b',inodeId:item.id,accessMask:OPEN_HANDLE_WRITE,
        shareMask:7,expiresAt:now+60_000},now)).toMatchObject({granted:false,reason:'sharing_violation'});
      expect(handles.hasAccess(item.id,'u:device-a',OPEN_HANDLE_READ,now)).toBe(true);
      expect(handles.hasAccess(item.id,'u:device-b',OPEN_HANDLE_READ,now)).toBe(false);
      expect(handles.close(firstId,'u:device-b')).toMatchObject({closed:false,reason:'forbidden'});
      expect(handles.deleteSharingAllowed(item.id,now)).toBe(false);
      expect(handles.close(firstId,'u:device-a')).toMatchObject({closed:true});
      expect(handles.deleteSharingAllowed(item.id,now)).toBe(true);
      expect(handles.acquire({handleId:firstId,owner:'u:device-a',inodeId:item.id,accessMask:OPEN_HANDLE_READ,
        shareMask:OPEN_HANDLE_READ,expiresAt:now+60_000},now+1)).toMatchObject({granted:true,reused:false});
      // Constants are shared with the DO path and remain the expected bit layout.
      expect([OPEN_HANDLE_READ,OPEN_HANDLE_WRITE,OPEN_HANDLE_DELETE]).toEqual([1,2,4]);
    });
  });

  it('allows the exact delete-capable initiating handle while preserving every other share-delete constraint',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
      const item=ns.put('root','own-handle-delete',false,0),now=Date.now();
      const own='own-handle',other='other-handle',owner='member:device';
      expect(handles.acquire({handleId:own,owner,inodeId:item.id,accessMask:OPEN_HANDLE_DELETE,shareMask:0,
        expiresAt:now+60_000},now).granted).toBe(true);
      expect(handles.deleteSharingAllowed(item.id,now,owner,own)).toBe(true);
      expect(handles.deleteSharingAllowed(item.id,now,'different-owner',own)).toBe(false);
      // A different same-owner handle with share=0 is never exempted by the
      // initiating handle id, even though normal share checks prevent both from
      // being simultaneously acquired in this case.
      expect(handles.close(own,owner).closed).toBe(true);
      expect(handles.acquire({handleId:other,owner,inodeId:item.id,accessMask:0,
        shareMask:0,expiresAt:now+60_000},now).granted).toBe(true);
      expect(handles.deleteSharingAllowed(item.id,now,owner,own)).toBe(false);
      expect(ns.remove(item.id,undefined,owner,own)).toMatchObject({deleted:false,reason:'sharing_violation'});
      expect(ns.remove(item.id,undefined,owner,other)).toMatchObject({deleted:false,reason:'sharing_violation'});
      expect(handles.close(other,owner).closed).toBe(true);
      expect(ns.remove(item.id,undefined,owner,other).deleted).toBe(true);
    });
  });

  it('allows an open DELETE handle to rename its own inode but never bypasses another inode handle',async()=>{
    await runInDurableObject(fresh(),async(_fs,state)=>{
      const sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
      const source=ns.put('root','before',false,0),destination=ns.put('root','after',false,0),now=Date.now();
      const owner='u:d',own='rename-handle';
      handles.acquire({handleId:own,owner,inodeId:source.id,accessMask:OPEN_HANDLE_DELETE,shareMask:0,
        expiresAt:now+60_000},now);
      const renamed=ns.rename(source.id,{name:'moved',owner,openHandle:own});
      expect(renamed.name).toBe('moved');
      const targetHandle='target-handle';
      handles.acquire({handleId:targetHandle,owner,inodeId:destination.id,accessMask:OPEN_HANDLE_READ,
        shareMask:OPEN_HANDLE_READ,expiresAt:now+60_000},now);
      expect(()=>ns.rename(source.id,{name:'after',owner,openHandle:own,
        replace:{id:destination.id,expectedVersion:destination.version}})).toThrow('share delete access');
      expect(ns.getItem(destination.id)?.deleted).toBe(false);
    });
  });

  it('threads an authenticated initiating handle through DO delete and rename',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,ns=new NamespaceStore(state.storage.sql);
      const principal={type:'user' as const,id:'owner',orgRole:'owner' as const},owner='owner:device';
      const deleted=ns.put('root','delete-own-handle',false,0),deleteHandle=crypto.randomUUID();
      expect(await fs.beginOpenFor(principal,deleted.id,owner,{handleId:deleteHandle,accessMask:OPEN_HANDLE_DELETE,shareMask:0,ttlMs:60_000}))
        .toMatchObject({granted:true});
      expect(await fs.deleteItem(deleted.id,undefined,owner,deleteHandle)).toMatchObject({deleted:true});
      expect(ns.getItem(deleted.id)?.deleted).toBe(true);

      const moved=ns.put('root','rename-own-handle',false,0),renameHandle=crypto.randomUUID();
      expect(await fs.beginOpenFor(principal,moved.id,owner,{handleId:renameHandle,accessMask:OPEN_HANDLE_DELETE,shareMask:0,ttlMs:60_000}))
        .toMatchObject({granted:true});
      expect(await fs.renameItem(moved.id,{name:'renamed-own-handle',owner,openHandle:renameHandle,principal}))
        .toMatchObject({item:{id:moved.id,name:'renamed-own-handle'}});
    });
  });

  it('renews bounded handle batches transactionally with per-handle ACL and owner checks',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,ns=new NamespaceStore(state.storage.sql),handles=new OpenHandleStore(state.storage.sql);
      const item=ns.put('root','batch-renew',false,0),owner='owner:device',principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
      const now=Date.now(),ids=[crypto.randomUUID(),crypto.randomUUID()];
      for(const handleId of ids) handles.acquire({handleId,owner,inodeId:item.id,accessMask:OPEN_HANDLE_READ,
        shareMask:7,expiresAt:now+30_000},now);
      const renewed=await fs.renewOpenBatchFor(principal,owner,ids,60_000);
      expect(renewed.handles).toHaveLength(2);
      expect(renewed.handles.every(handle=>handle.granted&&handle.expiresAt!>=now+59_000)).toBe(true);
      expect(await fs.renewOpenBatchFor(principal,'other:device',ids,60_000)).toMatchObject({handles:[
        {granted:false,reason:'forbidden'},{granted:false,reason:'forbidden'},
      ]});
      expect(await fs.renewOpenBatchFor(principal,owner,Array.from({length:129},()=>crypto.randomUUID()),60_000)).toEqual({handles:[]});
    });
  });

  it('applies metadata through an old writable inode without changing its path replacement',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,ns=new NamespaceStore(state.storage.sql);
      const principal={type:'user' as const,id:'owner',orgRole:'owner' as const},owner='owner:device';
      const old=ns.put('root','same-name',false,0,{id:'old-inode'}),handleId=crypto.randomUUID();
      const opened=await fs.beginOpenFor(principal,old.id,owner,{handleId,accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000});
      expect(opened.granted).toBe(true);
      expect(ns.remove(old.id).deleted).toBe(true);
      const tombstone=ns.getItem(old.id)!,seq=tombstone.updatedSeq,currentSeq=ns.currentSeq();
      const updated=await fs.setBasicInfoFor(principal,old.id,{expectedVersion:tombstone.version,modifiedAt:1234,fileAttributes:32},owner);
      expect(updated).toMatchObject({item:{id:old.id,deleted:true,modifiedAt:1234,fileAttributes:32,updatedSeq:seq}});
      expect(ns.currentSeq()).toBe(currentSeq);
      const replacement=ns.put('root','same-name',false,0,{id:'new-inode'});
      expect(replacement).toMatchObject({id:'new-inode',deleted:false,fileAttributes:0});
      expect(ns.getItem(old.id)).toMatchObject({deleted:true,fileAttributes:32,modifiedAt:1234});
    });
  });

  it('serves a tombstoned inode only through its live handle and current ACL',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,ns=new NamespaceStore(state.storage.sql),acl=new DoAclStore(state.storage.sql);
      const folder=ns.put('root','scope',true,0),item=ns.put(folder.id,'file',false,16);
      const principal:Principal={type:'user',id:'member',orgRole:'standard'};
      acl.putGrant({id:'edit',spaceId:'space',inodeId:folder.id,principalType:'user',principalId:principal.id,
        level:'edit',mountAsRoot:false,expiresAt:null,grantedByMemberId:'owner',grantedAt:Date.now(),authorityGrantId:null,authorityInodeId:null});
      ns.setBlockMap(item.id,[block('open-data')]);
      const opened=await fs.beginOpenFor(principal,item.id,'member:device',{
        handleId:crypto.randomUUID(),accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000,
      });
      expect(opened.granted).toBe(true);
      expect(ns.remove(item.id).deleted).toBe(true);
      expect(fs.checkOpenAccess(principal,item.id,'read','member:device').allow).toBe(true);
      expect(fs.checkOpenAccess(principal,item.id,'read','member:other-device').allow).toBe(false);
      const retained=ns.getItem(item.id)!;
      const write=await fs.setBlockMap(item.id,[block('open-data')],{expectedVersion:retained.version,owner:'member:device',principal});
      expect(write).toMatchObject({deleted:true});
      acl.deleteGrant('edit');
      expect(fs.checkOpenAccess(principal,item.id,'read','member:device').allow).toBe(false);
      expect(ns.getBlockMap(item.id)).toHaveLength(1);
      const closed=await fs.closeOpenFor('member:device',opened.granted? (state.storage.sql.exec('SELECT handle_id FROM open_handles WHERE inode_id=?',item.id).one().handle_id as string):'');
      expect(closed.closed).toBe(true);
      expect(ns.getBlockMap(item.id)).toEqual([]);
    });
  });

  it('denies writable opens on DOS read-only files and supports metadata-only directory handles',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,ns=new NamespaceStore(state.storage.sql),acl=new DoAclStore(state.storage.sql);
      const folder=ns.put('root','scope',true,0),item=ns.put(folder.id,'readonly',false,0);
      const principal:Principal={type:'user',id:'member',orgRole:'standard'};
      acl.putGrant({id:'edit',spaceId:'space',inodeId:folder.id,principalType:'user',principalId:principal.id,
        level:'edit',mountAsRoot:false,expiresAt:null,grantedByMemberId:'owner',grantedAt:Date.now(),authorityGrantId:null,authorityInodeId:null});
      ns.setBasicInfo(item.id,{fileAttributes:1},item.version);
      expect(await fs.beginOpenFor(principal,item.id,'member:device',{
        handleId:crypto.randomUUID(),accessMask:OPEN_HANDLE_READ|OPEN_HANDLE_WRITE,shareMask:7,ttlMs:60_000,
      })).toMatchObject({granted:false,reason:'forbidden'});
      const directory=await fs.beginOpenFor(principal,folder.id,'member:device',{
        handleId:crypto.randomUUID(),accessMask:0,shareMask:OPEN_HANDLE_READ,ttlMs:60_000,
      });
      expect(directory.granted).toBe(true);
    });
  });

  it('validates optional stream lookup objects again inside the DO',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,ns=new NamespaceStore(state.storage.sql);
      const item=ns.put('root','validate-stream-lookup',false,0),principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
      for (const stream of [null,{}, {name:'',required:true}, {name:'a/b',required:true}, {name:'fork',required:1}]) {
        const handleId=crypto.randomUUID();
        const result=await fs.beginOpenFor(principal,item.id,'owner:device',{
          handleId,accessMask:OPEN_HANDLE_READ,shareMask:7,ttlMs:60_000,stream,
        } as never);
        expect(result).toMatchObject({granted:false,reason:'invalid'});
        expect(Number(state.storage.sql.exec('SELECT COUNT(*) AS count FROM open_handles WHERE handle_id=?',handleId).one().count)).toBe(0);
      }
    });
  });

  it('returns handle capacity before inspecting a required missing stream',async()=>{
    await runInDurableObject(fresh(),async(instance,state)=>{
      const fs=instance as unknown as FilespaceDO,sql=state.storage.sql,ns=new NamespaceStore(sql);
      const item=ns.put('root','stream-capacity-order',false,0),owner='owner:device',principal={type:'user' as const,id:'owner',orgRole:'owner' as const};
      const now=Date.now();
      const ids=JSON.stringify(Array.from({length:OPEN_HANDLE_MAX_PER_OWNER},(_,i)=>`capacity-${i}`));
      sql.exec(`INSERT INTO open_handles(handle_id,owner,inode_id,access_mask,share_mask,opened_at,expires_at)
        SELECT value,?,?,0,7,?,? FROM json_each(?);`,owner,item.id,now,now+60_000,ids);
      const attempt=crypto.randomUUID();
      expect(await fs.beginOpenFor(principal,item.id,owner,{handleId:attempt,accessMask:OPEN_HANDLE_READ,shareMask:7,ttlMs:60_000,
        stream:{name:'missing-fork',required:true}})).toMatchObject({granted:false,reason:'capacity'});
      expect(Number(sql.exec('SELECT COUNT(*) AS count FROM open_handles WHERE handle_id=?',attempt).one().count)).toBe(0);
    });
  });
});
