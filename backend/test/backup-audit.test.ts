// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe,it,expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { validateRestoredAudit, validateRestoredAuditStep } from '../src/backup-audit';
import { backupPageDigest,type BackupCell,type BackupPage } from '../src/backup-state';
import { AuditLog,InMemoryAuditStore,GENESIS_HASH,type AuditRecord,hashRecord } from '../src/security/audit';
import type { Env } from '../src/env';

const encode=new TextEncoder(),hex=(value:Uint8Array)=>[...sha256(value)].map(byte=>byte.toString(16).padStart(2,'0')).join('');
const prefix='audit/org::space/';
const session={backupId:'restore-generation',targets:[{id:'filespace:org::space',kind:'filespace',name:'org::space',orgId:'org',filespaceId:'space'}]};
const cell=(value:unknown):BackupCell=>value===null?{type:'null'}:typeof value==='number'?{type:'integer',value:String(value)}:{type:'text',value:String(value)};
function page(table:string,values:Record<string,unknown>[],columns?:string[],nextRowId:number|null=null):BackupPage {
  const body={table,columns:columns??Object.keys(values[0]??{}),rows:values.map(row=>(columns??Object.keys(row)).map(key=>cell(row[key]))),nextRowId};return {...body,digest:backupPageDigest(body)};
}
const auditRow=(event:AuditRecord)=>({seq:event.seq,ts:event.ts,org_id:event.orgId,space_id:event.spaceId??null,actor_sub:event.actorSub,action:event.action,decision:event.decision,prev_hash:event.prevHash,hash:event.hash,json:JSON.stringify(event)});
async function fixture({archived=4,through=archived-1,total=6,segmentSize=2}:{archived?:number;through?:number;total?:number;segmentSize?:number}={}) {
  const log=new AuditLog(new InMemoryAuditStore()),records:AuditRecord[]=[];
  for(let i=0;i<total;i++)records.push(await log.write({actorSub:'owner',actorType:'session',orgId:'org',spaceId:'space',action:'item.create',decision:'allow',detail:{index:i}},1000+i));
  const objects=new Map<string,Uint8Array>(),receipts=new Map<string,{kind:string;key:string;bytes:number;sha256:string;verified:boolean}>(),gets:string[]=[],pages:string[]=[];
  const put=(key:string,value:unknown,raw=false)=>{const bytes=encode.encode(raw?String(value):JSON.stringify(value));objects.set(key,bytes);receipts.set(key,{kind:'audit',key,bytes:bytes.length,sha256:hex(bytes),verified:true});};
  const segments=[];
  for(let i=0;i<archived;i+=segmentSize){
    const group=records.slice(i,Math.min(i+segmentSize,archived)),first=group[0],last=group.at(-1)!,key=`${prefix}1970-01-01/${first.seq}-${last.seq}.ndjson`;
    put(key,group.map(value=>JSON.stringify(value)).join('\n'),true);
    segments.push({date:'1970-01-01',key,firstSeq:first.seq,lastSeq:last.seq,firstPrevHash:first.prevHash,lastHash:last.hash,count:group.length});
  }
  const index={filespaceId:'org::space',segments,ringStartsAtSeq:archived};
  if(archived)put(`${prefix}index.json`,index);
  const ring=records.slice(through+1).map(auditRow),meta=[{key:'archived_through_seq',value:through}],metaText=[{key:'filespace_key',value:'org::space'},...(total?[{key:'audit_chain_tail',value:JSON.stringify(records.at(-1))}]:[])];
  const stub={
    async backupExpectedObject(input:{key:string}) {return receipts.get(input.key)??null;},
    async backupCatalogPage(input:{table:string;afterRowId?:number}){
      pages.push(input.table);
      if(input.table==='meta')return page('meta',meta);
      if(input.table==='meta_text')return page('meta_text',metaText);
      // One ring record per page proves the verifier carries chain state across pages.
      const offset=input.afterRowId===undefined?0:input.afterRowId+1;
      return page('audit',ring.slice(offset,offset+1),['seq','ts','org_id','space_id','actor_sub','action','decision','prev_hash','hash','json'],offset+1<ring.length?offset:null);
    },
  };
  const env={FILESPACE:{idFromName:(name:string)=>name,get:()=>stub},AUDIT_BUCKET:{async get(key:string){gets.push(key);const bytes=objects.get(key);return bytes?{size:bytes.length,body:new Response(bytes).body!}:null;}}} as unknown as Env;
  return {env,records,objects,receipts,gets,pages,put,index,ring,meta,metaText,stub};
}
describe('restored audit completeness',()=>{
  it('verifies all archived segments, receipt bytes, paged resident ring and persistent tail',async()=>{
    const f=await fixture();await validateRestoredAudit(f.env,session);
    expect(f.gets).toEqual([`${prefix}index.json`,`${prefix}1970-01-01/0-1.ndjson`,`${prefix}1970-01-01/2-3.ndjson`]);
    expect(f.pages.filter(table=>table==='audit')).toHaveLength(2);
  });
  it('accepts index publication ahead of SQL trimming only if the overlapping ring rejoins the same chain',async()=>{
    const f=await fixture({archived:4,through:1});await validateRestoredAudit(f.env,session);
    const changed={...f.records[2],action:'changed'};const {hash:_,...unsealed}=changed;changed.hash=await hashRecord(unsealed);
    f.ring[0]=auditRow(changed);await expect(validateRestoredAudit(f.env,session)).rejects.toThrow(/backup_audit_/);
  });
  it('accepts a never-archived genesis ring, an empty filespace and an entirely archived empty ring',async()=>{
    for(const options of [{archived:0,total:2},{archived:0,total:0},{archived:4,total:4}]){
      const f=await fixture(options);await validateRestoredAudit(f.env,session);
    }
  });
  it('requires the archived index and every segment to exist and have a verified expectation',async()=>{
    for(const kind of ['missingIndex','missingSegment','unverifiedIndex','unverifiedSegment','missingReceipt']){
      const f=await fixture(),segment=f.index.segments[0].key;
      if(kind==='missingIndex')f.objects.delete(`${prefix}index.json`);
      if(kind==='missingSegment')f.objects.delete(segment);
      if(kind==='unverifiedIndex')f.receipts.get(`${prefix}index.json`)!.verified=false;
      if(kind==='unverifiedSegment')f.receipts.get(segment)!.verified=false;
      if(kind==='missingReceipt')f.receipts.delete(segment);
      await expect(validateRestoredAudit(f.env,session)).rejects.toThrow(/backup_audit_/);
    }
  });
  it('rejects unsafe segment references before reading them, cross-filespace indexes and malformed index bounds',async()=>{
    for(const mutate of [
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.index.segments[0].key='audit/other::space/private.ndjson';},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.index.segments[0].key=`${prefix}../escape.ndjson`;},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.index.filespaceId='another';},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.index.segments[1].firstSeq++;},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.index.ringStartsAtSeq++;},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.index.segments[0].count++;},
    ]){
      const f=await fixture();mutate(f);f.put(`${prefix}index.json`,f.index);
      await expect(validateRestoredAudit(f.env,session)).rejects.toThrow(/backup_audit_/);
      expect(f.gets.some(key=>key.includes('..')||key.startsWith('audit/other'))).toBe(false);
    }
  });
  it('rejects byte corruption and semantically altered records even when an object receipt is recomputed',async()=>{
    for(const reseal of [false,true]){
      const f=await fixture(),key=f.index.segments[0].key;
      const altered=[{...f.records[0],action:'tampered'},f.records[1]].map(value=>JSON.stringify(value)).join('\n');
      if(reseal)f.put(key,altered,true);else f.objects.set(key,encode.encode(altered));
      await expect(validateRestoredAudit(f.env,session)).rejects.toThrow(/backup_audit_/);
    }
  });
  it('rejects missing newest ring rows, detached persistent tails, SQL/JSON disagreement and archive gaps',async()=>{
    for(const mutate of [
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.ring.pop();},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.ring[0].action='different-column';},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.meta[0].value=8;},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.metaText[1].value=JSON.stringify(f.records[3]);},
      (f:Awaited<ReturnType<typeof fixture>>)=>{f.metaText[0].value='other::space';},
    ]){
      const f=await fixture();mutate(f);await expect(validateRestoredAudit(f.env,session)).rejects.toThrow(/backup_audit_/);
    }
  });
  it('rejects oversized remote objects before consuming their bodies and malformed metadata digests',async()=>{
    const f=await fixture();let read=false;
    (f.env.AUDIT_BUCKET as unknown as {get:()=>Promise<unknown>}).get=async()=>({size:8*1024*1024+1,body:new ReadableStream({pull(){read=true;}})});
    await expect(validateRestoredAudit(f.env,session)).rejects.toThrow(/backup_audit_/);
    // A default stream may pre-pull; receipt bounds, not body acceptance, decide failure.
    const second=await fixture();second.stub.backupCatalogPage=async()=>({...page('meta',[]),digest:GENESIS_HASH});
    await expect(validateRestoredAudit(second.env,session)).rejects.toThrow('backup_audit_invalid_metadata_page');
  });
});

describe('bounded restored audit validation',()=>{
  it('persists progress across many segment/page batches without rereading completed segments',async()=>{
    const f=await fixture({archived:80,through:69,total:100});
    let progress,steps=0;
    while(true){
      const before=f.gets.length,result=await validateRestoredAuditStep(f.env,session,progress);
      expect(f.gets.length-before).toBeLessThanOrEqual(9);
      // JSON serialization simulates the coordinator surviving a process restart.
      progress=JSON.parse(JSON.stringify(result.progress));steps++;
      if(result.complete)break;
      expect(steps).toBeLessThan(30);
    }
    expect(steps).toBeGreaterThan(5);
    const segments=f.gets.filter(key=>key.endsWith('.ndjson'));
    expect(segments).toHaveLength(40);expect(new Set(segments).size).toBe(40);
  });
  it('rejects late corruption after an earlier batch was durably checkpointed',async()=>{
    const f=await fixture({archived:40,total:42});
    const first=await validateRestoredAuditStep(f.env,session);expect(first.complete).toBe(false);
    f.objects.set(f.index.segments[9].key,encode.encode('corrupt'));
    await expect(validateRestoredAuditStep(f.env,session,first.progress)).rejects.toThrow(/backup_audit_/);
  });
  it('pins the audit index digest across independently resumed requests',async()=>{
    const f=await fixture({archived:40,total:42});
    const first=await validateRestoredAuditStep(f.env,session);
    f.put(`${prefix}index.json`,{...f.index,extra:'changed after checkpoint'});
    await expect(validateRestoredAuditStep(f.env,session,first.progress)).rejects.toThrow('backup_audit_index_changed');
  });
});

it('validates a 20,000-event archive across independently serialized restart checkpoints',async()=>{
  const f=await fixture({archived:20000,total:20032,segmentSize:100});
  let progress,steps=0;
  while(true){const result=await validateRestoredAuditStep(f.env,session,progress);steps++;
    if(result.complete)break;progress=JSON.parse(JSON.stringify(result.progress));
    expect(steps).toBeLessThan(50);
  }
  expect(steps).toBeGreaterThanOrEqual(25);
  expect(f.gets.filter(key=>key.endsWith('.ndjson'))).toHaveLength(200);
},30000);
