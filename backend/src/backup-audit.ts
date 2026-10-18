// SPDX-License-Identifier: AGPL-3.0-or-later
// Deep validation of restored audit history before any metadata promotion.
import { sha256 } from '@noble/hashes/sha256';
import type { Env } from './env';
import { backupPageDigest, type BackupCell, type BackupPage } from './backup-state';
import { GENESIS_HASH, hashRecord, type AuditRecord } from './security/audit';

interface Target { id: string; kind: string; name: string; orgId?: string; filespaceId?: string }
interface Session { backupId: string; targets: Target[] }
interface Receipt { kind: string; key: string; bytes: number; sha256: string; verified: boolean }
interface Stub {
  backupCatalogPage(input: {backupId:string;table:string;afterRowId?:number}): Promise<BackupPage>;
  backupExpectedObject(input: {backupId:string;kind:'audit';key:string}): Promise<Receipt|null>;
}
const MAX_BYTES=8*1024*1024, MAX_PAGES=1_000_000, enc=new TextEncoder();
const hex=(bytes:Uint8Array)=>[...sha256(bytes)].map(value=>value.toString(16).padStart(2,'0')).join('');
function fail(reason:string):never {throw new Error(`backup_audit_${reason}`);}
function number(value:unknown,min=0):number {if(!Number.isSafeInteger(value)||Number(value)<min)fail('invalid_sequence');return Number(value);}
function text(value:unknown):string {if(typeof value!=='string')fail('invalid_text');return value;}
function hash(value:unknown):string {if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))fail('invalid_hash');return value;}
function object(value:unknown):Record<string,unknown> {if(!value||typeof value!=='object'||Array.isArray(value))fail('invalid_record');return value as Record<string,unknown>;}
function decode(cell:BackupCell):string|number|null {
  if(cell.type==='null')return null;
  if(cell.type==='text')return text(cell.value);
  if(cell.type==='integer'&&typeof cell.value==='string'&&/^-?(0|[1-9][0-9]*)$/.test(cell.value))return number(Number(cell.value),Number.MIN_SAFE_INTEGER);
  if(cell.type==='real'&&Number.isFinite(cell.value))return cell.value;
  return fail('invalid_metadata_cell');
}
async function* rows(stub:Stub,backupId:string,table:string):AsyncGenerator<Record<string,string|number|null>> {
  let cursor:number|undefined, pages=0;
  do {
    const page=await stub.backupCatalogPage({backupId,table,afterRowId:cursor});
    if(page.table!==table||!Array.isArray(page.rows)||page.rows.length>4096||!Array.isArray(page.columns)||page.columns.length>128
      ||new Set(page.columns).size!==page.columns.length||enc.encode(JSON.stringify(page)).length>MAX_BYTES+1024
      ||backupPageDigest(page)!==page.digest)fail('invalid_metadata_page');
    for(const cells of page.rows){
      if(!Array.isArray(cells)||cells.length!==page.columns.length)fail('invalid_metadata_row');
      const row:Record<string,string|number|null>=Object.create(null);
      cells.forEach((cell,index)=>{row[page.columns[index]]=decode(cell);});yield row;
    }
    if(page.nextRowId===null)return;
    if(!page.rows.length||!Number.isSafeInteger(page.nextRowId)||page.nextRowId<=(cursor??-1)||++pages>MAX_PAGES)fail('invalid_metadata_cursor');
    cursor=page.nextRowId;
  }while(true);
}
async function readObject(env:Env,stub:Stub,backupId:string,key:string,required:boolean):Promise<Uint8Array|null> {
  if(!env.AUDIT_BUCKET)fail('bucket_missing');
  const receipt=await stub.backupExpectedObject({backupId,kind:'audit',key});
  const stored=await env.AUDIT_BUCKET.get(key);
  if(!stored){if(required||receipt)fail('object_missing');return null;}
  try {
    if(!receipt||receipt.kind!=='audit'||receipt.key!==key||receipt.verified!==true
      ||!Number.isSafeInteger(receipt.bytes)||receipt.bytes<0||receipt.bytes>MAX_BYTES||stored.size!==receipt.bytes||stored.size>MAX_BYTES)fail('object_unverified');
    hash(receipt.sha256);
    const chunks:Uint8Array[]=[],reader=stored.body.getReader();let count=0;
    try {
      while(true){const {value,done}=await reader.read();if(done)break;count+=value.byteLength;if(count>receipt.bytes||count>MAX_BYTES)fail('object_size');chunks.push(value);}
    }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
    if(count!==receipt.bytes)fail('object_size');
    const bytes=new Uint8Array(count);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    if(hex(bytes)!==receipt.sha256)fail('object_checksum');return bytes;
  }catch(error){await stored.body.cancel().catch(()=>{});throw error;}
}
function parse(bytes:Uint8Array):unknown {try{return JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:false}).decode(bytes));}catch{return fail('invalid_json');}}
function record(value:unknown,target:Target):AuditRecord {
  const row=object(value);number(row.seq);number(row.ts);hash(row.hash);hash(row.prevHash);
  if(row.orgId!==target.orgId||(row.spaceId!==undefined&&row.spaceId!==target.filespaceId)
    ||typeof row.actorSub!=='string'||typeof row.action!=='string'||!['allow','deny'].includes(String(row.decision))
    ||!['session','service','guest'].includes(String(row.actorType)))fail('record_identity');
  return row as unknown as AuditRecord;
}
interface Chain { seq:number; hash:string }
async function accept(value:AuditRecord,state:Chain):Promise<void> {
  if(value.seq!==state.seq||value.prevHash!==state.hash)fail('chain_gap');
  const {hash:sealed,...unsealed}=value;if(await hashRecord(unsealed)!==sealed)fail('record_hash');
  state.seq++;state.hash=sealed;
}
/** Server-owned cursor. The frozen catalog and immutable object receipts bind
 * every checkpoint; no caller may supply or edit this state. */
export interface AuditValidationProgress {
  targetIndex: number;
  current?: {
    archivedThrough: number; checkpoint: AuditRecord | null;
    archive: Chain; checkpointHash?: string; segmentIndex: number;
    indexHash: string | null; ring?: Chain; ringCursor?: number;
  };
}
export interface AuditValidationStep { complete: boolean; progress: AuditValidationProgress }
function metadataPage(page: BackupPage, table: string): Record<string,string|number|null>[] {
  if(page.table!==table || !Array.isArray(page.columns) || !Array.isArray(page.rows)
    || page.rows.length>4096 || page.columns.length>128 || new Set(page.columns).size!==page.columns.length
    || enc.encode(JSON.stringify(page)).length>MAX_BYTES+1024 || backupPageDigest(page)!==page.digest) fail('invalid_metadata_page');
  return page.rows.map(cells=>{
    if(!Array.isArray(cells)||cells.length!==page.columns.length)fail('invalid_metadata_row');
    const row:Record<string,string|number|null>=Object.create(null);
    cells.forEach((cell,index)=>{row[page.columns[index]]=decode(cell);});return row;
  });
}
/** Bound each HTTP invocation to eight archive segments and four SQL pages.
 * The coordinator persists progress before returning 202, so a Worker restart
 * repeats at most one bounded batch and never promotes partially checked data. */
export async function validateRestoredAuditStep(env:Env,session:Session,previous?:AuditValidationProgress):Promise<AuditValidationStep> {
  const progress:AuditValidationProgress=previous?structuredClone(previous):{targetIndex:0};
  const targets=session.targets.filter(target=>target.kind==='filespace');
  let segmentsLeft=8,pagesLeft=4;
  while(progress.targetIndex<targets.length){
    const target=targets[progress.targetIndex];
    if(!target.orgId||!target.filespaceId||target.name!==`${target.orgId}::${target.filespaceId}`)fail('filespace_identity');
    const stub=env.FILESPACE.get(env.FILESPACE.idFromName(target.name)) as unknown as Stub;
    if(!progress.current){
      let archivedThrough=-1,markerSeen=false,checkpoint:AuditRecord|null=null;
      for await(const row of rows(stub,session.backupId,'meta'))if(row.key==='archived_through_seq'){
        if(markerSeen)fail('duplicate_checkpoint');markerSeen=true;archivedThrough=number(row.value,-1);
      }
      for await(const row of rows(stub,session.backupId,'meta_text')){
        if(row.key==='filespace_key'&&row.value!==target.name)fail('filespace_identity');
        if(row.key==='audit_chain_tail'){
          if(checkpoint)fail('duplicate_checkpoint');checkpoint=record(parse(enc.encode(text(row.value))),target);
          const {hash:sealed,...unsealed}=checkpoint;if(await hashRecord(unsealed)!==sealed)fail('checkpoint_hash');
        }
      }
      progress.current={archivedThrough,checkpoint,archive:{seq:0,hash:GENESIS_HASH},
        checkpointHash:archivedThrough===-1?GENESIS_HASH:undefined,segmentIndex:0,indexHash:null};
    }
    const state=progress.current,prefix=`audit/${target.name}/`;
    if(!state.ring){
      const body=await readObject(env,stub,session.backupId,`${prefix}index.json`,state.archivedThrough>=0);
      const digest=body?hex(body):null;
      if(state.segmentIndex && digest!==state.indexHash)fail('index_changed');
      state.indexHash=digest;
      if(body){
        const index=object(parse(body));
        if(index.filespaceId!==target.name||!Array.isArray(index.segments)||index.segments.length>100_000)fail('invalid_index');
        const seen=new Set<string>();let seq=0,previousHash=GENESIS_HASH;
        // Validate every reference before using the resumed cursor. The index is
        // bounded to 8MiB and its digest stays pinned across requests.
        for(const raw of index.segments){
          const segment=object(raw),key=text(segment.key),first=number(segment.firstSeq),last=number(segment.lastSeq),count=number(segment.count,1);
          if(!key.startsWith(prefix)||key.includes('..')||/[\u0000-\u001f\\]/.test(key)||key.length>2048||seen.has(key)||key===`${prefix}index.json`)fail('unsafe_segment');
          seen.add(key);
          if(first!==seq||last<first||count!==last-first+1||segment.firstPrevHash!==previousHash)fail('index_gap');
          seq=last+1;previousHash=hash(segment.lastHash);
        }
        if(index.ringStartsAtSeq!==seq)fail('index_high_water');
        while(state.segmentIndex<index.segments.length){
          if(segmentsLeft--<=0)return {complete:false,progress};
          const segment=object(index.segments[state.segmentIndex]),key=text(segment.key),count=number(segment.count,1);
          if(segment.firstSeq!==state.archive.seq||segment.firstPrevHash!==state.archive.hash)fail('index_gap');
          const bytes=await readObject(env,stub,session.backupId,key,true);
          let decoded:string;try{decoded=new TextDecoder('utf-8',{fatal:true,ignoreBOM:false}).decode(bytes!);}catch{fail('invalid_json');}
          let offset=0,records=0;
          while(offset<decoded!.length){
            const newline=decoded!.indexOf('\n',offset),end=newline<0?decoded!.length:newline;
            const line=decoded!.slice(offset,end).trim();offset=newline<0?decoded!.length:end+1;if(!line)continue;
            const event=record(parse(enc.encode(line)),target);await accept(event,state.archive);records++;
            if(event.seq===state.archivedThrough)state.checkpointHash=event.hash;
            if(records>count)fail('segment_count');
          }
          if(records!==count||state.archive.seq!==Number(segment.lastSeq)+1||state.archive.hash!==segment.lastHash)fail('segment_count');
          state.segmentIndex++;
        }
      }
      if(state.checkpointHash===undefined||state.archivedThrough>=state.archive.seq)fail('missing_archived_history');
      state.ring={seq:state.archivedThrough+1,hash:state.checkpointHash};
    }
    while(true){
      if(pagesLeft--<=0)return {complete:false,progress};
      const page=await stub.backupCatalogPage({backupId:session.backupId,table:'audit',afterRowId:state.ringCursor});
      const values=metadataPage(page,'audit');
      for(const row of values){
        const event=record(parse(enc.encode(text(row.json))),target);
        if(row.seq!==event.seq||row.ts!==event.ts||row.org_id!==event.orgId||(row.space_id??undefined)!==event.spaceId
          ||row.actor_sub!==event.actorSub||row.action!==event.action||row.decision!==event.decision||row.hash!==event.hash||row.prev_hash!==event.prevHash)fail('ring_columns');
        await accept(event,state.ring);
        if(state.ring.seq===state.archive.seq&&state.ring.hash!==state.archive.hash)fail('archive_ring_fork');
      }
      if(page.nextRowId===null)break;
      if(!values.length||!Number.isSafeInteger(page.nextRowId)||page.nextRowId<=(state.ringCursor??-1))fail('invalid_metadata_cursor');
      state.ringCursor=page.nextRowId;
    }
    if(state.ring.seq<state.archive.seq||(state.ring.seq===state.archive.seq&&state.ring.hash!==state.archive.hash))fail('archive_ring_gap');
    if(state.checkpoint&&(state.checkpoint.seq!==state.ring.seq-1||state.checkpoint.hash!==state.ring.hash))fail('checkpoint_mismatch');
    progress.targetIndex++;delete progress.current;
  }
  return {complete:true,progress};
}
/** Convenience verifier for offline/unit callers. HTTP uses one step per call. */
export async function validateRestoredAudit(env:Env,session:Session):Promise<void> {
  let progress:AuditValidationProgress|undefined;
  while(true){const result=await validateRestoredAuditStep(env,session,progress);if(result.complete)return;progress=result.progress;}
}
