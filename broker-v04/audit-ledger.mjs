import {constants} from 'node:fs';
import {open,lstat,unlink} from 'node:fs/promises';
import path from 'node:path';
import {createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {canonical} from '../broker-v03/client.mjs';
import {sha256,eventDigest,verifyAuditHead} from './core.mjs';

export const AUDIT_MAX_LOG_BYTES=64*1024*1024;
const MAX_LOG=AUDIT_MAX_LOG_BYTES;
const ZERO='0'.repeat(64), HEX=/^[0-9a-f]{64}$/, HEX32=/^[0-9a-f]{32}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ID=/^[A-Za-z0-9_.:-]{1,100}$/;
const ACK_DOMAIN='sac.audit.ack.v1\n';
const CHAIN_DOMAIN='sac.audit.chain.v1\n';
const HEAD_DOMAIN='sac.audit.head.v1\n';
const BASE=['schema','type','owner_id','node','run','proposal_id','action_digest','grant_sha256','nonce','audience','environment'];
function exact(x,keys){return x && typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));}
function matchingIntent(result){
  const out={};for(const key of BASE)out[key]=key==='type'?'intent':result[key];return out;
}
function chainPayload(record,sinkId){
  return {schema:'sac.audit.chain.v1',sink_id:sinkId,seq:record.seq,prev_sha256:record.prev_sha256,
    event_sha256:eventDigest(record.event),
    ack_sha256:sha256(canonical({ack:record.ack,signature_b64url:record.signature_b64url}))};
}
export function validEvent(e){
  const keys=e?.type==='intent'?BASE:e?.type==='result'?[...BASE,'execution_id','effect_sha256']:[];
  return keys.length>0 && exact(e,keys) && e.schema==='sac.audit.event.v1'
    && UUID.test(e.owner_id) && ID.test(e.node) && ID.test(e.run) && UUID.test(e.proposal_id)
    && HEX.test(e.action_digest) && HEX.test(e.grant_sha256) && HEX32.test(e.nonce)
    && typeof e.audience==='string' && /^sac:\/\/broker\/[a-z0-9._/-]{1,100}$/.test(e.audience)
    && ['development','staging','production'].includes(e.environment)
    && (e.type==='intent'||(UUID.test(e.execution_id) && HEX.test(e.effect_sha256)));
}
function verifyStored(record,seq,prev,publicKey,sinkId){
  if(!exact(record,['seq','prev_sha256','event','ack','signature_b64url','chain_signature_b64url']) || record.seq!==seq
     || record.prev_sha256!==prev || !validEvent(record.event))throw new Error('AUDIT_LEDGER_INVALID');
  const a=record.ack;
  if(!exact(a,['schema','sink_id','event_sha256','event_type','accepted_at']) ||
     a.schema!=='sac.audit.ack.v1' || a.sink_id!==sinkId || a.event_sha256!==eventDigest(record.event) ||
     a.event_type!==record.event.type || !Number.isSafeInteger(a.accepted_at)) throw new Error('AUDIT_ACK_INVALID');
  const s=record.signature_b64url;
  if(typeof s!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s))throw new Error('AUDIT_SIGNATURE_INVALID');
  const b=Buffer.from(s,'base64url');
  if(b.length!==64||b.toString('base64url')!==s||!verify(null,Buffer.from(ACK_DOMAIN+canonical(a)),publicKey,b))
    throw new Error('AUDIT_SIGNATURE_INVALID');
  const cs=record.chain_signature_b64url;
  if(typeof cs!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(cs))throw new Error('AUDIT_CHAIN_SIGNATURE_INVALID');
  const cb=Buffer.from(cs,'base64url');
  if(cb.length!==64||cb.toString('base64url')!==cs||
     !verify(null,Buffer.from(CHAIN_DOMAIN+canonical(chainPayload(record,sinkId))),publicKey,cb))
    throw new Error('AUDIT_CHAIN_SIGNATURE_INVALID');
}

/** Verify a complete signed ledger snapshot, optionally against a prior head. */
export function verifyAuditSnapshot({lines,head,trusted,prior=null}){
  if(typeof lines!=='string'||Buffer.byteLength(lines)>MAX_LOG||
     (lines!==''&&!lines.endsWith('\n'))||!verifyAuditHead(head,trusted)||
     (prior!==null&&!verifyAuditHead(prior,trusted)))throw new Error('AUDIT_SNAPSHOT_INVALID');
  if(prior!==null && prior.head.seq>head.head.seq)throw new Error('AUDIT_SNAPSHOT_ROLLBACK');
  const publicKey=createPublicKey({key:trusted.public_jwk,format:'jwk'});
  let seq=0,previous=ZERO;
  let priorMatched=prior===null||(prior.head.seq===0&&prior.head.head_sha256===ZERO);
  const entries=new Set();
  const records=lines===''?[]:lines.slice(0,-1).split('\n');
  for(const line of records){
    if(line==='')throw new Error('AUDIT_LEDGER_NONCANONICAL');
    const record=JSON.parse(line);
    if(canonical(record)!==line)throw new Error('AUDIT_LEDGER_NONCANONICAL');
    verifyStored(record,++seq,previous,publicKey,trusted.id);
    const id=eventDigest(record.event);
    if(entries.has(id))throw new Error('AUDIT_DUPLICATE_EVENT');
    if(record.event.type==='result'&&!entries.has(eventDigest(matchingIntent(record.event))))
      throw new Error('AUDIT_RESULT_WITHOUT_INTENT');
    entries.add(id);previous=sha256(line);
    if(prior!==null&&seq===prior.head.seq)priorMatched=previous===prior.head.head_sha256;
  }
  if(!priorMatched)throw new Error('AUDIT_SNAPSHOT_FORK');
  if(seq!==head.head.seq||previous!==head.head.head_sha256)throw new Error('AUDIT_SNAPSHOT_HEAD_MISMATCH');
  return {seq,head_sha256:previous};
}

/** Independent single-writer process; a stale lock requires operator recovery. */
export async function openAuditLedger({directory,sinkId,privatePem,anchor=null,clock=()=>Math.floor(Date.now()/1000)}){
  if(!path.isAbsolute(directory)||!/^[A-Za-z0-9_.:-]{1,64}$/.test(sinkId||''))throw new Error('AUDIT_CONFIGURATION_INVALID');
  const dir=await lstat(directory);
  if(!dir.isDirectory()||dir.isSymbolicLink()||(dir.mode&0o077)!==0)throw new Error('AUDIT_DIRECTORY_NOT_PRIVATE');
  if(typeof process.getuid==='function' && dir.uid!==process.getuid())throw new Error('AUDIT_DIRECTORY_OWNER_MISMATCH');
  const privateKey=createPrivateKey(privatePem),publicKey=createPublicKey(privateKey);
  if(privateKey.asymmetricKeyType!=='ed25519')throw new Error('AUDIT_ED25519_REQUIRED');
  if(anchor!==null && !verifyAuditHead(anchor,{id:sinkId,public_jwk:publicKey.export({format:'jwk'})}))
    throw new Error('AUDIT_ANCHOR_INVALID');
  const lockPath=path.join(directory,'writer.lock'), filePath=path.join(directory,'audit.jsonl');
  let lock,file;
  try {
    lock=await open(lockPath,'wx',0o600);
    file=await open(filePath,constants.O_RDWR|constants.O_CREAT|constants.O_APPEND|constants.O_NOFOLLOW,0o600);
    const s=await file.stat();
    if(!s.isFile()||s.nlink!==1||(s.mode&0o077)!==0||s.size>MAX_LOG ||
       (typeof process.getuid==='function'&&s.uid!==process.getuid()))throw new Error('AUDIT_FILE_UNSAFE');
    const contents=await file.readFile({encoding:'utf8'});
    if(contents && !contents.endsWith('\n'))throw new Error('AUDIT_LEDGER_TRUNCATED');
    let previous=ZERO,seq=0;const entries=new Map();
    let anchorMatched=anchor===null || (anchor.head.seq===0 && anchor.head.head_sha256===ZERO);
    for(const line of contents.split('\n')){
      if(!line)continue;
      const record=JSON.parse(line);
      if(canonical(record)!==line)throw new Error('AUDIT_LEDGER_NONCANONICAL');
      verifyStored(record,++seq,previous,publicKey,sinkId);
      const id=eventDigest(record.event);
      if(entries.has(id))throw new Error('AUDIT_DUPLICATE_EVENT');
      if(record.event.type==='result'&&!entries.has(eventDigest(matchingIntent(record.event))))
        throw new Error('AUDIT_RESULT_WITHOUT_INTENT');
      entries.set(id,{ack:record.ack,signature_b64url:record.signature_b64url});
      previous=sha256(line);
      if(anchor!==null && seq===anchor.head.seq)anchorMatched=previous===anchor.head.head_sha256;
    }
    if(!anchorMatched)throw new Error('AUDIT_ANCHOR_MISMATCH');
    let tail=Promise.resolve(),closed=false,closing=false,poisoned=false;
    async function append(event){
      if(closed||closing)throw new Error('AUDIT_LEDGER_CLOSING');
      const op=tail.then(async()=>{
        if(poisoned || !validEvent(event))throw new Error('AUDIT_EVENT_INVALID_OR_LEDGER_UNSAFE');
        const id=eventDigest(event);
        if(entries.has(id))return entries.get(id);
        if(event.type==='result'&&!entries.has(eventDigest(matchingIntent(event))))throw new Error('AUDIT_RESULT_WITHOUT_INTENT');
        const ack={schema:'sac.audit.ack.v1',sink_id:sinkId,event_sha256:id,event_type:event.type,accepted_at:clock()};
        if(!Number.isSafeInteger(ack.accepted_at))throw new Error('AUDIT_TIME_INVALID');
        const signature=sign(null,Buffer.from(ACK_DOMAIN+canonical(ack)),privateKey).toString('base64url');
        const record={seq:seq+1,prev_sha256:previous,event,ack,signature_b64url:signature};
        record.chain_signature_b64url=sign(null,Buffer.from(CHAIN_DOMAIN+canonical(chainPayload(record,sinkId))),privateKey).toString('base64url');
        const line=canonical(record);
        const stat=await file.stat();
        if(stat.size+Buffer.byteLength(line)+1>MAX_LOG)throw new Error('AUDIT_LOG_FULL');
        try {await file.writeFile(line+'\n'); await file.sync();}
        catch(err){poisoned=true;throw err;}
        seq++; previous=sha256(line);
        const envelope={ack,signature_b64url:signature};entries.set(id,envelope);return envelope;
      });
      tail=op.catch(()=>{});return op;
    }
    function makeHead(){
      if(poisoned)throw new Error('AUDIT_LEDGER_UNSAFE');
      const head={schema:'sac.audit.head.v1',sink_id:sinkId,seq,head_sha256:previous,captured_at:clock()};
      if(!Number.isSafeInteger(head.captured_at))throw new Error('AUDIT_TIME_INVALID');
      return {head,signature_b64url:sign(null,Buffer.from(HEAD_DOMAIN+canonical(head)),privateKey).toString('base64url')};
    }
    async function signedHead(){
      if(closed||closing)throw new Error('AUDIT_LEDGER_CLOSING');
      const op=tail.then(makeHead);
      tail=op.catch(()=>{});return op;
    }
    async function snapshot(){
      if(closed||closing)throw new Error('AUDIT_LEDGER_CLOSING');
      const op=tail.then(async()=>{
        if(poisoned)throw new Error('AUDIT_LEDGER_UNSAFE');
        const stat=await file.stat();
        if(stat.size>MAX_LOG)throw new Error('AUDIT_LOG_FULL');
        const bytes=Buffer.alloc(stat.size);let offset=0;
        while(offset<bytes.length){
          const {bytesRead}=await file.read(bytes,offset,bytes.length-offset,offset);
          if(bytesRead===0)throw new Error('AUDIT_SNAPSHOT_READ_FAILED');
          offset+=bytesRead;
        }
        return {lines:new TextDecoder('utf-8',{fatal:true}).decode(bytes),head:makeHead()};
      });
      tail=op.catch(()=>{});return op;
    }
    return {append,signedHead,snapshot, async close(){if(closing||closed)throw new Error('AUDIT_LEDGER_CLOSING');
      closing=true;await tail;closed=true;await file.close();await lock.close();await unlink(lockPath);}};
  } catch(err){
    if(file)await file.close().catch(()=>{});
    if(lock){await lock.close().catch(()=>{});await unlink(lockPath).catch(()=>{});}
    throw err;
  }
}
