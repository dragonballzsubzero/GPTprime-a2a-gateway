import {constants} from 'node:fs';
import {open,lstat,readdir,unlink,link} from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {canonical} from '../broker-v03/client.mjs';
import {verifyAuditSnapshot,AUDIT_MAX_LOG_BYTES} from './audit-ledger.mjs';
import {verifyAuditHead} from './core.mjs';

const NAME=/^checkpoint-([0-9]{12})-([a-f0-9]{64})\.json$/;
const MAX_CHECKPOINT=2*AUDIT_MAX_LOG_BYTES+32768;
function sameHead(a,b){return a.head.seq===b.head.seq&&a.head.head_sha256===b.head.head_sha256;}
function exact(x,keys){return x&&typeof x==='object'&&!Array.isArray(x)&&
  Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));}

/**
 * Independent checkpoint candidate. The directory must live under a different
 * operator and durable storage boundary from the audited ledger. An externally
 * retained latest head is required to reopen a populated directory. This code
 * cannot protect against deletion by an administrator of its own storage.
 */
export async function openAuditWitness({directory,trusted,expectedHead=null,bootstrap=false}){
  if(!path.isAbsolute(directory)||!trusted||typeof bootstrap!=='boolean'||
     (bootstrap&&expectedHead!==null))throw new Error('WITNESS_CONFIGURATION_INVALID');
  const pinnedTrust=JSON.parse(canonical(trusted));
  if(expectedHead!==null&&!verifyAuditHead(expectedHead,pinnedTrust))throw new Error('WITNESS_CONFIGURATION_INVALID');
  const pinnedExpected=expectedHead===null?null:JSON.parse(canonical(expectedHead));
  const d=await lstat(directory);
  if(!d.isDirectory()||d.isSymbolicLink()||(d.mode&0o077)!==0||
     (typeof process.getuid==='function'&&d.uid!==process.getuid()))throw new Error('WITNESS_DIRECTORY_UNSAFE');
  const lockPath=path.join(directory,'writer.lock');let lock;
  try{
    lock=await open(lockPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
    const entries=await readdir(directory);
    if(entries.some(n=>n!=='writer.lock'&&!NAME.test(n)))throw new Error('WITNESS_UNEXPECTED_FILE');
    const files=entries.filter(n=>NAME.test(n)).sort();
    if(files.length===0&&!bootstrap)throw new Error('WITNESS_BOOTSTRAP_REQUIRED');
    if(files.length>0&&(bootstrap||expectedHead===null))throw new Error('WITNESS_EXPECTED_HEAD_REQUIRED');
    let latest=null;
    for(const name of files){
      const match=NAME.exec(name),fh=await open(path.join(directory,name),constants.O_RDONLY|constants.O_NOFOLLOW);
      let data;
      try{
        const s=await fh.stat();
        if(!s.isFile()||s.nlink!==1||(s.mode&0o077)!==0||s.size>MAX_CHECKPOINT||
           (typeof process.getuid==='function'&&s.uid!==process.getuid()))throw new Error('WITNESS_CHECKPOINT_UNSAFE');
        data=await fh.readFile('utf8');
      }finally{await fh.close();}
      const item=JSON.parse(data);
      if(!exact(item,['schema','head','lines'])||item.schema!=='sac.audit.checkpoint.v1'||canonical(item)!==data)
        throw new Error('WITNESS_CHECKPOINT_INVALID');
      const verified=verifyAuditSnapshot({lines:item.lines,head:item.head,trusted:pinnedTrust,prior:latest});
      if(String(verified.seq).padStart(12,'0')!==match[1]||verified.head_sha256!==match[2]||
         (latest!==null&&verified.seq<=latest.head.seq))throw new Error('WITNESS_CHECKPOINT_ORDER_INVALID');
      latest=item.head;
    }
    if(latest!==null&&!sameHead(latest,pinnedExpected))throw new Error('WITNESS_EXPECTED_HEAD_MISMATCH');
    let tail=Promise.resolve(),closing=false,closed=false,poisoned=false;
    async function checkpoint({lines,head}){
      if(closing||closed)throw new Error('WITNESS_CLOSING');
      const op=tail.then(async()=>{
        if(poisoned)throw new Error('WITNESS_UNSAFE');
        const pinnedHead=JSON.parse(canonical(head));
        const verified=verifyAuditSnapshot({lines,head:pinnedHead,trusted:pinnedTrust,prior:latest});
        if(verified.seq>999999999999)throw new Error('WITNESS_SEQUENCE_LIMIT');
        if(latest!==null&&sameHead(latest,pinnedHead))return JSON.parse(canonical(latest));
        const name='checkpoint-'+String(verified.seq).padStart(12,'0')+'-'+verified.head_sha256+'.json';
        const final=path.join(directory,name),temp=path.join(directory,'.pending-'+randomUUID());
        const content=canonical({schema:'sac.audit.checkpoint.v1',head:pinnedHead,lines});
        if(Buffer.byteLength(content)>MAX_CHECKPOINT)throw new Error('WITNESS_CHECKPOINT_TOO_LARGE');
        let fh;
        try{
          fh=await open(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
          await fh.writeFile(content);await fh.sync();await fh.close();fh=null;
          // link is an atomic no-overwrite publish on the witness filesystem.
          await link(temp,final);await unlink(temp);
          const dir=await open(directory,constants.O_RDONLY|constants.O_DIRECTORY);
          try{await dir.sync();}finally{await dir.close();}
        }catch(error){
          poisoned=true;
          if(fh)await fh.close().catch(()=>{});
          throw error;
        }
        latest=pinnedHead;return JSON.parse(canonical(latest));
      });
      tail=op.catch(()=>{});return op;
    }
    return {checkpoint,latestHead:()=>latest===null?null:JSON.parse(canonical(latest)),async close(){
      if(closing||closed)throw new Error('WITNESS_CLOSING');
      closing=true;await tail;closed=true;await lock.close();await unlink(lockPath);
    }};
  }catch(error){
    if(lock){await lock.close().catch(()=>{});await unlink(lockPath).catch(()=>{});}
    throw error;
  }
}
