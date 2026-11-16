import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtemp,readFile,readdir,rm,unlink,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {openAuditLedger,verifyAuditSnapshot} from '../broker-v04/audit-ledger.mjs';
import {openAuditWitness} from '../broker-v04/audit-witness.mjs';
import {createAuditHttpServer} from '../broker-v04/audit-http.mjs';
import {createAuditSnapshotClient} from '../broker-v04/audit-witness-client.mjs';

const event={schema:'sac.audit.event.v1',type:'intent',owner_id:'11111111-1111-4111-8111-111111111111',
  node:'test.node',run:'test-run',proposal_id:'22222222-2222-4222-8222-222222222222',
  action_digest:'a'.repeat(64),grant_sha256:'b'.repeat(64),nonce:'1'.repeat(32),
  audience:'sac://broker/canary',environment:'staging'};

async function fixture(){
  const root=await mkdtemp(path.join(tmpdir(),'audit-witness-'));
  const {mkdir}=await import('node:fs/promises');
  for(const n of ['audit','witness','fork'])await mkdir(path.join(root,n),{mode:0o700});
  const key=generateKeyPairSync('ed25519');
  const privatePem=key.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  const trusted={id:'audit-1',public_jwk:key.publicKey.export({format:'jwk'})};
  const opts={sinkId:trusted.id,privatePem,clock:()=>1800000000};
  const ledger=await openAuditLedger({...opts,directory:path.join(root,'audit')});
  const snapshot=async()=>({head:await ledger.signedHead(),lines:await readFile(path.join(root,'audit','audit.jsonl'),'utf8')});
  return {root,trusted,opts,ledger,snapshot,dir:path.join(root,'witness')};
}

test('witness retains verified checkpoints and requires the independently retained latest head',async()=>{
  const f=await fixture();let witness;
  try{
    await assert.rejects(openAuditWitness({directory:f.dir,trusted:f.trusted}),/BOOTSTRAP_REQUIRED/);
    witness=await openAuditWitness({directory:f.dir,trusted:f.trusted,bootstrap:true});
    await assert.rejects(openAuditWitness({directory:f.dir,trusted:f.trusted,bootstrap:true}),/EEXIST/);
    await f.ledger.append(event);
    const first=await witness.checkpoint(await f.snapshot());assert.equal(first.head.seq,1);
    const mutable=witness.latestHead();mutable.head.seq=50;assert.equal(witness.latestHead().head.seq,1);
    await f.ledger.append({...event,nonce:'2'.repeat(32)});
    const second=await witness.checkpoint(await f.snapshot());assert.equal(second.head.seq,2);
    await witness.checkpoint(await f.snapshot());
    assert.equal((await readdir(f.dir)).filter(x=>x.startsWith('checkpoint-')).length,2);
    await witness.close();witness=null;
    await assert.rejects(openAuditWitness({directory:f.dir,trusted:f.trusted}),/EXPECTED_HEAD_REQUIRED/);
    await assert.rejects(openAuditWitness({directory:f.dir,trusted:f.trusted,expectedHead:first}),/EXPECTED_HEAD_MISMATCH/);
    witness=await openAuditWitness({directory:f.dir,trusted:f.trusted,expectedHead:second});
    assert.equal(witness.latestHead().head.seq,2);
  }finally{if(witness)await witness.close();await f.ledger.close();await rm(f.root,{recursive:true,force:true});}
});

test('witness rejects tampering, rollback, and an independently signed fork',async()=>{
  const f=await fixture();let witness,fork;
  try{
    witness=await openAuditWitness({directory:f.dir,trusted:f.trusted,bootstrap:true});
    await f.ledger.append(event);const first=await f.snapshot();await witness.checkpoint(first);
    const corrupted=first.lines.replace('test-run','changed-run');
    await assert.rejects(witness.checkpoint({...first,lines:corrupted}));
    await assert.rejects(witness.checkpoint({...first,lines:first.lines+'\n'}),/NONCANONICAL/);
    await f.ledger.append({...event,nonce:'2'.repeat(32)});const second=await f.snapshot();
    await witness.checkpoint(second);
    await assert.rejects(witness.checkpoint(first),/ROLLBACK/);
    fork=await openAuditLedger({...f.opts,directory:path.join(f.root,'fork')});
    await fork.append({...event,nonce:'3'.repeat(32)});
    await fork.append({...event,nonce:'4'.repeat(32)});
    const forked={head:await fork.signedHead(),lines:await readFile(path.join(f.root,'fork','audit.jsonl'),'utf8')};
    assert.doesNotThrow(()=>verifyAuditSnapshot({...forked,trusted:f.trusted}));
    await assert.rejects(witness.checkpoint(forked),/FORK/);
    assert.equal(witness.latestHead().head.seq,2);
  }finally{if(witness)await witness.close();if(fork)await fork.close();await f.ledger.close();await rm(f.root,{recursive:true,force:true});}
});

test('witness fails closed if a retained checkpoint is deleted or modified',async()=>{
  const f=await fixture();let witness;
  try{
    witness=await openAuditWitness({directory:f.dir,trusted:f.trusted,bootstrap:true});
    await f.ledger.append(event);await witness.checkpoint(await f.snapshot());
    await f.ledger.append({...event,nonce:'2'.repeat(32)});const latest=await witness.checkpoint(await f.snapshot());
    await witness.close();witness=null;
    const names=(await readdir(f.dir)).filter(n=>n.startsWith('checkpoint-')).sort();
    const last=path.join(f.dir,names[1]);const saved=await readFile(last,'utf8');
    await writeFile(last,saved.replace('test-run','other-run'));
    await assert.rejects(openAuditWitness({directory:f.dir,trusted:f.trusted,expectedHead:latest}));
    await unlink(last);
    await assert.rejects(openAuditWitness({directory:f.dir,trusted:f.trusted,expectedHead:latest}),/EXPECTED_HEAD_MISMATCH/);
  }finally{if(witness)await witness.close();await f.ledger.close();await rm(f.root,{recursive:true,force:true});}
});

test('snapshot reader and append credentials have separate HTTP capabilities',async()=>{
  const f=await fixture(),writer='w'.repeat(48),reader='r'.repeat(48);
  assert.throws(()=>createAuditHttpServer({ledger:f.ledger,bearerToken:writer,readerToken:writer}),/READER_CONFIGURATION_INVALID/);
  const server=createAuditHttpServer({ledger:f.ledger,bearerToken:writer,readerToken:reader});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    await f.ledger.append(event);
    const base=`http://127.0.0.1:${server.address().port}`;
    const get=token=>fetch(base+'/snapshot',{headers:{authorization:'Bearer '+token}});
    assert.equal((await get(writer)).status,401);
    assert.equal((await get('wrong')).status,401);
    const response=await get(reader);assert.equal(response.status,200);
    const snapshot=await response.json();assert.equal(verifyAuditSnapshot({...snapshot,trusted:f.trusted}).seq,1);
    const denied=await fetch(base+'/append',{method:'POST',headers:{authorization:'Bearer '+reader,
      'content-type':'application/json'},body:JSON.stringify(event)});
    assert.equal(denied.status,401);
    assert.equal((await fetch(base+'/head',{headers:{authorization:'Bearer '+reader}})).status,401);
    const client=createAuditSnapshotClient({origin:'https://audit.example',secretProvider:async()=>reader,
      fetchImpl:async(url,options)=>{
        assert.equal(url,'https://audit.example/snapshot');
        assert.equal(options.headers.authorization,'Bearer '+reader);
        return new Response(JSON.stringify(snapshot),{status:200});
      }});
    assert.equal((await client.snapshot()).head.head.seq,1);
    assert.throws(()=>createAuditSnapshotClient({origin:base,secretProvider:async()=>reader}),/HTTPS_BASE_ORIGIN_REQUIRED/);
  }finally{await new Promise(resolve=>server.close(resolve));await f.ledger.close();await rm(f.root,{recursive:true,force:true});}
});

test('concurrent ledger appends and snapshot reads produce verifiable matching heads',async()=>{
  const f=await fixture();
  try{
    const operations=[];
    for(let i=1;i<=20;i++){
      operations.push(f.ledger.append({...event,nonce:i.toString(16).padStart(32,'0')}));
      operations.push(f.ledger.snapshot().then(s=>verifyAuditSnapshot({...s,trusted:f.trusted})));
    }
    const results=await Promise.all(operations);
    assert.deepEqual(results.filter((_,i)=>i%2===1).map(x=>x.seq),Array.from({length:20},(_,i)=>i+1));
  }finally{await f.ledger.close();await rm(f.root,{recursive:true,force:true});}
});
