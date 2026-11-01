import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createEnvelope,verifyEnvelope,signedReceipt,verifyReceipt,generateIdentity,FileReplayStore,sha256,parseStrictWire} from '../src/transport.mjs';
import {createGateway} from '../src/server.mjs';

const alice=generateIdentity(), bob=generateIdentity(), mallory=generateIdentity();
const clock=Date.parse('2026-11-01T18:00:00.000Z');
const trusted={'alice.node':alice.public_pem};
const payload=Buffer.from('a reproducible local integrity probe\n');
const signed=()=>createEnvelope({sender:'alice.node',recipient:'bob.node',payload,privatePem:alice.private_pem,now:clock});
const opts={now:clock,recipient:'bob.node'};
const fails=(e,reason)=>assert.throws(()=>verifyEnvelope(e,trusted,opts),new RegExp(reason));

test('valid Ed25519 request verifies and binds payload digest',()=>{
  const v=verifyEnvelope(signed(),trusted,opts);
  assert.equal(v.payload.toString(),payload.toString());
  assert.match(v.requestHash,/^[a-f0-9]{64}$/);
});
test('payload tamper fails signature',()=>{
  const e=signed();e.payload_b64url=Buffer.from('malicious payload').toString('base64url');fails(e,'INVALID_SIGNATURE');
});
test('recipient alteration fails',()=>{const e=signed();e.recipient='other.node';fails(e,'RECIPIENT_MISMATCH');});
test('forged signing identity fails',()=>{const e=signed();e.sender='other.node';fails(e,'UNTRUSTED_SENDER');});
test('wrong trusted key fails',()=>assert.throws(()=>verifyEnvelope(signed(),{'alice.node':mallory.public_pem},opts),/INVALID_SIGNATURE/));
test('expired request is rejected',()=>assert.throws(()=>verifyEnvelope(signed(),trusted,{...opts,now:clock+400000}),/EXPIRED_OR_FUTURE/));
test('future request is rejected',()=>assert.throws(()=>verifyEnvelope(signed(),trusted,{...opts,now:clock-40000}),/EXPIRED_OR_FUTURE/));
test('extra fields are rejected',()=>{const e=signed();e.crypto_verified=true;fails(e,'INVALID_FIELDS');});
test('malformed base64url is rejected',()=>{const e=signed();e.payload_b64url+='=';fails(e,'INVALID_BASE64URL');});
test('NaN and non-integer timestamps are rejected',()=>{const e=signed();e.issued_at_ms=NaN;fails(e,'INVALID_TIMESTAMP');});
test('TTL bounded to five minutes',()=>assert.throws(()=>createEnvelope({sender:'alice.node',recipient:'bob.node',payload,privatePem:alice.private_pem,now:clock,ttlMs:400000}),/INVALID_TTL/));
test('canonical wire blocks duplicate fields and whitespace',()=>{
  const e=signed();const json=JSON.stringify(e);
  assert.deepEqual(parseStrictWire(Buffer.from(json)),e);
  assert.throws(()=>parseStrictWire(Buffer.from(json.replace('"sender":','"sender":"alice.node","sender":'))),/NONCANONICAL_WIRE_JSON/);
  assert.throws(()=>parseStrictWire(Buffer.from(' '+json)),/NONCANONICAL_WIRE_JSON/);
});
test('signed receipt verifies and rejects altered result',()=>{
  const v=verifyEnvelope(signed(),trusted,opts);
  const r=signedReceipt({node_id:'bob.node',request_sha256:v.requestHash,result_sha256:sha256(payload),privatePem:bob.private_pem,now:clock});
  assert.equal(verifyReceipt(r,bob.public_pem,v.requestHash),true);
  assert.throws(()=>verifyReceipt({...r,result_sha256:'0'.repeat(64)},bob.public_pem,v.requestHash),/INVALID_RECEIPT_SIGNATURE/);
  assert.throws(()=>verifyReceipt(r,mallory.public_pem,v.requestHash),/INVALID_RECEIPT_SIGNATURE/);
});
test('nonce replay persists across store instances and restarts',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'sac-replay-'));
  try{
    const s1=new FileReplayStore(dir);const s2=new FileReplayStore(dir);const v=verifyEnvelope(signed(),trusted,opts);
    assert.equal(await s1.claim(v.sender,v.nonce,v.requestHash),true);
    await assert.rejects(s2.claim(v.sender,v.nonce,v.requestHash),/REPLAY_DETECTED/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('live local gateway returns signed receipt and rejects replay',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'sac-http-'));
  const app=createGateway({nodeId:'bob.node',privatePem:bob.private_pem,trustStore:trusted,stateDir:dir,clock:()=>clock});
  try{
    app.listen(0,'127.0.0.1');await once(app,'listening');
    const addr=app.address();const url=`http://127.0.0.1:${addr.port}`;
    const health=await (await fetch(url+'/healthz')).json();assert.equal(health.production_qualified,false);
    const envelope=signed();const body=JSON.stringify(envelope);
    const res=await fetch(url+'/sac/v0.34/dispatch',{method:'POST',headers:{'content-type':'application/json'},body});
    assert.equal(res.status,200);
    const json=await res.json(); const v=verifyEnvelope(envelope,trusted,opts);
    assert.equal(verifyReceipt(json.receipt,bob.public_pem,v.requestHash),true);
    assert.equal(json.receipt.result_sha256,sha256(payload));
    const saved=JSON.parse(await readFile(path.join(dir,'receipts',v.requestHash+'.json'),'utf8'));
    assert.deepEqual(saved,json.receipt);
    const replay=await fetch(url+'/sac/v0.34/dispatch',{method:'POST',headers:{'content-type':'application/json'},body});
    assert.equal(replay.status,409);assert.deepEqual(await replay.json(),{error:'REPLAY_DETECTED'});
    const malicious=JSON.stringify({...signed(),signature_b64url:'AA'});
    const rejected=await fetch(url+'/sac/v0.34/dispatch',{method:'POST',headers:{'content-type':'application/json'},body:malicious});
    assert.equal(rejected.status,400); assert.equal((await rejected.json()).error,'BAD_SIGNATURE_LENGTH');
  }finally{await new Promise(ok=>app.close(ok));await rm(dir,{recursive:true,force:true});}
});