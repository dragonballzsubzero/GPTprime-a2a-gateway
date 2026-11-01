import test from 'node:test';
import assert from 'node:assert/strict';
import {generateIdentity,createEnvelope,verifyEnvelope,signedReceipt,sha256} from '../src/transport.mjs';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
const py=process.env.PYTHON||'python';
const checker=new URL('../scripts/verify_cross_runtime.py',import.meta.url).pathname;

test('Python validates Node Ed25519 request and receipt',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'sac-cross-'));
 try{
  const a=generateIdentity(),b=generateIdentity();const payload=Buffer.from('cross runtime validation');
  const e=createEnvelope({sender:'alice.node',recipient:'bob.node',payload,privatePem:a.private_pem});
  const v=verifyEnvelope(e,{'alice.node':a.public_pem});
  const r=signedReceipt({node_id:'bob.node',request_sha256:v.requestHash,result_sha256:sha256(payload),privatePem:b.private_pem});
  const trust=path.join(dir,'trust.json'),envelope=path.join(dir,'envelope.json'),pub=path.join(dir,'bob.pem'),receipt=path.join(dir,'receipt.json');
  await Promise.all([writeFile(trust,JSON.stringify({'alice.node':a.public_pem})),writeFile(envelope,JSON.stringify(e)),writeFile(pub,b.public_pem),writeFile(receipt,JSON.stringify(r))]);
  let p=spawnSync(py,[checker,'request',trust,envelope],{encoding:'utf8'});assert.equal(p.status,0,p.stderr);assert.equal(JSON.parse(p.stdout).request_sha256,v.requestHash);
  p=spawnSync(py,[checker,'receipt',pub,receipt],{encoding:'utf8'});assert.equal(p.status,0,p.stderr);assert.equal(JSON.parse(p.stdout).result_sha256,sha256(payload));
  await writeFile(envelope,JSON.stringify({...e,payload_b64url:Buffer.from('tamper').toString('base64url')}));
  p=spawnSync(py,[checker,'request',trust,envelope],{encoding:'utf8'});assert.equal(p.status,1);assert.match(p.stderr,/INVALID_SIGNATURE/);
 }finally{await rm(dir,{recursive:true,force:true});}
});