import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import path from 'node:path';
import {generateFrameKeys,sealFrame,openFrame} from '../src/confidential-frame.mjs';
import {FileReplayStore} from '../src/transport.mjs';
const policy='c'.repeat(64);
test('100 independently generated software keys can sign recipient-specific frames (local fixture, not cloud AI)',async()=>{
 const coordinator=generateFrameKeys();let successes=0;const hashes=new Set();
 for(let i=0;i<100;i++){
  const receiver=generateFrameKeys();
  const frame=sealFrame({sender:'node.coordinator',recipient:`node.${i.toString().padStart(3,'0')}`,capability:'review.source',policy_sha256:policy,plaintext:Buffer.from('fixture:'+i),sender_sign_private_pem:coordinator.sign_private_pem,recipient_enc_public_pem:receiver.enc_public_pem});
  hashes.add(frame.ephemeral_spki);
  const ledger={seen:new Set(),async claim(s,n){if(this.seen.has(n))throw new Error('REPLAY');this.seen.add(n)}};
  const plain=await openFrame(frame,{expected_recipient:frame.recipient,expected_capability:frame.capability,expected_policy_sha256:policy,sender_sign_public_pem:coordinator.sign_public_pem,recipient_enc_private_pem:receiver.enc_private_pem,replay_store:ledger});
  assert.equal(plain.plaintext.toString(),'fixture:'+i);successes++;
 }
 assert.equal(successes,100);assert.equal(hashes.size,100);
});
test('durable replay reservation survives new ledger instances',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'sac-cf-nonce-'));
 try{const sender=generateFrameKeys(),receiver=generateFrameKeys();const frame=sealFrame({sender:'agent.signed',recipient:'agent.target',capability:'review.source',policy_sha256:policy,plaintext:Buffer.from('real crypto local test'),sender_sign_private_pem:sender.sign_private_pem,recipient_enc_public_pem:receiver.enc_public_pem});const opts={expected_recipient:'agent.target',expected_capability:'review.source',expected_policy_sha256:policy,sender_sign_public_pem:sender.sign_public_pem,recipient_enc_private_pem:receiver.enc_private_pem};await openFrame(frame,{...opts,replay_store:new FileReplayStore(dir)});await assert.rejects(openFrame(frame,{...opts,replay_store:new FileReplayStore(dir)}),/REPLAY_DETECTED/);}finally{await rm(dir,{recursive:true,force:true})}
});