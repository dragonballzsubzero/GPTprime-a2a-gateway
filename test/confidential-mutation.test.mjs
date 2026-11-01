import test from 'node:test';import assert from 'node:assert/strict';
import {generateFrameKeys,sealFrame,openFrame} from '../src/confidential-frame.mjs';
const a=generateFrameKeys(),b=generateFrameKeys(),digest='f'.repeat(64);
function options(){return {expected_recipient:'node.bbb',expected_capability:'task.review',expected_policy_sha256:digest,sender_sign_public_pem:a.sign_public_pem,recipient_enc_private_pem:b.enc_private_pem,replay_store:{async claim(){}},now:60000};}
const frame=sealFrame({sender:'node.aaa',recipient:'node.bbb',capability:'task.review',policy_sha256:digest,plaintext:'sensitive fixture',sender_sign_private_pem:a.sign_private_pem,recipient_enc_public_pem:b.enc_public_pem,now:60000});
const mutable=['sender','recipient','capability','job_id','nonce','policy_sha256','expires_at_ms','salt','iv','ciphertext','tag','signature'];
test('720 deterministic signed-field mutation attempts fail before releasing plaintext',async()=>{
 let rejected=0;
 for(let i=0;i<720;i++){
  const name=mutable[i%mutable.length],v=structuredClone(frame),value=v[name];
  if(typeof value==='number') v[name]=value+1;
  else if(typeof value==='string'){
   const at=Math.floor(i/mutable.length)%value.length;
   const c=value[at];v[name]=value.slice(0,at)+(c==='A'?'B':'A')+value.slice(at+1);
  }
  try{await openFrame(v,options());}catch{rejected++;}
 }
 assert.equal(rejected,720);
});