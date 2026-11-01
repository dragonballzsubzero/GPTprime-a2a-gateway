import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey, sign} from 'node:crypto';
import {generateFrameKeys, sealFrame, openFrame} from '../src/confidential-frame.mjs';
const policy='b'.repeat(64);
function validlyResign(e,pem){
  const keys=Object.keys(e).filter(k=>k!=='signature');
  e.signature=sign(null,Buffer.from(JSON.stringify(keys.map(k=>e[k])),'utf8'),createPrivateKey(pem)).toString('base64url');
  return e;
}
test('AEAD-invalid but validly signed frame cannot burn nonce',async()=>{
  const sender=generateFrameKeys(),receiver=generateFrameKeys();
  const original=sealFrame({sender:'alpha.node',recipient:'beta.node',capability:'probe.sha256',policy_sha256:policy,plaintext:'durable task',sender_sign_private_pem:sender.sign_private_pem,recipient_enc_public_pem:receiver.enc_public_pem});
  const claims=new Set();let attempted=0;
  const store={async claim(actor,nonce){attempted++;const k=actor+':'+nonce;if(claims.has(k))throw Error('REPLAY');claims.add(k)}};
  const options={expected_recipient:'beta.node',expected_capability:'probe.sha256',expected_policy_sha256:policy,sender_sign_public_pem:sender.sign_public_pem,recipient_enc_private_pem:receiver.enc_private_pem,replay_store:store};
  const altered=structuredClone(original);const tag=Buffer.from(altered.tag,'base64url');tag[0]^=1;altered.tag=tag.toString('base64url');validlyResign(altered,sender.sign_private_pem);
  await assert.rejects(openFrame(altered,options));
  assert.equal(attempted,0,'invalid ciphertext must never spend replay slot');
  const result=await openFrame(original,options);assert.equal(result.plaintext.toString(),'durable task');assert.equal(attempted,1);
  await assert.rejects(openFrame(original,options),/REPLAY/);
});