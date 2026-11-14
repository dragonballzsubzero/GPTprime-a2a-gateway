import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import {canonical,digest,validateCanaryAction,verifyNodeProposal,verifyOwnerGrant,PROPOSAL_DOMAIN,GRANT_DOMAIN} from '../broker-v03/client.mjs';
const nodeKey=generateKeyPairSync('ed25519');
const ownerKey=generateKeyPairSync('ed25519');
const nodePub=nodeKey.publicKey.export({format:'jwk'});
const ownerPub=ownerKey.publicKey.export({format:'jwk'});
const action={node:'gptprime.future.preview',run:'test-run',operation:'audit_canary',resource:'sac://broker/canary',parameters:{tag:'TEST_ONLY'}};
const nodeSign=(a)=>sign(null,Buffer.from(PROPOSAL_DOMAIN+canonical(a)),nodeKey.privateKey).toString('base64url');
const ownerSign=(g)=>sign(null,Buffer.from(GRANT_DOMAIN+canonical(g)),ownerKey.privateKey).toString('base64url');
test('canonical signing is stable across insertion orders',()=>assert.equal(canonical({b:2,a:1}),canonical({a:1,b:2})));
test('canonical signing rejects unsafe values',()=>{assert.throws(()=>canonical({x:NaN}));assert.throws(()=>canonical({x:1.25}));});
test('canary is only allowed effect',()=>{assert.equal(validateCanaryAction(action),true);assert.equal(validateCanaryAction({...action,operation:'shell_exec'}),false);});
test('out-of-scope resource denied',()=>assert.equal(validateCanaryAction({...action,resource:'https://example.org'}),false));
test('valid signed node proposal verified',()=>assert.equal(verifyNodeProposal({action,signature_b64url:nodeSign(action),public_jwk:nodePub}),true));
test('tampered node proposal rejected',()=>assert.equal(verifyNodeProposal({action:{...action,parameters:{tag:'TAMPERED'}},signature_b64url:nodeSign(action),public_jwk:nodePub}),false));
test('owner exact grant accepts matching effect',()=>{
 const t=1800000000;
 const grant={schema:'sac.exact-action.v3',owner:'00000000-0000-4000-8000-000000000001',node:action.node,run:action.run,action_digest:digest(action),proposal_id:'00000000-0000-4000-8000-000000000002',nonce:'1'.repeat(32),iat:t,exp:t+60};
 assert.equal(verifyOwnerGrant({grant,signature_b64url:ownerSign(grant),public_jwk:ownerPub,action,proposal_id:grant.proposal_id,owner_id:grant.owner,now:t+1}),true);
 assert.equal(verifyOwnerGrant({grant,signature_b64url:ownerSign(grant),public_jwk:ownerPub,action:{...action,parameters:{tag:'ALTERED'}},proposal_id:grant.proposal_id,owner_id:grant.owner,now:t+1}),false);
 assert.equal(verifyOwnerGrant({grant,signature_b64url:ownerSign(grant),public_jwk:ownerPub,action,proposal_id:grant.proposal_id,owner_id:grant.owner,now:t+70}),false);
});
test('foreign owner public key does not verify grant',()=>{
 const t=1800000000;
 const grant={schema:'sac.exact-action.v3',owner:'00000000-0000-4000-8000-000000000001',node:action.node,run:action.run,action_digest:digest(action),proposal_id:'00000000-0000-4000-8000-000000000002',nonce:'2'.repeat(32),iat:t,exp:t+60};
 assert.equal(verifyOwnerGrant({grant,signature_b64url:ownerSign(grant),public_jwk:nodePub,action,proposal_id:grant.proposal_id,owner_id:grant.owner,now:t+1}),false);
});
