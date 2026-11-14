import { createHash, createPublicKey, verify } from 'node:crypto';
const NODES = new Set(['gptprime.future.preview','geminiprime.preview.v1','llamaprime.preview.v1']);
export const PROPOSAL_DOMAIN = 'sac.node-proposal.v3\n';
export const GRANT_DOMAIN = 'sac.exact-action.v3\n';
const SAFE_TAG = /^[A-Za-z0-9_.:-]{1,64}$/;
export function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.length > 100) throw new Error('ARRAY_LIMIT');
    return '['+value.map(canonical).join(',')+']';
  }
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort();
    if (keys.length > 32 || keys.some(k => ['__proto__','constructor','prototype'].includes(k))) throw new Error('UNSAFE_KEYS');
    return '{'+keys.map(k => JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  }
  throw new Error('UNSUPPORTED_VALUE');
}
export const digest = obj => createHash('sha256').update(canonical(obj)).digest('hex');
export function validateCanaryAction(action) {
  if (!action || typeof action!=='object'||Array.isArray(action))return false;
  const k=Object.keys(action).sort().join(',');
  if(k!=='node,operation,parameters,resource,run'||!NODES.has(action.node)||
     typeof action.run!=='string'||!/^[A-Za-z0-9_.:-]{1,100}$/.test(action.run)||
     action.operation!=='audit_canary'||action.resource!=='sac://broker/canary'||
     !action.parameters||typeof action.parameters!=='object'||Array.isArray(action.parameters)||
     Object.keys(action.parameters).join(',')!=='tag'||typeof action.parameters.tag!=='string'||
     !SAFE_TAG.test(action.parameters.tag))return false;
  try { canonical(action); return true; } catch { return false; }
}
export function verifyNodeProposal({ action, signature_b64url, public_jwk }) {
  if (!validateCanaryAction(action) || typeof signature_b64url!=='string' ||
    !/^[A-Za-z0-9_-]{86}$/.test(signature_b64url))return false;
  if (!public_jwk || public_jwk.kty!=='OKP' || public_jwk.crv!=='Ed25519' ||
    Object.keys(public_jwk).sort().join(',')!=='crv,kty,x') return false;
  try{
    const sig=Buffer.from(signature_b64url,'base64url');
    if(sig.length!==64||sig.toString('base64url')!==signature_b64url)return false;
    return verify(null, Buffer.from(PROPOSAL_DOMAIN+canonical(action)),
       createPublicKey({format:'jwk',key:public_jwk}),sig);
  }catch{return false;}
}
export function verifyOwnerGrant({grant,signature_b64url,public_jwk,action,proposal_id,owner_id,now}) {
  if(!validateCanaryAction(action)||!grant||typeof grant!=='object'||Array.isArray(grant))return false;
  if(Object.keys(grant).sort().join(',')!=='action_digest,exp,iat,node,nonce,owner,proposal_id,run,schema')return false;
  const t = now ?? Math.floor(Date.now()/1000);
  if(grant.schema!=='sac.exact-action.v3'||grant.owner!==owner_id||
    grant.node!==action.node||grant.run!==action.run||
    grant.action_digest!==digest(action)||grant.proposal_id!==proposal_id||
    typeof grant.nonce!=='string'||!/^[0-9a-f]{32}$/.test(grant.nonce)||
    !Number.isSafeInteger(grant.iat)||!Number.isSafeInteger(grant.exp)||
    grant.exp<=t||grant.iat>t||grant.exp<=grant.iat||grant.exp-grant.iat>180)return false;
  try{
    if(!public_jwk||public_jwk.kty!=='OKP'||public_jwk.crv!=='Ed25519'||Object.keys(public_jwk).sort().join(',')!=='crv,kty,x')return false;
    if(!/^[A-Za-z0-9_-]{86}$/.test(signature_b64url))return false;
    const sig=Buffer.from(signature_b64url,'base64url');
    if(sig.length!==64||sig.toString('base64url')!==signature_b64url)return false;
    return verify(null,Buffer.from(GRANT_DOMAIN+canonical(grant)),
      createPublicKey({format:'jwk',key:public_jwk}),sig);
  }catch{return false;}
}
