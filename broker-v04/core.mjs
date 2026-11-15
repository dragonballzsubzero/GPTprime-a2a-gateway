import {createHash, createPublicKey, verify} from 'node:crypto';
import {canonical, digest} from '../broker-v03/client.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const KID = /^[A-Za-z0-9_.:-]{1,128}$/;
const AUDIT_DOMAIN = 'sac.audit.ack.v1\n';
const SINK_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const NODE = /^[a-z][a-z0-9._-]{2,63}$/;
const ID = /^[A-Za-z0-9_.:-]{1,100}$/;
const NONCE = /^[0-9a-f]{32}$/;
export const NODE_DOMAIN='sac.node-proposal.v3\n';
export const GRANT_DOMAIN='sac.exact-action.v4\n';

export class BrokerError extends Error {
  constructor(code, status=403) { super(code); this.code=code; this.status=status; }
}
function must(ok, code, status=403) { if (!ok) throw new BrokerError(code,status); }
function exact(obj, keys) {
  return obj && typeof obj === 'object' && !Array.isArray(obj)
    && Object.getPrototypeOf(obj) === Object.prototype
    && Object.keys(obj).length === keys.length && keys.every(k => Object.hasOwn(obj,k));
}
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const eventDigest = event => sha256(canonical(event));

export function verifyEd25519(public_jwk, signature_b64url, message) {
  try {
    if(!exact(public_jwk,['kty','crv','x'])||public_jwk.kty!=='OKP'||public_jwk.crv!=='Ed25519'||
       typeof public_jwk.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(public_jwk.x))return false;
    const pub=Buffer.from(public_jwk.x,'base64url');
    if(pub.length!==32||pub.toString('base64url')!==public_jwk.x||
       typeof signature_b64url!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature_b64url))return false;
    const sig=Buffer.from(signature_b64url,'base64url');
    return sig.length===64 && sig.toString('base64url')===signature_b64url &&
      verify(null,Buffer.from(message),createPublicKey({format:'jwk',key:public_jwk}),sig);
  }catch{return false;}
}

export function validateCanaryAction(action){
  return exact(action,['node','run','operation','resource','parameters']) && typeof action.node==='string'
    && NODE.test(action.node) && typeof action.run==='string' && ID.test(action.run)
    && action.operation==='audit_canary' && action.resource==='sac://broker/canary'
    && exact(action.parameters,['tag']) && typeof action.parameters.tag==='string'
    && /^[A-Za-z0-9_.:-]{1,64}$/.test(action.parameters.tag);
}

export function verifyExactGrant({grant,signature,public_jwk,action,proposal_id,owner_id,
                                 owner_kid,node_kid,audience,environment,now}) {
  const fields=['schema','owner','node','run','action_digest','proposal_id','nonce','iat','exp',
                'audience','environment','owner_kid','node_kid'];
  if(!exact(grant,fields)||!validateCanaryAction(action)||!Number.isSafeInteger(now)
    || grant.schema!=='sac.exact-action.v4'||grant.owner!==owner_id||grant.node!==action.node
    || grant.run!==action.run||grant.action_digest!==digest(action)||grant.proposal_id!==proposal_id
    || grant.audience!==audience||grant.environment!==environment||grant.owner_kid!==owner_kid
    || grant.node_kid!==node_kid||typeof grant.nonce!=='string'||!NONCE.test(grant.nonce)
    || !Number.isSafeInteger(grant.iat)||!Number.isSafeInteger(grant.exp)
    || grant.exp<=now||grant.iat>now||grant.exp<=grant.iat||grant.exp-grant.iat>180)return false;
  return verifyEd25519(public_jwk,signature,GRANT_DOMAIN+canonical(grant));
}

export function verifyAuditAck(event, envelope, trusted) {
  try {
    if (!exact(envelope,['ack','signature_b64url']) || !exact(envelope.ack,
      ['schema','sink_id','event_sha256','event_type','accepted_at'])) return false;
    const a=envelope.ack;
    if (!trusted || !SINK_ID.test(trusted.id) || a.schema!=='sac.audit.ack.v1'
       || a.sink_id!==trusted.id || a.event_sha256!==eventDigest(event)
       || a.event_type!==event.type || !Number.isSafeInteger(a.accepted_at)) return false;
    const jwk=trusted.public_jwk;
    if (!exact(jwk,['kty','crv','x']) || jwk.kty!=='OKP' || jwk.crv!=='Ed25519'
        || typeof jwk.x!=='string' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)) return false;
    const keyBytes=Buffer.from(jwk.x,'base64url');
    if(keyBytes.length!==32 || keyBytes.toString('base64url')!==jwk.x) return false;
    if(typeof envelope.signature_b64url!=='string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature_b64url)) return false;
    const signature=Buffer.from(envelope.signature_b64url,'base64url');
    if(signature.length!==64 || signature.toString('base64url')!==envelope.signature_b64url) return false;
    return verify(null,Buffer.from(AUDIT_DOMAIN+canonical(a)),createPublicKey({format:'jwk',key:jwk}),signature);
  } catch { return false; }
}

const PROPOSE_KEYS=['action','node_kid','node_signature_b64url'];
const EXECUTE_KEYS=[...PROPOSE_KEYS,'proposal_id','grant','owner_kid','grant_signature_b64url'];

/** Trusted adapters are supplied by the host; no model gets signing/service secrets. */
export function createBroker({auth,keys,store,audit,trustedAudit,audience,environment,clock=()=>Math.floor(Date.now()/1000)}) {
  if(!auth?.authenticate || !keys?.resolve || !store?.propose || !store?.executeCanary || !audit?.append)
    throw new Error('BROKER_ADAPTERS_REQUIRED');
  if(!trustedAudit || !SINK_ID.test(trustedAudit.id || '') || !trustedAudit.public_jwk)
    throw new Error('TRUSTED_AUDITOR_REQUIRED');
  if(typeof audience!=='string'||!/^sac:\/\/broker\/[a-z0-9._/-]{1,100}$/.test(audience)
     || !['development','staging','production'].includes(environment))throw new Error('BROKER_AUDIENCE_REQUIRED');

  async function verifyContext(token, body, execute) {
    must(typeof token==='string' && token.length>=20 && token.length<=4096,'AUTH_REQUIRED',401);
    const user=await auth.authenticate(token);
    must(user && UUID.test(user.owner_id || '') && user.aal==='aal2','AUTH_SESSION_DENIED',401);
    must(exact(body, execute?EXECUTE_KEYS:PROPOSE_KEYS),'INVALID_REQUEST_SHAPE',422);
    must(validateCanaryAction(body.action),'EFFECT_NOT_ALLOWLISTED',422);
    const keyset=await keys.resolve(user.owner_id,body.action.node);
    must(keyset && keyset.allowed===true,'NODE_OR_OWNER_NOT_ENROLLED');
    must(typeof keyset.owner_key?.x==='string' && typeof keyset.node_key?.x==='string'
      && typeof trustedAudit.public_jwk?.x==='string'
      && keyset.owner_key.x!==keyset.node_key.x && keyset.owner_key.x!==trustedAudit.public_jwk.x
      && keyset.node_key.x!==trustedAudit.public_jwk.x,'SIGNING_IDENTITIES_MUST_BE_DISTINCT');
    must(KID.test(keyset.node_kid || '') && body.node_kid===keyset.node_kid,'NODE_KEY_MISMATCH');
    must(verifyEd25519(keyset.node_key,body.node_signature_b64url,NODE_DOMAIN+canonical(body.action)),
         'INVALID_NODE_SIGNATURE');
    if(execute){
      must(UUID.test(body.proposal_id || ''),'INVALID_PROPOSAL_ID',422);
      must(KID.test(keyset.owner_kid || '') && body.owner_kid===keyset.owner_kid,'OWNER_KEY_MISMATCH');
      must(verifyExactGrant({grant:body.grant,signature:body.grant_signature_b64url,
        public_jwk:keyset.owner_key,action:body.action,proposal_id:body.proposal_id,
        owner_id:user.owner_id,owner_kid:body.owner_kid,node_kid:body.node_kid,
        audience,environment,now:clock()}),'INVALID_EXACT_ACTION_GRANT');
    }
    return {user,keyset,action:body.action,digest:digest(body.action)};
  }

  return {
    async propose(token,body){
      const c=await verifyContext(token,body,false);
      const result=await store.propose({owner_id:c.user.owner_id,action:c.action,action_digest:c.digest});
      must(result?.accepted===true && UUID.test(result.proposal_id || '') && result.action_digest===c.digest,
           'PROPOSAL_STORE_DENIED',503);
      return {status:'PROPOSED',proposal_id:result.proposal_id,action_digest:c.digest};
    },
    async execute(token,body){
      const c=await verifyContext(token,body,true);
      const signedGrantHash=sha256(canonical(body.grant)+'.'+body.grant_signature_b64url);
      const intent={schema:'sac.audit.event.v1',type:'intent',owner_id:c.user.owner_id,
        node:c.action.node,run:c.action.run,proposal_id:body.proposal_id,action_digest:c.digest,
        grant_sha256:signedGrantHash,nonce:body.grant.nonce,audience,environment};
      let ack;
      try {ack=await audit.append(intent);} catch {throw new BrokerError('AUDIT_INTENT_UNAVAILABLE',503);}
      must(verifyAuditAck(intent,ack,trustedAudit),'AUDIT_INTENT_UNVERIFIED',503);
      must(clock()<body.grant.exp,'GRANT_EXPIRED_BEFORE_EXECUTION');
      // Recheck the same owner's session after the potentially slow audit hop.
      // The transaction still needs its own atomic revocation design.
      const refreshed=await auth.authenticate(token);
      must(refreshed && refreshed.owner_id===c.user.owner_id && refreshed.aal==='aal2','AUTH_SESSION_DENIED',401);
      must(clock()<body.grant.exp,'GRANT_EXPIRED_BEFORE_EXECUTION');
      let execution;
      try {
        execution=await store.executeCanary({owner_id:c.user.owner_id,action:c.action,
          action_digest:c.digest,proposal_id:body.proposal_id,nonce:body.grant.nonce,
          grant_iat:body.grant.iat,grant_exp:body.grant.exp,owner_kid:body.owner_kid,node_kid:body.node_kid,
          grant_sha256:signedGrantHash,audit_intent_sha256:eventDigest(intent),
          audit_ack_sha256:sha256(canonical(ack))});
      } catch {throw new BrokerError('EXECUTION_OUTCOME_UNKNOWN_DO_NOT_RETRY',503);}
      must(execution && typeof execution.executed==='boolean','EXECUTION_OUTCOME_UNKNOWN_DO_NOT_RETRY',503);
      if(!execution.executed) throw new BrokerError(execution.reason==='GRANT_REPLAY'?'GRANT_REPLAY':'EXECUTION_DENIED',403);
      // A malformed response may hide an already-committed effect. Never call it a denial.
      must(UUID.test(execution.execution_id || '') && HEX64.test(execution.effect_sha256 || ''),
           'EXECUTION_OUTCOME_UNKNOWN_DO_NOT_RETRY',503);
      const result={schema:'sac.audit.event.v1',type:'result',owner_id:c.user.owner_id,
        node:c.action.node,run:c.action.run,proposal_id:body.proposal_id,action_digest:c.digest,
        grant_sha256:signedGrantHash,nonce:body.grant.nonce,audience,environment,execution_id:execution.execution_id,
        effect_sha256:execution.effect_sha256};
      let resultAck;
      try {resultAck=await audit.append(result);} catch {}
      const recorded=verifyAuditAck(result,resultAck,trustedAudit);
      return {status:recorded?'EXECUTED_AUDIT_RECORDED':'EXECUTED_AUDIT_PENDING',
        execution_id:execution.execution_id,action_digest:c.digest,effect_sha256:execution.effect_sha256,
        audit_status:recorded?'INDEPENDENT_LOG_RECORDED_NOT_RECONCILED':'PENDING_INDEPENDENT_RECONCILIATION',
        automatic_retry:false};
    }
  };
}
