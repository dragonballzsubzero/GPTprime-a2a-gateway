import {canonical,digest} from '../broker-v03/client.mjs';
import {validEvent} from './audit-ledger.mjs';
import {sha256,verifyAuditAck,verifyEd25519,verifyExactGrant} from './core.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[A-Za-z0-9_.:-]{1,100}$/;
const DOMAIN='sac.effect-observation.v2\n';
function exact(x,keys){return x&&typeof x==='object'&&!Array.isArray(x)&&
  Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));}

/**
 * Build an observation only from a separately configured read-only source,
 * trusted owner/auditor keys and a separately controlled signing function.
 * Injection makes transport testable; the host must establish its isolation.
 */
export async function observeExecution({intent,intent_ack,action,grant,grant_signature_b64url,
                                        execution_id,trustedAudit,trustedOwner,observer,source,signer,
                                        clock=()=>Math.floor(Date.now()/1000)}){
  if(!validEvent(intent)||intent.type!=='intent'||!verifyAuditAck(intent,intent_ack,trustedAudit))
    throw Error('INTENT_NOT_VERIFIED');
  const now=clock(),accepted=intent_ack.ack.accepted_at;
  if(!Number.isSafeInteger(now)||accepted>now||!UUID.test(execution_id||'')||
     !trustedOwner||trustedOwner.owner_id!==intent.owner_id||!trustedOwner.public_jwk||
     !observer||!ID.test(observer.id||'')||!ID.test(observer.source||'')||
     observer.audience!==intent.audience||observer.environment!==intent.environment||
     !observer.public_jwk||typeof source?.readExecution!=='function'||typeof signer!=='function')
    throw Error('OBSERVER_CONFIGURATION_INVALID');
  if(!trustedAudit.public_jwk?.x||!trustedOwner.public_jwk.x||!observer.public_jwk.x||
     new Set([trustedAudit.public_jwk.x,trustedOwner.public_jwk.x,observer.public_jwk.x]).size!==3)
    throw Error('OBSERVER_IDENTITIES_NOT_DISTINCT');
  if(!verifyExactGrant({grant,signature:grant_signature_b64url,public_jwk:trustedOwner.public_jwk,
    action,proposal_id:intent.proposal_id,owner_id:intent.owner_id,owner_kid:trustedOwner.kid,
    node_kid:grant?.node_kid,audience:observer.audience,environment:observer.environment,now:accepted})||
    digest(action)!==intent.action_digest||grant.node!==intent.node||grant.run!==intent.run||
    grant.nonce!==intent.nonce||sha256(canonical(grant)+'.'+grant_signature_b64url)!==intent.grant_sha256)
    throw Error('OWNER_GRANT_OR_INTENT_MISMATCH');
  const row=await source.readExecution(execution_id);
  if(!exact(row,['execution_id','owner_id','proposal_id','action_digest','grant_sha256','effect_sha256','operation','resource'])||
     row.execution_id!==execution_id||row.owner_id!==intent.owner_id||row.proposal_id!==intent.proposal_id||
     row.action_digest!==intent.action_digest||row.grant_sha256!==intent.grant_sha256||
     !HEX.test(row.effect_sha256||'')||
     row.effect_sha256!==sha256([intent.owner_id,intent.node,intent.action_digest,action.parameters.tag].join(':'))||
     row.operation!=='audit_canary'||row.resource!=='sac://broker/canary')
    throw Error('INDEPENDENT_SOURCE_MISMATCH');
  const observation={schema:'sac.effect-observation.v2',observer_id:observer.id,source:observer.source,
    owner_id:row.owner_id,proposal_id:row.proposal_id,grant_sha256:row.grant_sha256,execution_id:row.execution_id,
    action_digest:row.action_digest,effect_sha256:row.effect_sha256,audience:observer.audience,
    environment:observer.environment,observed_at:now,status:'present'};
  const signature=await signer(Buffer.from(DOMAIN+canonical(observation)));
  if(!Buffer.isBuffer(signature)||signature.length!==64||
     !verifyEd25519(observer.public_jwk,signature.toString('base64url'),DOMAIN+canonical(observation)))
    throw Error('OBSERVER_SIGNER_KEY_MISMATCH');
  return {observation,observation_signature:signature.toString('base64url')};
}
