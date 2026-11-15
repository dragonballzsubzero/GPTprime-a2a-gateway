import {readFile} from 'node:fs/promises';
import {canonical} from '../broker-v03/client.mjs';
import {validEvent} from './audit-ledger.mjs';
import {eventDigest,sha256,verifyAuditAck,verifyEd25519} from './core.mjs';
import {readPrivateFile} from './secrets.mjs';

const OBS_DOMAIN='sac.effect-observation.v2\n';
const FIELDS=['schema','observer_id','source','owner_id','proposal_id','grant_sha256','execution_id','action_digest','effect_sha256',
              'audience','environment','observed_at','status'];
function exact(x,keys){return x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));}

/** Verify separately signed observation; this cannot prove real-world truth by itself. */
export function reconcile({intent,intent_ack,result,result_ack,observation,observation_signature,
                           trustedAudit,trustedObserver,now=Math.floor(Date.now()/1000)}){
  if(!validEvent(intent)||intent.type!=='intent'||!validEvent(result)||result.type!=='result')throw Error('EVENT_INVALID');
  for(const key of ['owner_id','node','run','proposal_id','action_digest','grant_sha256','nonce','audience','environment'])
    if(intent[key]!==result[key])throw Error('EVENT_BINDING_MISMATCH');
  if(!verifyAuditAck(intent,intent_ack,trustedAudit)||!verifyAuditAck(result,result_ack,trustedAudit))throw Error('AUDIT_ACK_INVALID');
  if(!trustedObserver||!trustedObserver.public_jwk||trustedObserver.public_jwk.x===trustedAudit.public_jwk.x)
    throw Error('OBSERVER_KEY_NOT_DISTINCT');
  if(!exact(observation,FIELDS)||observation.schema!=='sac.effect-observation.v2'||
     observation.observer_id!==trustedObserver.id||!Array.isArray(trustedObserver.allowed_sources)||
     !trustedObserver.allowed_sources.includes(observation.source)||observation.status!=='present'||
     observation.owner_id!==result.owner_id||observation.proposal_id!==result.proposal_id||
     observation.grant_sha256!==result.grant_sha256||
     observation.execution_id!==result.execution_id||observation.action_digest!==result.action_digest||
     observation.effect_sha256!==result.effect_sha256||observation.audience!==result.audience||
     observation.environment!==result.environment||!Number.isSafeInteger(observation.observed_at)||
     !Number.isSafeInteger(now)||observation.observed_at<intent_ack.ack.accepted_at||observation.observed_at>now)
    throw Error('OBSERVATION_BINDING_INVALID');
  if(!verifyEd25519(trustedObserver.public_jwk,observation_signature,OBS_DOMAIN+canonical(observation)))
    throw Error('OBSERVER_SIGNATURE_INVALID');
  return {status:'RECONCILED_SIGNED_OBSERVATION',execution_id:result.execution_id,
    intent_sha256:eventDigest(intent),result_sha256:eventDigest(result),
    observer_statement_sha256:sha256(canonical(observation)),
    limitation:'Signatures establish who attested; independent operational control and source truth require separate verification.'};
}

if(process.argv[1]?.endsWith('/reconcile.mjs')){
  try{
    if(process.argv.length!==4)throw Error('Usage: node reconcile.mjs <evidence.json> <trusted-config.json>');
    const text=(await readFile(process.argv[2],'utf8')).trim();
    const data=JSON.parse(text);
    if(JSON.stringify(data)!==text||!exact(data,['intent','intent_ack','result','result_ack','observation','observation_signature']))
      throw Error('UNTRUSTED_EVIDENCE_INVALID');
    const config=JSON.parse(await readPrivateFile(process.argv[3]));
    if(!exact(config,['trustedAudit','trustedObserver']))throw Error('TRUSTED_CONFIGURATION_INVALID');
    console.log(JSON.stringify(reconcile({...data,...config}),null,2));
  }catch(e){console.error(JSON.stringify({status:'NOT_RECONCILED',error:e.message}));process.exitCode=2;}
}
