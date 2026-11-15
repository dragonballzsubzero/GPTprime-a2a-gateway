import {readFile} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,randomBytes,sign} from 'node:crypto';
import {createInterface} from 'node:readline/promises';
import {canonical,digest} from '../broker-v03/client.mjs';
import {GRANT_DOMAIN,NODE_DOMAIN,validateCanaryAction,verifyEd25519,verifyExactGrant} from './core.mjs';
import {readPrivateFile} from './secrets.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KID=/^[A-Za-z0-9_.:-]{1,128}$/;
function exact(obj,keys){return obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k));}

/** Validates only; this function does not imply the owner has approved. */
export function validateApprovalRequest(proposal,config){
  if(!exact(proposal,['action','action_digest','proposal_id','node_kid','node_signature_b64url'])||
     !validateCanaryAction(proposal.action)||!UUID.test(proposal.proposal_id||'')||
     proposal.action_digest!==digest(proposal.action)||proposal.node_kid!==config.node_kid||
     !UUID.test(config.owner_id||'')||!KID.test(config.owner_kid||'')||!KID.test(config.node_kid||'')||
     typeof config.audience!=='string'||!/^sac:\/\/broker\/[a-z0-9._/-]{1,100}$/.test(config.audience)||
     !['development','staging','production'].includes(config.environment)||
     !verifyEd25519(config.node_public_jwk,proposal.node_signature_b64url,NODE_DOMAIN+canonical(proposal.action)))
    throw new Error('PROPOSAL_OR_TRUSTED_CONFIGURATION_INVALID');
  return true;
}

/** Called only after the human confirmation in the CLI or an independent authorized owner workflow. */
export function signOwnerGrant(proposal,config,privatePem,{now=Math.floor(Date.now()/1000),nonce=randomBytes(16).toString('hex')}={}){
  validateApprovalRequest(proposal,config);
  if(!Number.isSafeInteger(now)||now<0||typeof nonce!=='string'||!/^[0-9a-f]{32}$/.test(nonce))throw new Error('INVALID_CLOCK_OR_NONCE');
  const privateKey=createPrivateKey(privatePem);
  if(privateKey.asymmetricKeyType!=='ed25519')throw new Error('ED25519_OWNER_KEY_REQUIRED');
  const derived=createPublicKey(privateKey).export({format:'jwk'});
  if(!config.owner_public_jwk||derived.x!==config.owner_public_jwk.x||derived.crv!=='Ed25519')throw new Error('OWNER_KEY_MISMATCH');
  const action=proposal.action;
  const grant={schema:'sac.exact-action.v4',owner:config.owner_id,node:action.node,run:action.run,
    action_digest:proposal.action_digest,proposal_id:proposal.proposal_id,nonce,iat:now,exp:now+120,
    audience:config.audience,environment:config.environment,owner_kid:config.owner_kid,node_kid:config.node_kid};
  const signature_b64url=sign(null,Buffer.from(GRANT_DOMAIN+canonical(grant)),privateKey).toString('base64url');
  if(!verifyExactGrant({grant,signature:signature_b64url,public_jwk:config.owner_public_jwk,
    action,proposal_id:proposal.proposal_id,owner_id:config.owner_id,owner_kid:config.owner_kid,
    node_kid:config.node_kid,audience:config.audience,environment:config.environment,now}))
    throw new Error('SIGNED_GRANT_SELF_CHECK_FAILED');
  return {grant,owner_kid:config.owner_kid,grant_signature_b64url:signature_b64url};
}

async function main(){
  if(process.argv.length!==3||!process.stdin.isTTY||!process.stderr.isTTY)
    throw new Error('INTERACTIVE_OWNER_TERMINAL_AND_PROPOSAL_FILE_REQUIRED');
  for(const name of ['SAC_OWNER_ID','SAC_OWNER_KEY_ID','SAC_NODE_KEY_ID','SAC_BROKER_AUDIENCE','SAC_BROKER_ENVIRONMENT',
                     'SAC_OWNER_PRIVATE_KEY_PATH','SAC_OWNER_PUBLIC_JWK_PATH','SAC_NODE_PUBLIC_JWK_PATH'])
    if(!process.env[name])throw new Error('Missing trusted owner configuration: '+name);
  const proposalText=(await readFile(process.argv[2],'utf8')).trim();
  const proposal=JSON.parse(proposalText);
  if(JSON.stringify(proposal)!==proposalText)throw new Error('NONCANONICAL_PROPOSAL_FILE');
  const config={owner_id:process.env.SAC_OWNER_ID,owner_kid:process.env.SAC_OWNER_KEY_ID,node_kid:process.env.SAC_NODE_KEY_ID,
    audience:process.env.SAC_BROKER_AUDIENCE,environment:process.env.SAC_BROKER_ENVIRONMENT,
    owner_public_jwk:JSON.parse(await readFile(process.env.SAC_OWNER_PUBLIC_JWK_PATH,'utf8')),
    node_public_jwk:JSON.parse(await readFile(process.env.SAC_NODE_PUBLIC_JWK_PATH,'utf8'))};
  validateApprovalRequest(proposal,config);
  console.error(JSON.stringify({owner_id:config.owner_id,audience:config.audience,environment:config.environment,
    owner_kid:config.owner_kid,node_kid:config.node_kid,proposal_id:proposal.proposal_id,
    action_digest:proposal.action_digest,action:proposal.action},null,2));
  const terminal=createInterface({input:process.stdin,output:process.stderr});
  let answer;
  try{answer=await terminal.question('Type APPROVE followed by the displayed action digest: ');}finally{terminal.close();}
  if(answer!=='APPROVE '+proposal.action_digest)throw new Error('OWNER_APPROVAL_NOT_CONFIRMED');
  const secret=await readPrivateFile(process.env.SAC_OWNER_PRIVATE_KEY_PATH);
  console.log(JSON.stringify(signOwnerGrant(proposal,config,secret)));
}
if(process.argv[1]?.endsWith('/owner-approve.mjs'))main().catch(e=>{console.error(e.message);process.exitCode=2;});
