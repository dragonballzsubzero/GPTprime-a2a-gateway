import {canonical} from '../broker-v03/client.mjs';
import {NODE_DOMAIN,validateCanaryAction,verifyEd25519} from './core.mjs';

/** A host-controlled signer owns the node key; the model supplies only an action. */
export async function signProposal({action,node_kid,node_public_jwk,signer}){
  if(!validateCanaryAction(action)||typeof node_kid!=='string'||!/^[A-Za-z0-9_.:-]{1,128}$/.test(node_kid)||typeof signer!=='function')
    throw new Error('PROPOSAL_INVALID');
  const message=Buffer.from(NODE_DOMAIN+canonical(action));
  const raw=await signer(message);
  if(!(raw instanceof Uint8Array)||raw.length!==64)throw new Error('NODE_SIGNER_FAILED');
  const signature=Buffer.from(raw).toString('base64url');
  if(!verifyEd25519(node_public_jwk,signature,message.toString('utf8')))throw new Error('NODE_SIGNER_KEY_MISMATCH');
  return {action,node_kid,node_signature_b64url:signature};
}
