/* SAC-CF-1 confidential message candidate, v0.1.0.
 * Independent host keys are REQUIRED. This is an additive local protocol component,
 * not a live SaaS gateway and not a claim of HPKE interoperability.
 * Production admission additionally requires current founder grants, identity
 * pinning, durable replay storage and external runtime execution evidence.
 */
import {
  createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes,
  diffieHellman, hkdfSync, createCipheriv, createDecipheriv,
  sign, verify, createHash,
} from 'node:crypto';

const SCHEMA='SAC-CF-1', MAX=32000, MAX_WIRE=65536, TTL=300000;
const N=/^[a-z][a-z0-9._-]{2,63}$/;
const HEX=/^[0-9a-f]{32}$/, SHA=/^[0-9a-f]{64}$/;
const B64=/^[a-zA-Z0-9_-]+$/;
const KEYS=['schema','sender','recipient','capability','job_id','nonce','policy_sha256','issued_at_ms','expires_at_ms','ephemeral_spki','salt','iv','ciphertext','tag','signature'];
const fail=(test,reason)=>{if(!test)throw new Error(reason)};
const encode=b=>Buffer.from(b).toString('base64url');
const digest=b=>createHash('sha256').update(b).digest('hex');
function decode(x, limit){
  fail(typeof x==='string'&&x.length>0&&B64.test(x),'INVALID_B64URL');
  const b=Buffer.from(x,'base64url');
  fail(b.length<=limit&&encode(b)===x,'NONCANONICAL_B64URL');
  return b;
}
function props(e){
  fail(e&&typeof e==='object'&&!Array.isArray(e),'INVALID_FRAME');
  fail(Object.keys(e).length===KEYS.length&&KEYS.every(k=>Object.hasOwn(e,k)),'INVALID_FIELDS');
  fail(e.schema===SCHEMA,'UNSUPPORTED_SCHEMA');
  fail(N.test(e.sender)&&N.test(e.recipient)&&N.test(e.capability),'INVALID_IDENTITY');
  fail(HEX.test(e.job_id)&&HEX.test(e.nonce)&&SHA.test(e.policy_sha256),'INVALID_BINDING');
  fail(Number.isSafeInteger(e.issued_at_ms)&&Number.isSafeInteger(e.expires_at_ms)&&e.expires_at_ms>=e.issued_at_ms&&e.expires_at_ms-e.issued_at_ms<=TTL,'INVALID_WINDOW');
}
function header(e){
  // Fixed ordered array: explicitly versioned signing input, not RFC 8785/JCS.
  return Buffer.from(JSON.stringify(KEYS.slice(0,-1).map(k=>e[k])),'utf8');
}
function aad(e){return Buffer.from(JSON.stringify([e.schema,e.sender,e.recipient,e.capability,e.job_id,e.nonce,e.policy_sha256,e.issued_at_ms,e.expires_at_ms]),'utf8');}
function key(shared,salt,recipient){return Buffer.from(hkdfSync('sha256',shared,salt,Buffer.from('SAC-CF-1:'+recipient,'utf8'),32));}
export function generateFrameKeys(){
  const signKeys=generateKeyPairSync('ed25519'),encKeys=generateKeyPairSync('x25519');
  const save=(k,type)=>k.export({type,format:'pem'}).toString();
  return {sign_private_pem:save(signKeys.privateKey,'pkcs8'),sign_public_pem:save(signKeys.publicKey,'spki'),
    enc_private_pem:save(encKeys.privateKey,'pkcs8'),enc_public_pem:save(encKeys.publicKey,'spki')};
}
export function sealFrame({sender,recipient,capability,policy_sha256,plaintext,sender_sign_private_pem,recipient_enc_public_pem,now=Date.now(),ttl_ms=60000}){
  const bytes=Buffer.from(plaintext);
  fail(bytes.length>=1&&bytes.length<=MAX,'PAYLOAD_TOO_LARGE');
  fail(Number.isSafeInteger(now)&&Number.isSafeInteger(ttl_ms)&&ttl_ms>=1&&ttl_ms<=TTL,'INVALID_TIME');
  const ephem=generateKeyPairSync('x25519'),salt=randomBytes(16),iv=randomBytes(12);
  const shared=diffieHellman({privateKey:ephem.privateKey,publicKey:createPublicKey(recipient_enc_public_pem)});
  const e={schema:SCHEMA,sender,recipient,capability,job_id:randomBytes(16).toString('hex'),nonce:randomBytes(16).toString('hex'),policy_sha256,
   issued_at_ms:now,expires_at_ms:now+ttl_ms,ephemeral_spki:encode(ephem.publicKey.export({format:'der',type:'spki'})),salt:encode(salt),iv:encode(iv),ciphertext:'',tag:'',signature:''};
  props(e);
  const symmetric=key(shared,salt,recipient);
  try{
    const cipher=createCipheriv('aes-256-gcm',symmetric,iv);
    cipher.setAAD(aad(e));
    e.ciphertext=encode(Buffer.concat([cipher.update(bytes),cipher.final()]));e.tag=encode(cipher.getAuthTag());
    e.signature=encode(sign(null,header(e),createPrivateKey(sender_sign_private_pem)));
    fail(Buffer.byteLength(JSON.stringify(e),'utf8')<=MAX_WIRE,'FRAME_TOO_LARGE');
    return e;
  }finally{symmetric.fill(0);shared.fill(0);}
}
export async function openFrame(e,{expected_recipient,expected_capability,expected_policy_sha256,sender_sign_public_pem,recipient_enc_private_pem,replay_store,now=Date.now(),skew_ms=30000}={}){
  props(e);
  fail(e.recipient===expected_recipient,'RECIPIENT_MISMATCH');
  fail(e.capability===expected_capability,'CAPABILITY_MISMATCH');
  fail(e.policy_sha256===expected_policy_sha256,'POLICY_MISMATCH');
  fail(Number.isSafeInteger(now)&&Number.isSafeInteger(skew_ms)&&skew_ms>=0&&skew_ms<=60000,'INVALID_TIME');
  fail(now+skew_ms>=e.issued_at_ms&&now-skew_ms<=e.expires_at_ms,'EXPIRED_OR_FUTURE');
  const sig=decode(e.signature,64);fail(sig.length===64,'BAD_SIGNATURE_LENGTH');
  fail(typeof sender_sign_public_pem==='string'&&verify(null,header(e),createPublicKey(sender_sign_public_pem),sig),'BAD_SENDER_SIGNATURE');
  fail(replay_store&&typeof replay_store.claim==='function','REPLAY_STORE_REQUIRED');
  const ephem=decode(e.ephemeral_spki,128),salt=decode(e.salt,16),iv=decode(e.iv,12),ct=decode(e.ciphertext,MAX),tag=decode(e.tag,16);
  fail(salt.length===16&&iv.length===12&&tag.length===16,'INVALID_CIPHER_FRAME');
  // Authenticate ciphertext BEFORE allocating a durable replay slot.
  // A validly signed but AEAD-invalid frame must not consume the original nonce.
  // Durable atomic claim still happens BEFORE any plaintext is returned.
  const shared=diffieHellman({privateKey:createPrivateKey(recipient_enc_private_pem),publicKey:createPublicKey({key:ephem,format:'der',type:'spki'})});
  const symmetric=key(shared,salt,e.recipient);
  let plaintext;
  try{
    const decipher=createDecipheriv('aes-256-gcm',symmetric,iv);
    decipher.setAAD(aad(e));decipher.setAuthTag(tag);
    plaintext=Buffer.concat([decipher.update(ct),decipher.final()]);
    await replay_store.claim(e.sender,e.nonce,digest(header(e)));
    return {plaintext,sender:e.sender,recipient:e.recipient,capability:e.capability,job_id:e.job_id,wire_sha256:digest(header(e)),effect_authorized:false,provider_execution_verified:false};
  }catch(err){
    // Clear locally authenticated plaintext if persistence/claim fails.
    if(plaintext)plaintext.fill(0);
    throw err;
  }finally{symmetric.fill(0);shared.fill(0);}
}