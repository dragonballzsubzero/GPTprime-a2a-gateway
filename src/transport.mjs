import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { mkdir, open, readFile, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';

export const PROTOCOL = 'SAC-A2A-TRANSPORT-1';
export const VERSION = '0.34';
const LIMIT = 65536;
const NODE = /^[a-z][a-z0-9._-]{2,63}$/;
const HEX = /^[a-f0-9]{64}$/;
const HEX32 = /^[a-f0-9]{32}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const RECEIPT_KEYS = ['protocol','version','node_id','request_sha256','result_sha256','status','execution_class','completed_at_ms','signature_b64url'];
const ENVELOPE_KEYS = ['protocol','version','sender','recipient','message_id','nonce','issued_at_ms','expires_at_ms','operation','payload_b64url','signature_b64url'];

export const sha256 = b => createHash('sha256').update(b).digest('hex');
export const b64u = b => Buffer.from(b).toString('base64url');

function assert(condition, why) { if (!condition) throw new Error(why); }
function exact(obj, keys) {
  assert(obj && typeof obj === 'object' && !Array.isArray(obj), 'INVALID_OBJECT');
  assert(Object.keys(obj).length === keys.length && keys.every(k => Object.hasOwn(obj,k)), 'INVALID_FIELDS');
}
function strictDecode(s, maxBytes = LIMIT) {
  assert(typeof s === 'string' && B64URL.test(s), 'INVALID_BASE64URL');
  const b = Buffer.from(s, 'base64url');
  assert(b.length <= maxBytes && b64u(b) === s, 'NONCANONICAL_BASE64URL');
  return b;
}
export function publicKeyPem(privatePem) {
  return createPublicKey(createPrivateKey(privatePem)).export({type:'spki',format:'pem'}).toString();
}
export function generateIdentity() {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  return {
    private_pem: privateKey.export({type:'pkcs8',format:'pem'}).toString(),
    public_pem: publicKey.export({type:'spki',format:'pem'}).toString()
  };
}
export function coreForSignature(e) {
  exact(e, ENVELOPE_KEYS);
  assert(e.protocol === PROTOCOL && e.version === VERSION, 'UNSUPPORTED_PROTOCOL');
  assert(NODE.test(e.sender) && NODE.test(e.recipient), 'INVALID_NODE');
  assert(HEX32.test(e.message_id) && HEX32.test(e.nonce), 'INVALID_IDENTIFIER');
  assert(Number.isSafeInteger(e.issued_at_ms) && Number.isSafeInteger(e.expires_at_ms), 'INVALID_TIMESTAMP');
  assert(e.operation === 'probe.sha256', 'UNSUPPORTED_OPERATION');
  const payload = strictDecode(e.payload_b64url);
  const lines = [PROTOCOL, VERSION, e.sender, e.recipient, e.message_id, e.nonce,
    String(e.issued_at_ms), String(e.expires_at_ms), e.operation, sha256(payload)];
  return {message: Buffer.from(lines.join('\n')+'\n','utf8'), payload};
}
export function createEnvelope({sender, recipient, payload, privatePem, now=Date.now(), ttlMs=60000}) {
  assert(Number.isSafeInteger(now) && Number.isSafeInteger(ttlMs) && ttlMs >= 1 && ttlMs <= 300000, 'INVALID_TTL');
  const e = {
    protocol:PROTOCOL, version:VERSION, sender, recipient,
    message_id:randomBytes(16).toString('hex'), nonce:randomBytes(16).toString('hex'),
    issued_at_ms:now, expires_at_ms:now + ttlMs, operation:'probe.sha256',
    payload_b64url:b64u(payload), signature_b64url:'AA'
  };
  const {message} = coreForSignature(e);
  e.signature_b64url = b64u(sign(null,message,createPrivateKey(privatePem)));
  return e;
}
export function verifyEnvelope(e, trustStore, {now=Date.now(), recipient, skewMs=30000}={}) {
  const {message,payload}=coreForSignature(e);
  assert(HEX32.test(e.nonce), 'INVALID_NONCE');
  assert(e.expires_at_ms >= e.issued_at_ms && e.expires_at_ms-e.issued_at_ms <= 300000,'INVALID_WINDOW');
  assert(now + skewMs >= e.issued_at_ms && now - skewMs <= e.expires_at_ms,'EXPIRED_OR_FUTURE');
  if (recipient !== undefined) assert(e.recipient === recipient,'RECIPIENT_MISMATCH');
  assert(trustStore && Object.hasOwn(trustStore,e.sender) && typeof trustStore[e.sender] === 'string','UNTRUSTED_SENDER');
  const sig = strictDecode(e.signature_b64url, 64);
  assert(sig.length === 64,'BAD_SIGNATURE_LENGTH');
  assert(verify(null,message,createPublicKey(trustStore[e.sender]),sig),'INVALID_SIGNATURE');
  return {payload, requestHash:sha256(message), sender:e.sender, nonce:e.nonce};
}
export function signedReceipt({node_id,request_sha256,result_sha256,privatePem,now=Date.now()}) {
  assert(NODE.test(node_id) && HEX.test(request_sha256) && HEX.test(result_sha256) && Number.isSafeInteger(now),'INVALID_RECEIPT');
  const r={protocol:PROTOCOL,version:VERSION,node_id,request_sha256,result_sha256,
    status:'completed',execution_class:'local_integrity_probe',completed_at_ms:now,signature_b64url:'AA'};
  const message=receiptMessage(r);
  r.signature_b64url=b64u(sign(null,message,createPrivateKey(privatePem)));
  return r;
}
function receiptMessage(r) {
  exact(r, RECEIPT_KEYS);
  assert(r.protocol===PROTOCOL && r.version===VERSION && NODE.test(r.node_id),'INVALID_RECEIPT');
  assert(HEX.test(r.request_sha256) && HEX.test(r.result_sha256),'INVALID_DIGEST');
  assert(r.status==='completed' && r.execution_class==='local_integrity_probe','UNSUPPORTED_RECEIPT');
  assert(Number.isSafeInteger(r.completed_at_ms),'INVALID_TIMESTAMP');
  return Buffer.from([PROTOCOL,VERSION,r.node_id,r.request_sha256,r.result_sha256,r.status,r.execution_class,String(r.completed_at_ms)].join('\n')+'\n');
}
export function verifyReceipt(r, trustedPublicPem, expectedRequestHash) {
  const message=receiptMessage(r);
  if(expectedRequestHash) assert(r.request_sha256===expectedRequestHash,'WRONG_REQUEST_HASH');
  const signature=strictDecode(r.signature_b64url,64);
  assert(signature.length===64 && verify(null,message,createPublicKey(trustedPublicPem),signature),'INVALID_RECEIPT_SIGNATURE');
  return true;
}
export function parseStrictWire(bytes) {
  const str = Buffer.from(bytes).toString('utf8');
  assert(Buffer.byteLength(str,'utf8')===Buffer.byteLength(bytes) && Buffer.byteLength(bytes)<=131072,'BODY_TOO_LARGE_OR_ENCODING');
  const obj=JSON.parse(str);
  // Canonical Node JSON serialization avoids duplicate object members and divergent parsers.
  assert(str===JSON.stringify(obj),'NONCANONICAL_WIRE_JSON');
  return obj;
}
export class FileReplayStore {
  constructor(stateDir){this.dir=stateDir;}
  async claim(sender,nonce,requestHash){
    assert(NODE.test(sender) && HEX32.test(nonce) && HEX.test(requestHash),'INVALID_REPLAY_ID');
    const dir=path.join(this.dir,'nonces');
    await mkdir(dir,{recursive:true,mode:0o700});
    const filename=path.join(dir,sha256(Buffer.from(sender+'\n'+nonce)) +'.json');
    let file;
    try {file=await open(filename,'wx',0o600);} catch(e){if(e.code==='EEXIST')throw new Error('REPLAY_DETECTED'); throw e;}
    try {await file.writeFile(JSON.stringify({sender,nonce,request_sha256:requestHash}));await file.sync();}finally{await file.close();}
    return true;
  }
  async saveReceipt(r){
    const dir=path.join(this.dir,'receipts'); await mkdir(dir,{recursive:true,mode:0o700});
    const target=path.join(dir,r.request_sha256+'.json');
    const tempfile=target+'.'+randomBytes(8).toString('hex')+'.tmp';
    let f=await open(tempfile,'wx',0o600);
    try {await f.writeFile(JSON.stringify(r)+'\n'); await f.sync();} finally {await f.close();}
    await rename(tempfile,target);
  }
}