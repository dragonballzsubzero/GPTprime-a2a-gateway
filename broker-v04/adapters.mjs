import {BrokerError} from './core.mjs';

const MAX_RESPONSE=32768;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function httpsBase(value) {
  const u=new URL(value);
  if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash || (u.pathname!=='/' && u.pathname!==''))
    throw new Error('HTTPS_BASE_ORIGIN_REQUIRED');
  return u.origin;
}
async function jsonResponse(res) {
  if(!res.body) throw new Error('EMPTY_RESPONSE');
  const reader=res.body.getReader(); let size=0, chunks=[];
  try {
    for(;;){const p=await reader.read(); if(p.done)break; size+=p.value.length;
      if(size>MAX_RESPONSE){await reader.cancel();throw new Error('RESPONSE_TOO_LARGE');} chunks.push(p.value);}
  } finally { reader.releaseLock(); }
  const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));
  return JSON.parse(text);
}
function jwtClaims(token) {
  const parts=token.split('.');
  if(parts.length!==3 || !parts.every(x=>/^[A-Za-z0-9_-]+$/.test(x))) throw new Error('JWT_SHAPE');
  const bytes=Buffer.from(parts[1],'base64url');
  if(bytes.length>8192 || bytes.toString('base64url')!==parts[1])throw new Error('JWT_ENCODING');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const value=JSON.parse(text);
  // Compact serialization eliminates duplicate JSON member ambiguity.
  if(!value || Array.isArray(value) || typeof value!=='object' || JSON.stringify(value)!==text)throw new Error('JWT_CLAIMS_JSON');
  return value;
}

/** Host-only adapter. Network access is restricted to a configured HTTPS origin. */
export function createSupabaseAdapters({origin, anonKey, serviceKey, fetchImpl=fetch, clock=()=>Math.floor(Date.now()/1000)}) {
  const base=httpsBase(origin);
  if(typeof anonKey!=='string' || !anonKey || typeof serviceKey!=='string' || !serviceKey)throw new Error('SUPABASE_CONFIGURATION_REQUIRED');
  async function request(path,body) {
    const res=await fetchImpl(base+path,{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),
      headers:{'content-type':'application/json','apikey':serviceKey,'authorization':'Bearer '+serviceKey},body:JSON.stringify(body)});
    if(!res.ok)throw new Error('CONTROL_PLANE_UNAVAILABLE');
    return jsonResponse(res);
  }
  const auth={async authenticate(token){
    let claims;
    try {claims=jwtClaims(token);} catch {throw new BrokerError('AUTH_SESSION_DENIED',401);}
    const now=clock();
    if(claims.iss!==base+'/auth/v1' || claims.aal!=='aal2' || !UUID.test(claims.sub || '') ||
       !UUID.test(claims.session_id || '') || !Number.isSafeInteger(now) ||
       !Number.isSafeInteger(claims.iat) || claims.iat>now+30 || claims.iat<now-900 ||
       !Number.isSafeInteger(claims.exp) || claims.exp<=now)throw new BrokerError('AUTH_SESSION_DENIED',401);
    let res,user;
    try {
      res=await fetchImpl(base+'/auth/v1/user',{headers:{apikey:anonKey,authorization:'Bearer '+token},
        redirect:'error',signal:AbortSignal.timeout(5000)});
    } catch {throw new BrokerError('AUTH_SERVICE_UNAVAILABLE',503);}
    if(res.status===401||res.status===403)throw new BrokerError('AUTH_SESSION_DENIED',401);
    if(!res.ok)throw new BrokerError('AUTH_SERVICE_UNAVAILABLE',503);
    try {user=await jsonResponse(res);} catch {throw new BrokerError('AUTH_SERVICE_UNAVAILABLE',503);}
    if(!user||typeof user!=='object'||Array.isArray(user)||typeof user.id!=='string')
      throw new BrokerError('AUTH_SERVICE_UNAVAILABLE',503);
    if(!user || user.id!==claims.sub)throw new BrokerError('AUTH_SESSION_DENIED',401);
    let gate;
    try {
      gate=await request('/rest/v1/rpc/gptprime_v19_owner_session_gate_v1',{
        p_user_id:user.id,p_session_id:claims.session_id,p_token_issued_at:new Date(claims.iat*1000).toISOString()});
    }catch{throw new BrokerError('AUTH_SESSION_GATE_UNAVAILABLE',503);}
    if(!gate||typeof gate!=='object'||Array.isArray(gate)||gate.schema!=='gptprime.owner-session-gate.v1'||
       typeof gate.allowed!=='boolean'||typeof gate.code!=='string')
      throw new BrokerError('AUTH_SESSION_GATE_UNAVAILABLE',503);
    if(!gate.allowed)throw new BrokerError('AUTH_SESSION_DENIED',401);
    if(gate.code!=='OWNER_SESSION_VERIFIED')throw new BrokerError('AUTH_SESSION_GATE_UNAVAILABLE',503);
    return {owner_id:user.id,aal:'aal2'};
  }};
  const keys={resolve(owner_id,node){return request('/rest/v1/rpc/sac_broker_v03_keys',{p_owner:owner_id,p_node:node});}};
  const store={
    propose({owner_id,action,action_digest}){
      return request('/rest/v1/rpc/sac_broker_v03_propose',{p_owner:owner_id,p_node:action.node,
        p_run:action.run,p_digest:action_digest,p_action:action});
    },
    executeCanary(p){
      // This v0.4 RPC is NOT installed by this client. There is deliberately no
      // fallback to v0.3, whose transaction cannot check grant expiry or key IDs.
      return request('/rest/v1/rpc/sac_broker_v04_execute_canary',{
        p_owner:p.owner_id,p_node:p.action.node,p_run:p.action.run,p_digest:p.action_digest,
        p_nonce:p.nonce,p_proposal:p.proposal_id,p_canary_tag:p.action.parameters.tag,
        p_grant_iat:p.grant_iat,p_grant_exp:p.grant_exp,p_owner_kid:p.owner_kid,p_node_kid:p.node_kid,
        p_grant_sha256:p.grant_sha256,p_audit_intent_sha256:p.audit_intent_sha256,
        p_audit_ack_sha256:p.audit_ack_sha256});
    }
  };
  return {auth,keys,store};
}

export function createHttpsAuditClient({origin, secretProvider, fetchImpl=fetch}) {
  const base=httpsBase(origin);
  if(typeof secretProvider!=='function')throw new Error('AUDIT_CREDENTIAL_PROVIDER_REQUIRED');
  async function credential(){
    const secret=await secretProvider();
    if(typeof secret!=='string' || secret.length<32 || /[\r\n]/.test(secret))throw new Error('AUDIT_CREDENTIAL_UNAVAILABLE');
    return secret;
  }
  return {async append(event){
    const secret=await credential();
    const response=await fetchImpl(base+'/append',{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),
      headers:{'content-type':'application/json',authorization:'Bearer '+secret},body:JSON.stringify(event)});
    if(!response.ok)throw new Error('AUDIT_UNAVAILABLE');
    return jsonResponse(response);
  },async head(){
    const secret=await credential();
    const response=await fetchImpl(base+'/head',{method:'GET',redirect:'error',signal:AbortSignal.timeout(5000),
      headers:{authorization:'Bearer '+secret}});
    if(!response.ok)throw new Error('AUDIT_UNAVAILABLE');
    return jsonResponse(response);
  }};
}
