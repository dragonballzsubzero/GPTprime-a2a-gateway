
import { createClient } from "npm:@supabase/supabase-js@2.95.0";

const SCHEMA = "sac.exact-action.v3";
const NODE_SCHEMA = "sac.node-proposal.v3";
const ALLOWED_NODES = new Set(["gptprime.future.preview", "geminiprime.preview.v1", "llamaprime.preview.v1"]);
const MAX_BODY = 12000;
const MAX_TIME = 180;
const ASCII_TAG = /^[A-Za-z0-9_.:-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;

function reply(status:number, data:unknown) {
  return new Response(JSON.stringify(data), {status,headers:{
    "Content-Type":"application/json","Cache-Control":"no-store",
    "X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY"
  }});
}
function isObj(x:unknown):x is Record<string,unknown> {
  return x!==null && typeof x==="object" && !Array.isArray(x);
}
function ownKeys(x:Record<string,unknown>, names:string[]) {
  const keys=Object.keys(x);
  return keys.length===names.length && keys.every(k=>names.includes(k));
}
function stable(x:unknown):string {
  if(x===null) return "null";
  if(typeof x==="string" || typeof x==="boolean") return JSON.stringify(x);
  if(typeof x==="number" && Number.isFinite(x) && Number.isSafeInteger(x))return JSON.stringify(x);
  if(Array.isArray(x)) {if(x.length>100) throw Error("array length");return "["+x.map(stable).join(",")+"]";}
  if(isObj(x)){
    const keys=Object.keys(x).sort();
    if(keys.length>32 || keys.some(k=>["__proto__","prototype","constructor"].includes(k))) throw Error("unsafe key");
    return "{"+keys.map(k=>JSON.stringify(k)+":"+stable(x[k])).join(",")+"}";
  }
  throw Error("unsupported value");
}
function strictDecode(s:unknown, expected:number):Uint8Array {
  if(typeof s!=="string" || !/^[A-Za-z0-9_-]+$/.test(s) || s.length>512)throw Error("bad encoding");
  const normalized=s.replace(/-/g,"+").replace(/_/g,"/");
  const raw=atob(normalized+"=".repeat((4-normalized.length%4)%4));
  const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
  const canon=btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  if(bytes.length!==expected || canon!==s)throw Error("bad length or noncanonical encoding");
  return bytes;
}
async function hashHex(s:string):Promise<string> {
  const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));
  return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function verifySig(jwk:unknown,signature:unknown,message:string):Promise<boolean> {
  if(!isObj(jwk)||!ownKeys(jwk,["kty","crv","x"])||jwk.kty!=="OKP"||jwk.crv!=="Ed25519")return false;
  try{
    strictDecode(jwk.x,32);
    const sig=strictDecode(signature,64);
    const key=await crypto.subtle.importKey("jwk",{
      kty:"OKP",crv:"Ed25519",x:jwk.x as string,ext:true
    },{name:"Ed25519"},false,["verify"]);
    return await crypto.subtle.verify("Ed25519",key,sig,new TextEncoder().encode(message));
  } catch {return false;}
}
function validateAction(action:unknown): action is Record<string,unknown> {
  if(!isObj(action)||!ownKeys(action,["node","run","operation","resource","parameters"]))return false;
  if(typeof action.node!=="string"||!ALLOWED_NODES.has(action.node))return false;
  if(typeof action.run!=="string"||!/^[A-Za-z0-9_.:-]{1,100}$/.test(action.run))return false;
  if(action.operation!=="audit_canary"||action.resource!=="sac://broker/canary")return false;
  if(!isObj(action.parameters)||!ownKeys(action.parameters,["tag"]) || typeof action.parameters.tag!=="string" || !ASCII_TAG.test(action.parameters.tag))return false;
  return true;
}
async function main(req:Request):Promise<Response> {
  if(req.method!=="POST" && req.method!=="GET")return reply(405,{error:"METHOD_NOT_ALLOWED"});
  const url=new URL(req.url);
  const path=url.pathname.split("/").pop();
  const header=req.headers.get("authorization")||"";
  if(!/^Bearer [A-Za-z0-9._-]{20,}$/.test(header))return reply(401,{error:"USER_TOKEN_REQUIRED"});
  const base=Deno.env.get("SUPABASE_URL");
  const anon=Deno.env.get("SUPABASE_ANON_KEY");
  const svc=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if(!base||!anon||!svc)return reply(503,{error:"BROKER_CONFIGURATION_UNAVAILABLE"});
  const token=header.slice(7);
  const auth=createClient(base,anon,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:{user},error:authError}=await auth.auth.getUser(token);
  if(authError||!user?.id)return reply(401,{error:"INVALID_USER_SESSION"});
  if(req.method==="GET" && path==="status"){
    return reply(200,{schema:SCHEMA,broker:"sac_broker_v03",mode:"FAIL_CLOSED",
      exposed_effects:["audit_canary"],quarantine_enforced:true,
      key_enrollment:"ADMIN_OUT_OF_BAND",production_qualified:false});
  }
  if(req.method!=="POST" || !["propose","execute"].includes(path||""))return reply(404,{error:"NOT_FOUND"});
  const raw=await req.text();
  if(raw.length>MAX_BODY)return reply(413,{error:"REQUEST_TOO_LARGE"});
  let body:unknown;
  try {body=JSON.parse(raw);} catch {return reply(400,{error:"INVALID_JSON"});}
  if(!isObj(body)||!isObj(body.action)||!validateAction(body.action))
    return reply(422,{error:"INVALID_ACTION"});
  const action=body.action;
  const admin=createClient(base,svc,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:keys,error:keyError}=await admin.rpc("sac_broker_v03_keys",{
    p_owner:user.id,p_node:action.node
  });
  if(keyError)return reply(503,{error:"CONTROL_PLANE_UNAVAILABLE"});
  if(!keys || keys.allowed!==true)return reply(403,{error:"NODE_OR_OWNER_NOT_ENROLLED",reason:keys?.reason||"NO_KEYS"});
  if(body.node_kid!==keys.node_kid)return reply(403,{error:"NODE_KEY_MISMATCH"});
  let actionBytes="";
  try {actionBytes=stable(action);} catch {return reply(422,{error:"UNSAFE_ACTION_JSON"});}
  const digest=await hashHex(actionBytes);
  if(!await verifySig(keys.node_key,body.node_signature_b64url,NODE_SCHEMA+"\n"+actionBytes))
    return reply(403,{error:"INVALID_NODE_SIGNATURE"});
  if(path==="propose"){
    const {data,error}=await admin.rpc("sac_broker_v03_propose",{
      p_owner:user.id,p_node:action.node,p_run:action.run,p_digest:digest,p_action:action
    });
    if(error)return reply(503,{error:"PROPOSAL_STORE_FAILED"});
    return reply(data?.accepted ? 202:403,data);
  }
  if(typeof body.proposal_id!=="string" ||
     !/^[a-f0-9-]{36}$/.test(body.proposal_id) ||
     !isObj(body.grant) || !ownKeys(body.grant,
     ["schema","owner","node","run","action_digest","proposal_id","nonce","iat","exp"]) ||
     typeof body.grant.iat!=="number" ||typeof body.grant.exp!=="number" ||
     !Number.isSafeInteger(body.grant.iat)|| !Number.isSafeInteger(body.grant.exp)){
    return reply(422,{error:"INVALID_GRANT_SHAPE"});
  }
  const grant=body.grant;
  const now=Math.floor(Date.now()/1000);
  if(grant.schema!==SCHEMA||grant.owner!==user.id||
     grant.node!==action.node||grant.run!==action.run||
     grant.action_digest!==digest||grant.proposal_id!==body.proposal_id||
     typeof grant.nonce!=="string"||!HEX32.test(grant.nonce)||
     grant.exp<=now||grant.iat>now||grant.exp-grant.iat>MAX_TIME||grant.exp-grant.iat<=0)
     return reply(403,{error:"GRANT_SCOPE_OR_TIME_INVALID"});
  if(body.owner_kid!==keys.owner_kid)return reply(403,{error:"OWNER_KEY_MISMATCH"});
  const grantBytes=stable(grant);
  if(!await verifySig(keys.owner_key,body.grant_signature_b64url,SCHEMA+"\n"+grantBytes))
    return reply(403,{error:"INVALID_OWNER_APPROVAL_SIGNATURE"});
  const grantHash=await hashHex(grantBytes+"."+String(body.grant_signature_b64url));
  const receiptHash=await hashHex("SAC-BROKER-RECEIPT-V3\n"+user.id+"\n"+digest+"\n"+grant.nonce);
  const {data,error}=await admin.rpc("sac_broker_v03_execute_canary",{
    p_owner:user.id,p_node:action.node,p_run:action.run,p_digest:digest,
    p_nonce:grant.nonce,p_proposal:body.proposal_id,
    p_canary_tag:(action.parameters as Record<string,unknown>).tag,
    p_grant_sha256:grantHash,p_receipt_sha256:receiptHash
  });
  if(error)return reply(503,{error:"ATOMIC_EXECUTION_STORE_FAILED"});
  return reply(data?.executed ? 200:403,data);
}
Deno.serve((req:Request)=>main(req).catch(()=>reply(500,{error:"BROKER_INTERNAL_ERROR"})));
