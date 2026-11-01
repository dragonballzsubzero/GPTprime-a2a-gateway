import { isTopic, queryUrl, normalizeSearch, recordSigningInput, canonical } from './normalize.mjs';

// SAC v1.2 public research adapter: allowlisted topics, verified user + AAL2,
// bounded metadata-only HTTPS retrieval, atomic per-user/topic/hour claim,
// server-side digest + quarantine. Not clinical or inference proof.
const origin = Deno.env.get('SUPABASE_URL')?.replace(/\/$/,'');
const secret = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
const baseHeaders = {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const respond=(status,body)=>new Response(JSON.stringify(body),{status,headers:baseHeaders});
const encode=async (s)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(b=>b.toString(16).padStart(2,'0')).join('');
const serviceHeaders=()=>({'apikey':secret,'Authorization':`Bearer ${secret}`,'Content-Type':'application/json'});
async function rest(resource,init={}) {
 const res=await fetch(`${origin}/rest/v1/${resource}`,{...init,headers:{...serviceHeaders(),...(init.headers||{})},signal:AbortSignal.timeout(7500)});
 return res;
}
async function authorize(req){
 if(!origin||!secret)return null;
 const auth=req.headers.get('authorization')||'';
 if(!/^Bearer [A-Za-z0-9_.-]+$/.test(auth)||auth.length>13000)return null;
 const token=auth.slice(7);
 const r=await fetch(`${origin}/auth/v1/user`,{headers:{apikey:secret,Authorization:`Bearer ${token}`},signal:AbortSignal.timeout(7000)});
 if(!r.ok)return null;
 const u=await r.json();
 if(!/^[a-f\d-]{36}$/i.test(u?.id||'')||!u.email_confirmed_at)return null;
 let jwt={};try{jwt=JSON.parse(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));}catch{return null;}
 if(jwt.sub!==u.id || jwt.aal!=='aal2')return null;
 const q=new URLSearchParams({select:'user_id,role,enabled',user_id:`eq.${u.id}`,limit:'1'});
 const check=await rest(`sac_console_admins_v1?${q}`);
 if(!check.ok)return null;
 const [p]=await check.json();
 return p?.enabled&&['founder','admin'].includes(p.role) ? {id:u.id,role:p.role} : null;
}
async function main(req){
 if(req.method!=='POST')return respond(405,{error:'METHOD_NOT_ALLOWED'});
 if(!req.headers.get('content-type')?.startsWith('application/json'))return respond(415,{error:'JSON_REQUIRED'});
 if(Number(req.headers.get('content-length')||0)>512)return respond(413,{error:'INPUT_TOO_LARGE'});
 const actor=await authorize(req);
 if(!actor)return respond(403,{error:'AUTH_AND_MFA_AAL2_REQUIRED'});
 const raw=await req.text();if(raw.length>512)return respond(413,{error:'INPUT_TOO_LARGE'});
 let body;try{body=JSON.parse(raw);}catch{return respond(400,{error:'INVALID_JSON'});}
 if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==1||!isTopic(body.topic))return respond(422,{error:'INVALID_TOPIC'});
 const hour=new Date(Math.floor(Date.now()/3600000)*3600000).toISOString();
 const claim=await rest('sac_feed_claims_v1',{method:'POST',headers:{'Prefer':'return=minimal'},body:JSON.stringify({actor_id:actor.id,topic:body.topic,hour_bucket:hour})});
 if(claim.status===409)return respond(429,{error:'HOURLY_TOPIC_LIMIT',retry_after:hour});
 if(!claim.ok)throw new Error('CLAIM_FAILED');
 const source=await fetch(queryUrl(body.topic),{method:'GET',headers:{Accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(11000)});
 if(!source.ok)return respond(502,{error:'SOURCE_HTTP_ERROR',upstream_status:source.status});
 const wire=await source.text();if(new TextEncoder().encode(wire).length>200000)return respond(502,{error:'SOURCE_PAYLOAD_TOO_LARGE'});
 let parsed;try{parsed=JSON.parse(wire);}catch{return respond(502,{error:'SOURCE_INVALID_JSON'});}
 let records;try{records=normalizeSearch(parsed);}catch{return respond(502,{error:'SOURCE_SCHEMA_INVALID'});}
 const retrievalHash=await encode(wire);let stored=0,duplicates=0,failed=0;
 for(const record of records){
  const digest=await encode(recordSigningInput(record));
  const row={connector_id:'europepmc',record_type:'paper',source_url:record.source_url,
   observed_at:new Date().toISOString(),payload:record.payload,payload_sha256:digest,provenance_status:'quarantined',created_by:actor.id};
  const r=await rest('sac_connector_evidence_v1',{method:'POST',headers:{Prefer:'return=minimal'},body:JSON.stringify(row)});
  if(r.status===409)duplicates++; else if(r.ok)stored++;else failed++;
 }
 return respond(failed?207:200,{ok:failed===0,topic:body.topic,upstream:'Europe PMC public REST search',
   upstream_response_sha256:retrievalHash,received:records.length,stored,duplicates,failed,
   assurance:'quarantined indexed metadata; source response hash is not a provider signature or a biological proof'});
}
Deno.serve(async req=>{try{return await main(req);}catch(e){console.error('SAC public research harvest:',e instanceof Error?e.message:'unknown');return respond(503,{error:'RESEARCH_ADAPTER_UNAVAILABLE'});}});