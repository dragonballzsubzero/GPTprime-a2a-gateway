// SAC Mainframe administrative status + research-evidence ingress, v1.0.
// Supabase edge built-in secrets only. All privileged data access requires verified
// Supabase Auth user + explicit enabled allowlist. No secrets sent to client.
const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const originUrl = Deno.env.get('SUPABASE_URL')?.replace(/\/$/, '');
const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
const allowedRecordTypes = new Set(['paper','technical_reference','provider_status','operational_observation','research_note']);
const forbiddenKey = /^(?:password|passphrase|api_?key|private_?key|secret|access_?token|refresh_?token|authorization|client_?secret|cookie|session_?token)$/i;
const json = (obj: unknown, status=200) => new Response(JSON.stringify(obj),{status,headers:JSON_HEADERS});
const fail = (status:number, code:string) => json({ok:false,error:code},status);
const clientHeaders = () => ({'apikey': serviceKey!, 'Authorization': `Bearer ${serviceKey!}`, 'Accept':'application/json'});

async function api(path:string, opts:RequestInit={}) {
  const r=await fetch(`${originUrl}${path}`, { ...opts, headers:{...clientHeaders(),...(opts.headers||{})}, signal:AbortSignal.timeout(9000)});
  if(!r.ok) throw new Error(`BACKEND_HTTP_${r.status}`);
  return r;
}
async function rows(table:string, params:Record<string,string>,limit=30) {
  const query=new URLSearchParams({...params,limit:String(limit)});
  const r=await api(`/rest/v1/${table}?${query.toString()}`);
  return await r.json();
}
async function count(table:string) {
  const r=await api(`/rest/v1/${table}?select=*`,{method:'HEAD',headers:{'Prefer':'count=exact'}});
  const cr=r.headers.get('content-range')||'';
  const n=Number(cr.split('/')[1]);
  return Number.isFinite(n)?n:null;
}
function canonical(value:unknown):unknown {
  if(Array.isArray(value)) return value.map(canonical);
  if(value!==null && typeof value==='object') return Object.fromEntries(Object.keys(value as Record<string,unknown>).sort().map(k=>[k,canonical((value as Record<string,unknown>)[k])]));
  return value;
}
function hasSecretFields(value:unknown,depth=0):boolean {
  if(depth>18)return true;
  if(Array.isArray(value))return value.some(v=>hasSecretFields(v,depth+1));
  if(value!==null && typeof value==='object')return Object.entries(value).some(([k,v])=>forbiddenKey.test(k)||hasSecretFields(v,depth+1));
  return false;
}
function decodeJwtBody(token:string):Record<string,unknown> {
  try{const encoded=token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');return JSON.parse(atob(encoded));}catch{return {};}
}
async function authenticated(req:Request): Promise<{id:string;role:string;aal:string}|null> {
  const bearer=req.headers.get('authorization')||'';
  if(!bearer.startsWith('Bearer ')||!originUrl||!serviceKey)return null;
  const token=bearer.slice(7);
  if(token.length<24||token.length>12000)return null;
  const u=await fetch(`${originUrl}/auth/v1/user`,{
    headers:{'apikey':serviceKey,'Authorization':`Bearer ${token}`},signal:AbortSignal.timeout(9000)});
  if(!u.ok)return null;
  const user=await u.json();
  if(!/^[a-f0-9-]{36}$/i.test(user?.id||'')||!user?.email_confirmed_at)return null;
  const allow=await rows('sac_console_admins_v1',{select:'user_id,role,enabled',user_id:`eq.${user.id}`},1);
  if(!allow[0]?.enabled)return null;
  return {id:user.id,role:allow[0].role,aal:String(decodeJwtBody(token).aal||'aal1')};
}

async function overview() {
  const [candidateList, findings, readiness, connectors, latest, recentEvidence, counts]=await Promise.all([
    rows('sac_runtime_candidates',{select:'candidate_name,provider_family,integration_state,blocker_codes,last_verified_at',order:'candidate_name.asc'},30),
    rows('sac_mainframe_findings_v1',{select:'code,severity,status,title,last_seen_at',order:'code.asc'},30),
    rows('sac_readiness_snapshots',{select:'stage,status,created_at',order:'created_at.desc'},1),
    rows('sac_connector_registry_v1',{select:'connector_id,display_name,purpose,access_surface,state,adapter_class,last_verified_at,evidence',order:'display_name.asc'},40),
    rows('sac_mainframe_telemetry_v1',{select:'sampled_at,metrics',order:'sampled_at.desc'},1),
    rows('sac_connector_evidence_v1',{select:'evidence_id,connector_id,record_type,source_url,received_at,provenance_status,payload_sha256',order:'received_at.desc'},12),
    Promise.all([count('oa_agent_nodes'),count('oa_capability_proofs'),count('oa_execution_contracts'),count('oa_execution_results'),count('sac_transport_receipts_v034'),count('sac_connector_evidence_v1')])
  ]);
  const m=latest[0]?.metrics||{};
  return {
    ok:true,release:'SAC Admin Console v1.0',as_of:new Date().toISOString(),
    counts:{enrolled_nodes:counts[0],capability_proofs:counts[1],execution_contracts:counts[2],execution_results:counts[3],transport_receipts:counts[4],ingested_research_records:counts[5]},
    telemetry:{sampled_at:latest[0]?.sampled_at||null,runner_enabled:m.runtime?.runner_enabled??null,runner_execution_proven:m.runtime?.runner_execution_proven??null,runner_state:m.runtime?.runner_latest_tick_state??null,queue_paused:m.runtime?.queue_paused??null,production_qualified:m.federation?.production_qualified??null,qualified_providers:m.federation?.qualified_providers??null,active_jobs:m.scheduler?.active_jobs??null},
    candidates:candidateList,findings,readiness:readiness[0]||null,connectors,recent_evidence:recentEvidence,
    evidence_scope:'Database-backed observations and admin metadata; not independent external provider attestation.'
  };
}
async function ingest(req:Request, actor:{id:string;role:string;aal:string}) {
  if(!['founder','admin'].includes(actor.role)||actor.aal!=='aal2')return fail(403,'MFA_AAL2_REQUIRED');
  if(!req.headers.get('content-type')?.toLowerCase().startsWith('application/json'))return fail(415,'JSON_REQUIRED');
  const input=await req.text();
  if(new TextEncoder().encode(input).length>65536)return fail(413,'PAYLOAD_TOO_LARGE');
  let v:Record<string,any>;
  try{v=JSON.parse(input);}catch{return fail(400,'INVALID_JSON');}
  if(!v||typeof v!=='object'||Array.isArray(v))return fail(422,'OBJECT_REQUIRED');
  const id=v.connector_id, type=v.record_type, observed=v.observed_at, url=v.source_url||null, payload=v.payload;
  if(typeof id!=='string'||!/^[-a-z0-9_]{2,64}$/.test(id)||!allowedRecordTypes.has(type))return fail(422,'INVALID_SOURCE_TYPE');
  if(!observed||typeof observed!=='string'||!Number.isFinite(Date.parse(observed))||Date.parse(observed)>Date.now()+86400000)return fail(422,'INVALID_OBSERVATION_DATE');
  if(url!==null&&(typeof url!=='string'||url.length>1800||!/^https:\/\//.test(url)))return fail(422,'INVALID_SOURCE_URL');
  if(!payload||typeof payload!=='object'||Array.isArray(payload)||hasSecretFields(payload))return fail(422,'UNSAFE_OR_INVALID_PAYLOAD');
  const source=await rows('sac_connector_registry_v1',{select:'connector_id',connector_id:`eq.${id}`},1);
  if(!source.length)return fail(404,'UNKNOWN_CONNECTOR');
  const serialized=JSON.stringify(canonical({connector_id:id,record_type:type,observed_at:observed,source_url:url,payload}));
  const hashBuffer=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(serialized));
  const digest=Array.from(new Uint8Array(hashBuffer)).map(x=>x.toString(16).padStart(2,'0')).join('');
  const row={connector_id:id,record_type:type,source_url:url,observed_at:observed,payload,payload_sha256:digest,provenance_status:'quarantined',created_by:actor.id};
  const result=await fetch(`${originUrl}/rest/v1/sac_connector_evidence_v1?select=evidence_id,provenance_status,payload_sha256`,{
    method:'POST',headers:{...clientHeaders(),'Content-Type':'application/json','Prefer':'return=representation'},body:JSON.stringify(row),signal:AbortSignal.timeout(9000)});
  if(result.status===409)return fail(409,'DUPLICATE_EVIDENCE');
  if(!result.ok)throw new Error(`INGEST_HTTP_${result.status}`);
  const rows=await result.json();
  return json({ok:true,...rows[0],verification_note:'Quarantined; independent provenance review required.'},201);
}
Deno.serve(async (req:Request) => {
 try {
   if(!['GET','POST'].includes(req.method))return fail(405,'METHOD_NOT_ALLOWED');
   const user=await authenticated(req);
   if(!user)return fail(403,'ACCESS_DENIED');
   if(req.method==='GET')return json({...await overview(),privilege:{role:user.role,aal:user.aal}});
   return ingest(req,user);
 } catch(e) {
   console.error('sac-admin-bridge request failure',e instanceof Error?e.message:'unknown');
   return fail(503,'UPSTREAM_UNAVAILABLE');
 }
});