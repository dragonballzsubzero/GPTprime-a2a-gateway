import { test } from 'node:test';
import assert from 'node:assert/strict';
const edgePath = new URL('../../supabase/functions/sac-research-harvest-v1/index.js',import.meta.url);
const actorId = '12345678-1234-4234-8234-123456789012';
let edgeHandler;
const preDeno = global.Deno;
global.Deno = {env:{get:key=>({SUPABASE_URL:'https://fixture.supabase.co',SUPABASE_SERVICE_ROLE_KEY:'test-service-value'})[key]},serve:fn=>{edgeHandler=fn}};
await import(edgePath.href);
global.Deno = preDeno;
const oldFetch = global.fetch;
function bearer(aal='aal2') { const body=Buffer.from(JSON.stringify({sub:actorId,aal,exp:9999999999})).toString('base64url');return `Bearer header.${body}.signature`; }
function request(topic='mitochondrial_import',aal='aal2') {return new Request('https://example.org/harvest',{method:'POST',headers:{Authorization:bearer(aal),'Content-Type':'application/json'},body:JSON.stringify({topic})});}
const upstream={resultList:{result:[{source:'MED',id:'31415926',title:'Peer-reviewed mitochondrial import evidence',pubYear:'2025',doi:'10.1000/xyz.abc'}]}};
function mockBackend({claimStatus=201,saveStatus=201,authStatus=200}={}){
 let feedRequests=0,saves=0,claimRequests=0;
 global.fetch = async (url,init={})=>{
  const s=String(url);
  if(s.endsWith('/auth/v1/user')) return new Response(JSON.stringify({id:actorId,email_confirmed_at:'2026-01-01'}),{status:authStatus});
  if(s.includes('sac_console_admins_v1')) return new Response(JSON.stringify([{user_id:actorId,role:'founder',enabled:true}]),{status:200});
  if(s.includes('sac_feed_claims_v1')){claimRequests++;return new Response('',{status:claimStatus});}
  if(s.startsWith('https://www.ebi.ac.uk/europepmc/')){feedRequests++;return new Response(JSON.stringify(upstream),{status:200});}
  if(s.includes('sac_connector_evidence_v1')){saves++;const p=JSON.parse(init.body);assert.equal(p.provenance_status,'quarantined');assert.match(p.payload_sha256,/^[a-f0-9]{64}$/);return new Response('',{status:saveStatus});}
  throw new Error('Unexpected mock URL: '+s);
 };
 return {getCalls:()=>({feedRequests,saves,claimRequests}),restore:()=>{global.fetch=oldFetch}};
}
test('Edge rejects unverified user before any feed access',async()=>{
 const m=mockBackend({authStatus:401});try{const res=await edgeHandler(request());assert.equal(res.status,403);assert.equal(m.getCalls().feedRequests,0);}finally{m.restore()}
});
test('Edge requires AAL2 independently of client UI',async()=>{
 const m=mockBackend();try{const res=await edgeHandler(request('mitochondrial_import','aal1'));assert.equal(res.status,403);assert.equal(m.getCalls().feedRequests,0);}finally{m.restore()}
});
test('Edge claims an hourly topic before requesting public source and rejects duplicates',async()=>{
 const m=mockBackend({claimStatus:409});try{const res=await edgeHandler(request());assert.equal(res.status,429);assert.equal(m.getCalls().feedRequests,0);assert.equal(m.getCalls().claimRequests,1);}finally{m.restore()}
});
test('Edge accepts an allowlisted AAL2 request, fetches a fixed public URL and quarantines only metadata',async()=>{
 const m=mockBackend();try{const res=await edgeHandler(request());const result=await res.json();assert.equal(res.status,200);assert.equal(result.stored,1);assert.equal(result.received,1);assert.equal(result.failed,0);assert.match(result.upstream_response_sha256,/^[a-f0-9]{64}$/);assert.deepEqual(m.getCalls(),{feedRequests:1,saves:1,claimRequests:1});}finally{m.restore()}
});
test('Edge rejects unauthorized topic without external lookups',async()=>{
 const m=mockBackend();try{const res=await edgeHandler(request('https://bad.example'));assert.equal(res.status,422);assert.equal(m.getCalls().feedRequests,0);}finally{m.restore()}
});