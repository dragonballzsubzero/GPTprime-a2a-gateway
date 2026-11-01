import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {TOPICS,MAX_RESULTS,isTopic,queryUrl,normalizeSearch,canonical,recordSigningInput} from '../research/normalize.mjs';
import handler from '../api/harvest.js';
const example={resultList:{result:[
 {source:'MED',id:'31415926',title:'Novel ATP8 import research',doi:'10.1000/abc.1',pubYear:'2025',authorString:'A Researcher',journalTitle:'Journal',citedByCount:'12',isOpenAccess:'Y',pmid:'31415926'},
 {source:'MED',id:'31415926',title:'Novel ATP8 import research'},
 {source:'PPR',id:'PPR12345',title:'Preprint analysis',doi:'javascript:alert(1)'},
 {source:'INJECT',id:'../etc/passwd',title:'Injected result'}
]}};
function res(){return {code:200,headers:{},body:null,setHeader(k,v){this.headers[k]=v},status(n){this.code=n;return this},json(x){this.body=x;return this},send(x){this.body=x;return this}}}
test('only fixed, approved topic identifiers may be searched',()=>{
 assert.equal(Object.keys(TOPICS).length,3);assert.equal(isTopic('endovascular_bci'),true);
 for(const wrong of ['','..','../../secret','ATP6 OR ALL','__proto__',null,42]){assert.equal(isTopic(wrong),false);assert.throws(()=>queryUrl(wrong));}
});
test('Europe PMC endpoint uses fixed HTTPS host, bounded page size and lite metadata',()=>{
 for(const topic of Object.keys(TOPICS)){
  const u=new URL(queryUrl(topic));assert.equal(u.hostname,'www.ebi.ac.uk');assert.equal(u.protocol,'https:');
  assert.equal(u.searchParams.get('resultType'),'lite');assert.equal(u.searchParams.get('pageSize'),String(MAX_RESULTS));
  assert.equal(u.searchParams.get('format'),'json');
 }
});
test('normalization is bounded and discards untrusted source identifiers and duplicate records',()=>{
 const results=normalizeSearch(example);assert.equal(results.length,2);
 assert.equal(results[0].payload.doi,'10.1000/abc.1');assert.equal(results[1].payload.doi,null);
 assert.match(results[0].source_url,/^https:\/\/europepmc\.org\/article\/MED\//);
 assert.equal(results[0].payload.abstractText,undefined);
});
test('malformed metadata and excessive upstream result count are rejected',()=>{
 for(const x of [null,{}, {errCode:'SYSTEM'}, {resultList:{result:'wrong'}},{resultList:{result:Array.from({length:101},()=>({}))}}])assert.throws(()=>normalizeSearch(x));
});
test('records are canonical with stable payload digests across JSON key order',()=>{
 const x=normalizeSearch(example)[0], y=JSON.parse(JSON.stringify(x));y.payload={...Object.fromEntries(Object.entries(y.payload).reverse())};
 assert.equal(recordSigningInput(x),recordSigningInput(y));
 assert.equal(createHash('sha256').update(recordSigningInput(x)).digest('hex').length,64);
 assert.deepEqual(canonical({z:2,a:{c:3,b:4}}),{a:{b:4,c:3},z:2});
});
test('research proxy refuses anonymous and unsupported HTTP methods',async()=>{
 let r=res();await handler({method:'GET',headers:{},body:{}},r);assert.equal(r.code,405);
 r=res();await handler({method:'POST',headers:{},body:{topic:'endovascular_bci'}},r);assert.equal(r.code,401);
});
test('research proxy rejects request-shape injection before any upstream call',async()=>{
 const r=res();await handler({method:'POST',headers:{authorization:'Bearer a.b.c'},body:{topic:'endovascular_bci',url:'https://evil.invalid'}},r);assert.equal(r.code,422);
});
test('research proxy fails closed if backend is unavailable',async()=>{
 const prior=[process.env.SAC_SUPABASE_URL,process.env.SAC_SUPABASE_PUBLISHABLE_KEY];
 delete process.env.SAC_SUPABASE_URL;delete process.env.SAC_SUPABASE_PUBLISHABLE_KEY;
 try{const r=res();await handler({method:'POST',headers:{authorization:'Bearer a.b.c'},body:{topic:'mitochondrial_import'}},r);assert.equal(r.code,503);}finally{[process.env.SAC_SUPABASE_URL,process.env.SAC_SUPABASE_PUBLISHABLE_KEY]=prior;}
});