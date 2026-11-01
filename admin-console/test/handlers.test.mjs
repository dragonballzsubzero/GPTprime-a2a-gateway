import assert from 'node:assert/strict';import {test} from 'node:test';
import config from '../api/config.js';import overview from '../api/overview.js';import ingest from '../api/ingest.js';
function res(){return {headers:{},code:200,body:null,setHeader(k,v){this.headers[k]=v},status(c){this.code=c;return this},json(v){this.body=v;return this},send(v){this.body=v;return this}}}
test('config refuses unsupported methods',()=>{const r=res();config({method:'POST'},r);assert.equal(r.code,405)});
test('config returns 503 without backend env',()=>{const r=res();delete process.env.SAC_SUPABASE_URL;delete process.env.SAC_SUPABASE_PUBLISHABLE_KEY;config({method:'GET'},r);assert.equal(r.code,503)});
test('config returns public settings only',()=>{process.env.SAC_SUPABASE_URL='https://lhezpozllgszjbrnpqoi.supabase.co';process.env.SAC_SUPABASE_PUBLISHABLE_KEY='sb_publishable_test';const r=res();config({method:'GET'},r);assert.equal(r.code,200);assert.equal(r.body.publishableKey,'sb_publishable_test');assert.deepEqual(Object.keys(r.body).sort(),['publishableKey','release','url'])});
test('overview refuses unauthenticated calls',async()=>{const r=res();await overview({method:'GET',headers:{}},r);assert.equal(r.code,401)});
test('overview rejects non-GET',async()=>{const r=res();await overview({method:'POST',headers:{}},r);assert.equal(r.code,405)});
test('ingest rejects anonymous and methods',async()=>{let r=res();await ingest({method:'POST',headers:{},body:{}},r);assert.equal(r.code,401);r=res();await ingest({method:'GET',headers:{},body:{}},r);assert.equal(r.code,405)});
test('ingest caps input size before upstream request',async()=>{const r=res();await ingest({method:'POST',headers:{authorization:'Bearer abc.def.ghi'},body:{a:'x'.repeat(70000)}},r);assert.equal(r.code,413)});