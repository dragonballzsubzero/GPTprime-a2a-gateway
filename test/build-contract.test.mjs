import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
test('Vercel manifest disables incompatible Express preset',async()=>{
 const v=JSON.parse(await readFile(new URL('vercel.json',root),'utf8'));
 assert.equal(v.framework,null);
 assert.equal(v.functions['api/*.js'].maxDuration,10);
});
test('Serverless gateways are explicit modules, not magic HTTP server detection',async()=>{
 const endpoints=['health','ready','dispatch'];
 for(const n of endpoints){let s=await readFile(new URL(`api/${n}.js`,root),'utf8');assert.match(s,/export default/);assert.doesNotMatch(s,/createServer\(|listen\(|express\(/)}
});