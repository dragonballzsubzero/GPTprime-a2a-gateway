import test from 'node:test';
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {mkdtemp,writeFile,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {generateIdentity,createEnvelope,verifyEnvelope,verifyReceipt,sha256} from '../src/transport.mjs';
const worker=new URL('../scripts/demo_worker.mjs',import.meta.url).pathname;
const names=['alpha.node','beta.node','gamma.node'];

test('3 independent Node processes exchange signed probes and verify receipts',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'sac-nodes-'));
 const ids=Object.fromEntries(names.map(n=>[n,generateIdentity()]));
 const children=[];
 try{
   for(const name of names){
     const d=path.join(dir,name);await mkdir(d,{recursive:true});
     await writeFile(path.join(d,'private.pem'),ids[name].private_pem,{mode:0o600});
     await writeFile(path.join(d,'trust.json'),JSON.stringify(Object.fromEntries(names.filter(x=>x!==name).map(x=>[x,ids[x].public_pem]))));
     const child=fork(worker,[],{silent:true,env:{...process.env,SAC_NODE_ID:name,SAC_PRIVATE_KEY_PATH:path.join(d,'private.pem'),SAC_TRUST_STORE_PATH:path.join(d,'trust.json'),SAC_STATE_DIR:path.join(d,'state')}});
     children.push(child);
     const [ready]=await once(child,'message');assert.equal(ready.ready,true);
     child._demoPort=ready.port;
   }
   for(let i=0;i<3;i++){
     const sender=names[i],recipient=names[(i+1)%3],target=children[(i+1)%3];
     const bytes=Buffer.from(`cross-process signed proof ${sender} -> ${recipient}`);
     const env=createEnvelope({sender,recipient,payload:bytes,privatePem:ids[sender].private_pem});
     const url=`http://127.0.0.1:${target._demoPort}/sac/v0.34/dispatch`;
     const reqBody=JSON.stringify(env);
     let res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:reqBody});
     assert.equal(res.status,200);
     const body=await res.json();
     const v=verifyEnvelope(env,{[sender]:ids[sender].public_pem},{recipient});
     assert.equal(verifyReceipt(body.receipt,ids[recipient].public_pem,v.requestHash),true);
     assert.equal(body.receipt.result_sha256,sha256(bytes));
     res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:reqBody});
     assert.equal(res.status,409);
   }
 }finally{
   for(const child of children){if(child.exitCode===null){child.send('stop');await Promise.race([once(child,'exit'),new Promise(resolve=>setTimeout(resolve,3000))]);if(child.exitCode===null)child.kill();}}
   await rm(dir,{recursive:true,force:true});
 }
});