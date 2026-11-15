import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm,chmod,symlink,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createSupabaseAdapters,createHttpsAuditClient} from '../broker-v04/adapters.mjs';
import {createBroker,verifyAuditAck,NODE_DOMAIN,GRANT_DOMAIN} from '../broker-v04/core.mjs';
import {canonical,digest} from '../broker-v03/client.mjs';
import {createBrokerHttpServer} from '../broker-v04/http.mjs';
import {readPrivateFile} from '../broker-v04/secrets.mjs';

const base='https://example.supabase.co',sub='00000000-0000-4000-8000-000000000001',now=1800000000;
const token=(claims)=>[Buffer.from('{}').toString('base64url'),Buffer.from(JSON.stringify(claims)).toString('base64url'),'sig'].join('.');
const sessionId='00000000-0000-4000-8000-000000000007';
const claims={iss:base+'/auth/v1',aal:'aal2',sub,session_id:sessionId,iat:now-1,exp:now+60};
function response(obj,status=200){return new Response(JSON.stringify(obj),{status,headers:{'content-type':'application/json'}});}

test('Supabase adapter binds verified subject and AAL2 to caller; fake network only',async()=>{
  const calls=[];
  const fetchImpl=async(url,options)=>{calls.push({url,options});return url.endsWith('/auth/v1/user')?
    response({id:sub}):response({schema:'gptprime.owner-session-gate.v1',allowed:true,code:'OWNER_SESSION_VERIFIED'});};
  const x=createSupabaseAdapters({origin:base,anonKey:'anon-test',serviceKey:'service-test',fetchImpl,clock:()=>now});
  assert.deepEqual(await x.auth.authenticate(token(claims)),{owner_id:sub,aal:'aal2'});
  assert.equal(calls[0].url,base+'/auth/v1/user');assert.equal(calls[0].options.headers.apikey,'anon-test');
  assert.equal(calls[1].url,base+'/rest/v1/rpc/gptprime_v19_owner_session_gate_v1');
  assert.equal(JSON.parse(calls[1].options.body).p_session_id,sessionId);
  for(const bad of [{...claims,aal:'aal1'},{...claims,iss:'https://else.invalid/auth/v1'},{...claims,exp:now},
                    {...claims,session_id:'bad'},{...claims,iat:now-901}])
    await assert.rejects(x.auth.authenticate(token(bad)),e=>e.code==='AUTH_SESSION_DENIED');
  assert.equal(calls.length,2);
});
test('session gate denial, outage and malformed response fail closed',async()=>{
  for(const [mode,expected] of [['revoked','AUTH_SESSION_DENIED'],['offline','AUTH_SESSION_GATE_UNAVAILABLE'],
                                ['malformed','AUTH_SESSION_GATE_UNAVAILABLE'],['false-positive','AUTH_SESSION_GATE_UNAVAILABLE']]){
    const fetchImpl=async url=>{
      if(url.endsWith('/auth/v1/user'))return response({id:sub});
      if(mode==='offline')throw Error('network');
      if(mode==='revoked')return response({schema:'gptprime.owner-session-gate.v1',allowed:false,code:'SESSION_MISSING_REVOKED_OR_NOT_AAL2'});
      if(mode==='false-positive')return response({schema:'gptprime.owner-session-gate.v1',allowed:true,code:'UNEXPECTED'});
      return response(null);
    };
    const x=createSupabaseAdapters({origin:base,anonKey:'a',serviceKey:'s',fetchImpl,clock:()=>now});
    await assert.rejects(x.auth.authenticate(token(claims)),e=>e.code===expected);
  }
});
test('Supabase adapter rejects different user returned by authenticated service',async()=>{
  const x=createSupabaseAdapters({origin:base,anonKey:'a',serviceKey:'s',fetchImpl:async()=>response({id:'00000000-0000-4000-8000-000000000099'}),clock:()=>now});
  await assert.rejects(x.auth.authenticate(token(claims)),e=>e.code==='AUTH_SESSION_DENIED');
});
test('Auth denial stays distinct from rate limits, service failure and malformed success',async()=>{
  for(const [mode,expected] of [['denied','AUTH_SESSION_DENIED'],['rate','AUTH_SERVICE_UNAVAILABLE'],
                                 ['offline','AUTH_SERVICE_UNAVAILABLE'],['malformed','AUTH_SERVICE_UNAVAILABLE']]){
    const fetchImpl=async()=>{if(mode==='offline')throw Error('network');
      if(mode==='denied')return response({},401);if(mode==='rate')return response({},429);
      return new Response('null',{status:200,headers:{'content-type':'application/json'}});};
    const x=createSupabaseAdapters({origin:base,anonKey:'a',serviceKey:'s',fetchImpl,clock:()=>now});
    await assert.rejects(x.auth.authenticate(token(claims)),e=>e.code===expected);
  }
});
test('v0.4 RPC receives expiry, key IDs and signed audit hashes; never falls back to v0.3 execution',async()=>{
  const calls=[];
  const x=createSupabaseAdapters({origin:base,anonKey:'anon-test',serviceKey:'service-test',fetchImpl:async(url,opt)=>{calls.push({url,body:JSON.parse(opt.body)});return response({executed:false,reason:'GRANT_REPLAY'});}});
  const p={owner_id:sub,action:{node:'node-1',run:'r',parameters:{tag:'t'}},action_digest:'a'.repeat(64),nonce:'b'.repeat(32),
    proposal_id:sub,grant_iat:now,grant_exp:now+20,owner_kid:'ok',node_kid:'nk',grant_sha256:'c'.repeat(64),
    audit_intent_sha256:'d'.repeat(64),audit_ack_sha256:'e'.repeat(64)};
  await x.store.executeCanary(p);
  assert.equal(calls.length,1);assert.equal(calls[0].url,base+'/rest/v1/rpc/sac_broker_v04_execute_canary');
  assert.equal(calls[0].body.p_grant_exp,now+20);assert.equal(calls[0].body.p_owner_kid,'ok');
  assert.equal(calls[0].body.p_audit_ack_sha256,'e'.repeat(64));
});
test('audit and database adapters refuse non-HTTPS configured origins',()=>{
  assert.throws(()=>createHttpsAuditClient({origin:'http://example.test',secretProvider:()=>''}),/HTTPS_BASE/);
  assert.throws(()=>createSupabaseAdapters({origin:'http://example.test',anonKey:'x',serviceKey:'y'}),/HTTPS_BASE/);
});
test('HTTPS audit adapter sends bounded exact event to its separate endpoint',async()=>{
  let sent;
  const audit=createHttpsAuditClient({origin:'https://audit.example.test',secretProvider:async()=>('t'.repeat(40)),
    fetchImpl:async(url,opt)=>{sent={url,opt};return response({ok:true});}});
  assert.deepEqual(await audit.append({type:'intent'}),{ok:true});
  assert.equal(sent.url,'https://audit.example.test/append');assert.equal(sent.opt.redirect,'error');
  assert.equal(sent.opt.headers.authorization,'Bearer '+'t'.repeat(40));
});
test('private credential reader rejects public mode, symlinks and hardlinks',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'sac-secrets-'));
  try{
    const file=path.join(dir,'secret');await writeFile(file,'fixture',{mode:0o600});
    assert.equal(await readPrivateFile(file),'fixture');
    await chmod(file,0o644);await assert.rejects(readPrivateFile(file),/PRIVATE_FILE_UNSAFE/);
    await chmod(file,0o600);const sym=path.join(dir,'sym');await symlink(file,sym);
    await assert.rejects(readPrivateFile(sym));
    const hard=path.join(dir,'hard');await link(file,hard);await assert.rejects(readPrivateFile(file),/PRIVATE_FILE_UNSAFE/);
  }finally{await rm(dir,{recursive:true,force:true});}
});

async function unusedPort(){
  const s=net.createServer();await new Promise(resolve=>s.listen(0,'127.0.0.1',resolve));
  const port=s.address().port;await new Promise(resolve=>s.close(resolve));return port;
}
async function startAudit(env){
  const child=spawn(process.execPath,['broker-v04/audit-main.mjs'],{env,stdio:['ignore','pipe','pipe']});
  let stderr='';child.stderr.on('data',v=>{stderr+=v.toString();});
  const timeout=setTimeout(()=>child.kill('SIGKILL'),5000);
  try{
    const [chunk]=await Promise.race([once(child.stdout,'data'),once(child,'exit').then(()=>{throw Error('audit failed: '+stderr);})]);
    assert.equal(JSON.parse(chunk.toString()).service,'sac-audit-v04');return child;
  }finally{clearTimeout(timeout);}
}
async function stop(child){
  child.kill('SIGTERM');
  const timer=setTimeout(()=>child.kill('SIGKILL'),3000);
  try{await once(child,'exit');}finally{clearTimeout(timer);}
}
test('separate local audit process durably signs and deduplicates events after restart',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'sac-audit-process-'));
  const keys=generateKeyPairSync('ed25519'),secret=randomBytes(32).toString('hex');
  const keyPath=path.join(dir,'key.pem'),tokenPath=path.join(dir,'token');
  const ledgerDir=path.join(dir,'ledger');await mkdir(ledgerDir,{mode:0o700});
  await writeFile(keyPath,keys.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  await writeFile(tokenPath,secret,{mode:0o600});
  const port=await unusedPort();
  const env={...process.env,SAC_AUDIT_DIR:ledgerDir,SAC_AUDIT_SINK_ID:'local-auditor',
    SAC_AUDIT_PRIVATE_KEY_PATH:keyPath,SAC_AUDIT_TOKEN_PATH:tokenPath,SAC_AUDIT_PORT:String(port)};
  const event={schema:'sac.audit.event.v1',type:'intent',owner_id:sub,node:'adapter.one',run:'r1',
    proposal_id:'00000000-0000-4000-8000-000000000002',action_digest:'a'.repeat(64),grant_sha256:'b'.repeat(64),
    nonce:'c'.repeat(32),audience:'sac://broker/staging/v04',environment:'staging'};
  let child;
  try{
    child=await startAudit(env);
    const url=`http://127.0.0.1:${port}/append`;
    let res=await fetch(url,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer bad'},body:JSON.stringify(event)});
    assert.equal(res.status,401);
    res=await fetch(url,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+secret},body:JSON.stringify(event)});
    assert.equal(res.status,200);const ack=await res.json();
    assert.equal(verifyAuditAck(event,ack,{id:'local-auditor',public_jwk:keys.publicKey.export({format:'jwk'})}),true);
    await stop(child);child=null;
    child=await startAudit(env);
    res=await fetch(url,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+secret},body:JSON.stringify(event)});
    assert.deepEqual(await res.json(),ack);
    await stop(child);child=null;
    assert.equal((await readFile(path.join(ledgerDir,'audit.jsonl'),'utf8')).trim().split('\n').length,1);
  }finally{if(child)await stop(child);await rm(dir,{recursive:true,force:true});}
});

test('local HTTP broker sends signed intent and result to a separate audit process; store is a fixture',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'sac-broker-e2e-'));
  const sink=generateKeyPairSync('ed25519'),owner=generateKeyPairSync('ed25519'),node=generateKeyPairSync('ed25519');
  const secret=randomBytes(32).toString('hex'),tokenValue='t'.repeat(40);
  const keyPath=path.join(dir,'key.pem'),tokenPath=path.join(dir,'token'),ledgerDir=path.join(dir,'ledger');
  await mkdir(ledgerDir,{mode:0o700});
  await writeFile(keyPath,sink.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  await writeFile(tokenPath,secret,{mode:0o600});
  const port=await unusedPort(),env={...process.env,SAC_AUDIT_DIR:ledgerDir,SAC_AUDIT_SINK_ID:'local-sink',
    SAC_AUDIT_PRIVATE_KEY_PATH:keyPath,SAC_AUDIT_TOKEN_PATH:tokenPath,SAC_AUDIT_PORT:String(port)};
  let child,server;
  try{
    child=await startAudit(env);let executions=0;const spent=new Set();
    const action={node:'adapter.one',run:'r1',operation:'audit_canary',resource:'sac://broker/canary',parameters:{tag:'safe'}};
    const proposalId='00000000-0000-4000-8000-000000000002';
    const baseProposal={action,node_kid:'node1',node_signature_b64url:sign(null,Buffer.from(NODE_DOMAIN+canonical(action)),node.privateKey).toString('base64url')};
    const grant={schema:'sac.exact-action.v4',owner:sub,node:action.node,run:action.run,action_digest:digest(action),
      proposal_id:proposalId,nonce:'1'.repeat(32),iat:now,exp:now+30,audience:'sac://broker/staging/v04',
      environment:'staging',owner_kid:'owner1',node_kid:'node1'};
    const request={...baseProposal,proposal_id:proposalId,grant,owner_kid:'owner1',
      grant_signature_b64url:sign(null,Buffer.from(GRANT_DOMAIN+canonical(grant)),owner.privateKey).toString('base64url')};
    const audit={append:async event=>{
      const r=await fetch(`http://127.0.0.1:${port}/append`,{method:'POST',
        headers:{'content-type':'application/json',authorization:'Bearer '+secret},body:JSON.stringify(event)});
      if(!r.ok)throw Error('test sink unavailable');return r.json();
    }};
    const broker=createBroker({auth:{authenticate:async()=>({owner_id:sub,aal:'aal2'})},
      keys:{resolve:async()=>({allowed:true,node_kid:'node1',node_key:node.publicKey.export({format:'jwk'}),
        owner_kid:'owner1',owner_key:owner.publicKey.export({format:'jwk'})})},
      store:{propose:async({action_digest})=>({accepted:true,proposal_id:proposalId,action_digest}),
        executeCanary:async p=>{if(spent.has(p.nonce))return {executed:false,reason:'GRANT_REPLAY'};
          spent.add(p.nonce);executions++;return {executed:true,execution_id:'00000000-0000-4000-8000-000000000003',effect_sha256:'b'.repeat(64)};}},
      audit,trustedAudit:{id:'local-sink',public_jwk:sink.publicKey.export({format:'jwk'})},
      audience:'sac://broker/staging/v04',environment:'staging',clock:()=>now+1});
    server=createBrokerHttpServer(broker);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const url=`http://127.0.0.1:${server.address().port}`;
    const post=(route,obj)=>fetch(url+route,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+tokenValue},body:JSON.stringify(obj)});
    let response=await post('/propose',baseProposal);assert.equal(response.status,202);
    const outcomes=await Promise.all(Array.from({length:12},()=>post('/execute',request)));
    assert.equal(outcomes.filter(r=>r.status===200).length,1);
    assert.equal(outcomes.filter(r=>r.status===403).length,11);
    assert.equal(executions,1);
    await new Promise(resolve=>server.close(resolve));server=null;
    await stop(child);child=null;
    const records=(await readFile(path.join(ledgerDir,'audit.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
    assert.deepEqual(records.map(r=>r.event.type),['intent','result']);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));if(child)await stop(child);await rm(dir,{recursive:true,force:true});}
});
