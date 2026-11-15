import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {canonical,digest} from '../broker-v03/client.mjs';
import {createBroker,verifyAuditAck,verifyAuditHead,eventDigest,sha256,NODE_DOMAIN,GRANT_DOMAIN} from '../broker-v04/core.mjs';
import {createBrokerHttpServer} from '../broker-v04/http.mjs';
import {openAuditLedger} from '../broker-v04/audit-ledger.mjs';
import {reconcile,recoverAuditResult} from '../broker-v04/reconcile.mjs';
import {validateApprovalRequest,signOwnerGrant} from '../broker-v04/owner-approve.mjs';
import {signProposal} from '../broker-v04/proposal-client.mjs';
import {observeExecution} from '../broker-v04/observer.mjs';

const ownerId='00000000-0000-4000-8000-000000000001';
const proposalId='00000000-0000-4000-8000-000000000002';
const executionId='00000000-0000-4000-8000-000000000003';
const audience='sac://broker/staging/v04',environment='staging';
const bearer='f'.repeat(40),N=1800000000;
const jwk=k=>k.publicKey.export({format:'jwk'});
const signBody=(key,domain,obj)=>sign(null,Buffer.from(domain+canonical(obj)),key.privateKey).toString('base64url');
function fixture(){
  const owner=generateKeyPairSync('ed25519'),node=generateKeyPairSync('ed25519'),auditor=generateKeyPairSync('ed25519');
  const action={node:'independent.adapter-01',run:'test-run',operation:'audit_canary',
                resource:'sac://broker/canary',parameters:{tag:'ONLY_CANARY'}};
  const nodeSignature=signBody(node,NODE_DOMAIN,action);
  const proposal={action,node_kid:'node-key-1',node_signature_b64url:nodeSignature};
  const grant={schema:'sac.exact-action.v4',owner:ownerId,node:action.node,run:action.run,
    action_digest:digest(action),proposal_id:proposalId,nonce:'1'.repeat(32),iat:N,exp:N+60,
    audience,environment,owner_kid:'owner-key-1',node_kid:'node-key-1'};
  const request={...proposal,proposal_id:proposalId,grant,owner_kid:'owner-key-1',
    grant_signature_b64url:signBody(owner,GRANT_DOMAIN,grant)};
  const calls={executions:0,events:[],acks:[],spent:new Set()};
  let now=N+1;
  const deps={auth:{authenticate:async t=>t===bearer?{owner_id:ownerId,aal:'aal2'}:null},
    keys:{resolve:async()=>({allowed:true,node_kid:'node-key-1',node_key:jwk(node),
                             owner_kid:'owner-key-1',owner_key:jwk(owner)})},
    store:{
      propose:async({action_digest})=>({accepted:true,proposal_id:proposalId,action_digest}),
      executeCanary:async p=>{
        if(calls.spent.has(p.nonce))return {executed:false,reason:'GRANT_REPLAY'};
        calls.spent.add(p.nonce); calls.executions++;
        return {executed:true,execution_id:executionId,effect_sha256:'a'.repeat(64)};
      }
    },
    audit:{append:async event=>{
      calls.events.push(event);
      const ack={schema:'sac.audit.ack.v1',sink_id:'independent-audit',event_sha256:eventDigest(event),
                 event_type:event.type,accepted_at:now};
      const envelope={ack,signature_b64url:signBody(auditor,'sac.audit.ack.v1\n',ack)};
      calls.acks.push(envelope);return envelope;
    }},
    trustedAudit:{id:'independent-audit',public_jwk:jwk(auditor)},audience,environment,clock:()=>now};
  return {owner,node,auditor,action,proposal,grant,request,calls,deps,setNow:n=>{now=n;}};
}
const errorCode=code=>e=>{assert.equal(e.code,code);return true;};

test('accepts independent enrolled adapter proposal and exact approved canary',async()=>{
  const f=fixture(),b=createBroker(f.deps);
  assert.equal((await b.propose(bearer,f.proposal)).status,'PROPOSED');
  const result=await b.execute(bearer,f.request);
  assert.equal(result.status,'EXECUTED_AUDIT_RECORDED');
  assert.equal(result.audit_status,'INDEPENDENT_LOG_RECORDED_NOT_RECONCILED');
  assert.equal(f.calls.executions,1);
  assert.deepEqual(f.calls.events.map(e=>e.type),['intent','result']);
});
test('host-owned signer signs and verifies the model-proposed action',async()=>{
  const f=fixture();
  const signed=await signProposal({action:f.action,node_kid:'node-key-1',node_public_jwk:jwk(f.node),
                                  signer:async message=>sign(null,message,f.node.privateKey)});
  assert.equal((await createBroker(f.deps).propose(bearer,signed)).status,'PROPOSED');
  await assert.rejects(signProposal({action:f.action,node_kid:'node-key-1',node_public_jwk:jwk(f.node),
                                    signer:async message=>sign(null,message,f.owner.privateKey)}),/NODE_SIGNER_KEY_MISMATCH/);
});
test('requires authenticated AAL2 owner context',async()=>{
  const f=fixture();f.deps.auth.authenticate=async()=>({owner_id:ownerId,aal:'aal1'});
  await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('AUTH_SESSION_DENIED'));
  assert.equal(f.calls.executions,0);
});
test('unknown effects and nodes denied by effect schema and live trust adapter',async()=>{
  const f=fixture(),b=createBroker(f.deps);
  await assert.rejects(b.propose(bearer,{...f.proposal,action:{...f.action,operation:'shell_exec'}}),errorCode('EFFECT_NOT_ALLOWLISTED'));
  f.deps.keys.resolve=async()=>({allowed:false});
  await assert.rejects(createBroker(f.deps).propose(bearer,f.proposal),errorCode('NODE_OR_OWNER_NOT_ENROLLED'));
});
test('rejects tampering, extra fields and forged node signatures',async()=>{
  const f=fixture(),b=createBroker(f.deps);
  await assert.rejects(b.execute(bearer,{...f.request,extra:true}),errorCode('INVALID_REQUEST_SHAPE'));
  const altered={...f.action,parameters:{tag:'CHANGED'}};
  await assert.rejects(b.execute(bearer,{...f.request,action:altered}),errorCode('INVALID_NODE_SIGNATURE'));
  assert.equal(f.calls.executions,0);
});
test('grant binds action, environment, audience, both key identifiers and expiry',async()=>{
  const changes=[{audience:'sac://broker/other/v04'},{environment:'production'},
    {action_digest:'f'.repeat(64)},{owner_kid:'other-owner'},{node_kid:'other-node'},
    {exp:N+181},{iat:N+2}];
  for(const change of changes){
    const f=fixture();f.request.grant={...f.grant,...change};
    f.request.grant_signature_b64url=signBody(f.owner,GRANT_DOMAIN,f.request.grant);
    await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('INVALID_EXACT_ACTION_GRANT'));
    assert.equal(f.calls.executions,0);
  }
});
test('offline owner grant helper checks node signature and produces an executable exact grant',async()=>{
  const f=fixture();
  const proposal={...f.proposal,proposal_id:proposalId,action_digest:digest(f.action)};
  const cfg={owner_id:ownerId,owner_kid:'owner-key-1',node_kid:'node-key-1',audience,environment,
    owner_public_jwk:jwk(f.owner),node_public_jwk:jwk(f.node)};
  assert.equal(validateApprovalRequest(proposal,cfg),true);
  const pem=f.owner.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  const signed=signOwnerGrant(proposal,cfg,pem,{now:N,nonce:'2'.repeat(32)});
  const result=await createBroker(f.deps).execute(bearer,{...f.proposal,proposal_id:proposalId,...signed});
  assert.equal(result.status,'EXECUTED_AUDIT_RECORDED');
  assert.throws(()=>signOwnerGrant({...proposal,action_digest:'f'.repeat(64)},cfg,pem,{now:N}),/PROPOSAL_OR_TRUSTED/);
  assert.throws(()=>signOwnerGrant(proposal,{...cfg,owner_public_jwk:jwk(f.node)},pem,{now:N}),/OWNER_KEY_MISMATCH/);
});
test('owner, node and audit keys must be distinct',async()=>{
  const f=fixture();f.deps.trustedAudit.public_jwk=jwk(f.owner);
  await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('SIGNING_IDENTITIES_MUST_BE_DISTINCT'));
});
test('invalid or unavailable audit intent blocks before effect',async()=>{
  for(const kind of ['down','bad-signature']){
    const f=fixture();
    f.deps.audit.append=async()=>{if(kind==='down')throw Error('down');return {ack:{},signature_b64url:'bad'};};
    await assert.rejects(createBroker(f.deps).execute(bearer,f.request),
      errorCode(kind==='down'?'AUDIT_INTENT_UNAVAILABLE':'AUDIT_INTENT_UNVERIFIED'));
    assert.equal(f.calls.executions,0);
  }
});
test('signed audit intent time outside the owner grant blocks before effect',async()=>{
  for(const accepted_at of [N-1,N+60,N+1000]){
    const f=fixture();
    f.deps.audit.append=async event=>{
      const ack={schema:'sac.audit.ack.v1',sink_id:'independent-audit',event_sha256:eventDigest(event),event_type:event.type,accepted_at};
      return {ack,signature_b64url:signBody(f.auditor,'sac.audit.ack.v1\n',ack)};
    };
    await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('AUDIT_INTENT_TIME_INVALID'));
    assert.equal(f.calls.executions,0);
  }
});
test('expiry after audit intent prevents execution',async()=>{
  const f=fixture(),original=f.deps.audit.append;
  f.deps.audit.append=async event=>{const ack=await original(event);f.setNow(N+60);return ack;};
  await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('GRANT_EXPIRED_BEFORE_EXECUTION'));
  assert.equal(f.calls.executions,0);
});
test('owner session revoked during audit hop blocks execution',async()=>{
  const f=fixture();let calls=0;
  f.deps.auth.authenticate=async()=>++calls===1?{owner_id:ownerId,aal:'aal2'}:null;
  await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('AUTH_SESSION_DENIED'));
  assert.equal(f.calls.events.length,1);assert.equal(f.calls.executions,0);
});
test('result logging failure reports executed and pending, never automatic retry',async()=>{
  const f=fixture(),original=f.deps.audit.append;
  f.deps.audit.append=async e=>{if(e.type==='result')throw Error('sink unavailable');return original(e);};
  const result=await createBroker(f.deps).execute(bearer,f.request);
  assert.equal(result.status,'EXECUTED_AUDIT_PENDING');assert.equal(result.automatic_retry,false);
  assert.equal(f.calls.executions,1);
});
test('signed result with an impossible future audit time remains pending',async()=>{
  const f=fixture(),original=f.deps.audit.append;
  f.deps.audit.append=async event=>{
    if(event.type==='intent')return original(event);
    const ack={schema:'sac.audit.ack.v1',sink_id:'independent-audit',event_sha256:eventDigest(event),event_type:event.type,accepted_at:N+1000};
    return {ack,signature_b64url:signBody(f.auditor,'sac.audit.ack.v1\n',ack)};
  };
  const out=await createBroker(f.deps).execute(bearer,f.request);
  assert.equal(out.status,'EXECUTED_AUDIT_PENDING');assert.equal(f.calls.executions,1);
});
test('uncertain store outcome never asserts an effect or retries',async()=>{
  const f=fixture();let calls=0;
  f.deps.store.executeCanary=async()=>{calls++;throw Error('timeout after possible commit');};
  await assert.rejects(createBroker(f.deps).execute(bearer,f.request),errorCode('EXECUTION_OUTCOME_UNKNOWN_DO_NOT_RETRY'));
  assert.equal(calls,1);
});
test('nonce replay rejects second attempt in single-process fixture',async()=>{
  const f=fixture(),b=createBroker(f.deps);
  await b.execute(bearer,f.request);
  await assert.rejects(b.execute(bearer,f.request),errorCode('GRANT_REPLAY'));
  assert.equal(f.calls.executions,1);
});
test('broker passes grant timing, key IDs and independent audit evidence to store',async()=>{
  const f=fixture();let captured;const original=f.deps.store.executeCanary;
  f.deps.store.executeCanary=async p=>{captured=p;return original(p);};
  await createBroker(f.deps).execute(bearer,f.request);
  assert.equal(captured.grant_exp,N+60);assert.equal(captured.grant_iat,N);
  assert.equal(captured.owner_kid,'owner-key-1');assert.equal(captured.node_kid,'node-key-1');
  assert.match(captured.audit_intent_sha256,/^[0-9a-f]{64}$/);assert.match(captured.audit_ack_sha256,/^[0-9a-f]{64}$/);
});
test('real local ledger signs, fsyncs, deduplicates, restarts and detects tampering',async()=>{
  const f=fixture(),dir=await mkdtemp(path.join(tmpdir(),'broker-v04-audit-'));
  const pem=f.auditor.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  try{
    const ledger=await openAuditLedger({directory:dir,sinkId:'independent-audit',privatePem:pem,clock:()=>N});
    const grantHash='a'.repeat(64);
    const e={schema:'sac.audit.event.v1',type:'intent',owner_id:ownerId,node:f.action.node,run:f.action.run,
      proposal_id:proposalId,action_digest:digest(f.action),grant_sha256:grantHash,nonce:'1'.repeat(32),audience,environment};
    await assert.rejects(ledger.append({...e,type:'result',execution_id:executionId,effect_sha256:'a'.repeat(64)}),/WITHOUT_INTENT/);
    const ack=await ledger.append(e);assert.equal(verifyAuditAck(e,ack,f.deps.trustedAudit),true);
    assert.deepEqual(await ledger.append(e),ack);
    await assert.rejects(openAuditLedger({directory:dir,sinkId:'independent-audit',privatePem:pem}));
    await ledger.close();
    const replay=await openAuditLedger({directory:dir,sinkId:'independent-audit',privatePem:pem});
    assert.deepEqual(await replay.append(e),ack);await replay.close();
    const p=path.join(dir,'audit.jsonl'),data=await readFile(p,'utf8');
    await writeFile(p,data.replace('ONLY_CANARY','CHANGED'));
    // Modify an authenticated event field; the record must fail signature/digest verification.
    const value=JSON.parse(data);value.event.run='changed-run';await writeFile(p,canonical(value)+'\n');
    await assert.rejects(openAuditLedger({directory:dir,sinkId:'independent-audit',privatePem:pem}));
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('ledger rejects removal of an interior signed event even if chain hashes are rebuilt',async()=>{
  const f=fixture(),dir=await mkdtemp(path.join(tmpdir(),'broker-v04-ledger-order-'));
  const pem=f.auditor.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  try{
    const ledger=await openAuditLedger({directory:dir,sinkId:'independent-audit',privatePem:pem,clock:()=>N});
    const event={schema:'sac.audit.event.v1',type:'intent',owner_id:ownerId,node:f.action.node,run:f.action.run,
      proposal_id:proposalId,action_digest:digest(f.action),grant_sha256:'a'.repeat(64),nonce:'1'.repeat(32),audience,environment};
    for(const n of ['1','2','3'])await ledger.append({...event,nonce:n.repeat(32)});
    await ledger.close();
    const file=path.join(dir,'audit.jsonl');
    const records=(await readFile(file,'utf8')).trim().split('\n').map(JSON.parse);
    const first=canonical(records[0]);
    records[2].seq=2;records[2].prev_sha256=sha256(first);
    await writeFile(file,first+'\n'+canonical(records[2])+'\n');
    await assert.rejects(openAuditLedger({directory:dir,sinkId:'independent-audit',privatePem:pem}),/AUDIT_CHAIN_SIGNATURE_INVALID/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('independently saved signed audit head detects loss of the anchored suffix',async()=>{
  const f=fixture(),dir=await mkdtemp(path.join(tmpdir(),'broker-v04-anchor-'));
  const pem=f.auditor.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  try{
    const opts={directory:dir,sinkId:'independent-audit',privatePem:pem,clock:()=>N};
    const ledger=await openAuditLedger(opts);
    const event={schema:'sac.audit.event.v1',type:'intent',owner_id:ownerId,node:f.action.node,run:f.action.run,
      proposal_id:proposalId,action_digest:digest(f.action),grant_sha256:'a'.repeat(64),nonce:'1'.repeat(32),audience,environment};
    await ledger.append(event);await ledger.append({...event,nonce:'2'.repeat(32)});
    const anchor=await ledger.signedHead();assert.equal(anchor.head.seq,2);
    assert.equal(verifyAuditHead(anchor,f.deps.trustedAudit),true);
    await ledger.append({...event,nonce:'3'.repeat(32)});await ledger.close();
    const reopened=await openAuditLedger({...opts,anchor});await reopened.close();
    const file=path.join(dir,'audit.jsonl'),lines=(await readFile(file,'utf8')).trim().split('\n');
    await writeFile(file,lines[0]+'\n');
    await assert.rejects(openAuditLedger({...opts,anchor}),/AUDIT_ANCHOR_MISMATCH/);
    await assert.rejects(openAuditLedger({...opts,anchor:{...anchor,head:{...anchor.head,seq:1}}}),/AUDIT_ANCHOR_INVALID/);
    await assert.rejects(openAuditLedger({...opts,anchor:false}),/AUDIT_ANCHOR_INVALID/);
    // Without an externally retained head, deleting a valid tail is undetectable.
    const noAnchor=await openAuditLedger(opts);await noAnchor.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('HTTP adapter rejects duplicate JSON keys and missing authentication',async()=>{
  const f=fixture(),server=createBrokerHttpServer(createBroker(f.deps));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const url=`http://127.0.0.1:${server.address().port}`;
    let r=await fetch(url+'/propose',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    assert.equal(r.status,401);
    r=await fetch(url+'/propose',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+bearer},body:'{"action":{},"action":{}}'});
    assert.equal(r.status,400);
    r=await fetch(url+'/propose',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+bearer},body:JSON.stringify(f.proposal)});
    assert.equal(r.status,202);assert.equal((await r.json()).status,'PROPOSED');
  } finally {await new Promise(resolve=>server.close(resolve));}
});
test('independently signed observation is needed to reconcile a logged effect',async()=>{
  const f=fixture();await createBroker(f.deps).execute(bearer,f.request);
  const observer=generateKeyPairSync('ed25519');
  const observation={schema:'sac.effect-observation.v2',observer_id:'observer-1',source:'readonly-db',
    owner_id:ownerId,proposal_id:proposalId,grant_sha256:f.calls.events[1].grant_sha256,
    execution_id:executionId,action_digest:digest(f.action),effect_sha256:'a'.repeat(64),audience,environment,
    observed_at:N+2,status:'present'};
  const params={intent:f.calls.events[0],intent_ack:f.calls.acks[0],result:f.calls.events[1],result_ack:f.calls.acks[1],
    observation,observation_signature:signBody(observer,'sac.effect-observation.v2\n',observation),
    trustedAudit:f.deps.trustedAudit,trustedObserver:{id:'observer-1',public_jwk:jwk(observer),allowed_sources:['readonly-db']},now:N+3};
  assert.equal(reconcile(params).status,'RECONCILED_SIGNED_OBSERVATION');
  assert.throws(()=>reconcile({...params,observation:{...observation,effect_sha256:'f'.repeat(64)}}),/OBSERVATION_BINDING_INVALID/);
  assert.throws(()=>reconcile({...params,observation_signature:'bad'}),/OBSERVER_SIGNATURE_INVALID/);
  assert.throws(()=>reconcile({...params,trustedObserver:{...params.trustedObserver,public_jwk:jwk(f.auditor)}}),/OBSERVER_KEY_NOT_DISTINCT/);
  assert.throws(()=>reconcile({...params,trustedObserver:{...params.trustedObserver,allowed_sources:['other']}}),/OBSERVATION_BINDING_INVALID/);
  // A different grant can produce the same action/effect digest. Reusing an
  // observed execution ID must not reconcile that other grant.
  const otherIntent={...params.intent,grant_sha256:'e'.repeat(64),nonce:'2'.repeat(32)};
  const otherResult={...params.result,grant_sha256:otherIntent.grant_sha256,nonce:otherIntent.nonce};
  const otherIntentAck=await f.deps.audit.append(otherIntent),otherResultAck=await f.deps.audit.append(otherResult);
  assert.throws(()=>reconcile({...params,intent:otherIntent,intent_ack:otherIntentAck,
    result:otherResult,result_ack:otherResultAck}),/OBSERVATION_BINDING_INVALID/);
});
test('observer binds owner grant and independently read execution before signing',async()=>{
  const f=fixture();
  const effect=sha256([ownerId,f.action.node,digest(f.action),f.action.parameters.tag].join(':'));
  f.deps.store.executeCanary=async()=>({executed:true,execution_id:executionId,effect_sha256:effect});
  await createBroker(f.deps).execute(bearer,f.request);
  const observer=generateKeyPairSync('ed25519');
  const row={execution_id:executionId,owner_id:ownerId,proposal_id:proposalId,action_digest:digest(f.action),
    grant_sha256:f.calls.events[0].grant_sha256,effect_sha256:effect,
    operation:'audit_canary',resource:'sac://broker/canary'};
  const args={intent:f.calls.events[0],intent_ack:f.calls.acks[0],action:f.action,grant:f.grant,
    grant_signature_b64url:f.request.grant_signature_b64url,execution_id:executionId,
    trustedAudit:f.deps.trustedAudit,trustedOwner:{owner_id:ownerId,kid:'owner-key-1',public_jwk:jwk(f.owner)},
    observer:{id:'observer-1',source:'readonly-db',audience,environment,public_jwk:jwk(observer)},
    source:{readExecution:async()=>row},signer:async bytes=>sign(null,bytes,observer.privateKey),clock:()=>N+2};
  const attested=await observeExecution(args);
  const trustedObserver={id:'observer-1',allowed_sources:['readonly-db'],public_jwk:jwk(observer)};
  assert.equal(reconcile({intent:f.calls.events[0],intent_ack:f.calls.acks[0],result:f.calls.events[1],
    result_ack:f.calls.acks[1],...attested,trustedAudit:f.deps.trustedAudit,trustedObserver,now:N+3}).status,
    'RECONCILED_SIGNED_OBSERVATION');
  await assert.rejects(observeExecution({...args,source:{readExecution:async()=>({...row,grant_sha256:'e'.repeat(64)})}}),/INDEPENDENT_SOURCE_MISMATCH/);
  await assert.rejects(observeExecution({...args,signer:async bytes=>sign(null,bytes,f.owner.privateKey)}),/OBSERVER_SIGNER_KEY_MISMATCH/);
  await assert.rejects(observeExecution({...args,grant:{...f.grant,nonce:'2'.repeat(32)}}),/OWNER_GRANT_OR_INTENT_MISMATCH/);
  let recoveredWrites=0;
  const originalAudit=f.deps.audit.append;
  const recovered=await recoverAuditResult({intent:f.calls.events[0],intent_ack:f.calls.acks[0],...attested,
    trustedAudit:f.deps.trustedAudit,trustedObserver,audit:{append:async event=>{recoveredWrites++;return originalAudit(event);}},now:N+3});
  assert.equal(recovered.effect_retried,false);assert.equal(recoveredWrites,1);
  assert.equal(recovered.reconciliation.status,'RECONCILED_SIGNED_OBSERVATION');
  await assert.rejects(recoverAuditResult({intent:f.calls.events[0],intent_ack:f.calls.acks[0],...attested,
    observation:{...attested.observation,grant_sha256:'f'.repeat(64)},trustedAudit:f.deps.trustedAudit,trustedObserver,
    audit:{append:async()=>{throw Error('must not be called');}},now:N+3}),/OBSERVATION_BINDING_INVALID/);
});
