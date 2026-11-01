import {createMfaClient} from './mfa-client.mjs';
// SAC Admin Console v1 — no persisted credentials, no external JS dependencies.
let settings=null, auth=null, snapshot=null, view='overview',busy=false, pendingMfa=null;
const $=id=>document.getElementById(id);
const main=$('main');
const safeText=x=>x===null||x===undefined?'unknown':String(x);
const el=(tag,attrs={},text)=>{const n=document.createElement(tag);for(const [k,v] of Object.entries(attrs)){if(k==='class')n.className=v;else if(k==='type')n.type=v;else n.setAttribute(k,v);}if(text!==undefined)n.textContent=safeText(text);return n;};
const append=(parent,...items)=>{for(const x of items)parent.append(x);return parent;};
const clsFor=value=>{const x=String(value||'').toLowerCase();return ['connected','ready','resolved','active'].includes(x)?'good':['blocked','critical','error','failed'].includes(x)?'bad':['needs_connection','needs_service_auth','partial','in_progress','quarantined','warning'].includes(x)?'warn':'dim'};
function notice(text,kind='note'){const n=el('div',{class:kind},text);main.append(n);return n;}
function intro(kicker,title,description){return append(el('section',{class:'page-intro'}),el('span',{class:'eyebrow'},kicker),el('h1',{},title),el('p',{},description));}
function panel(title){return append(el('section',{class:'panel block'}),el('h2',{},title));}
function pill(v){return el('span',{class:'pill '+clsFor(v)},safeText(v));}
function kv(label,value){return append(el('div',{class:'kv'}),el('span',{},label),el('strong',{},safeText(value)));}
function table(columns,items){const t=el('table'),thead=el('thead'),head=el('tr');columns.forEach(c=>head.append(el('th',{},c.title)));thead.append(head);const tbody=el('tbody');items.forEach(record=>{const tr=el('tr');columns.forEach(c=>{const td=el('td');const v=c.value(record);td.append(v instanceof Node?v:document.createTextNode(safeText(v)));tr.append(td);});tbody.append(tr);});append(t,thead,tbody);const container=el('div',{class:'table-wrap'});container.style.overflowX='auto';return append(container,t);}
function setMessage(text,error=false){const e=$('login-message');if(e){e.textContent=text;e.className=error?'hint error':'hint';}}
async function jsonReq(url,options={}){const r=await fetch(url,options);let obj;try{obj=await r.json();}catch{obj={error:'Invalid server response'};}if(!r.ok)throw new Error(obj.error_description||obj.msg||obj.error||`HTTP_${r.status}`);return obj;}
const apiHeaders=()=>({'Content-Type':'application/json',apikey:settings.publishableKey});
function setBusy(value){busy=value;const b=$('login-password');if(b)b.disabled=value;}
async function signIn(event){event.preventDefault();if(busy)return;setBusy(true);try{
 const email=$('email').value.trim(),password=$('password').value;
 if(!email||!password)throw new Error('Enter your existing email and password.');
 const response=await jsonReq(settings.url+'/auth/v1/token?grant_type=password',{method:'POST',headers:apiHeaders(),body:JSON.stringify({email,password})});
 acceptSession(response);$('password').value='';await refreshData();
}catch(err){setMessage(err.message,true)}finally{setBusy(false);}}
async function requestCode(){try{const email=$('email').value.trim();if(!email)throw new Error('Enter the registered email address first.');await jsonReq(settings.url+'/auth/v1/otp',{method:'POST',headers:apiHeaders(),body:JSON.stringify({email,create_user:false})});setMessage('Sign-in email requested. Enter its code here if the configured email template sends one; otherwise use its login link.');}catch(err){setMessage(err.message,true)}}
async function verifyCode(){try{const email=$('email').value.trim(),token=$('otp').value.trim();if(!email||!token)throw new Error('Enter email and one-time code.');const response=await jsonReq(settings.url+'/auth/v1/verify',{method:'POST',headers:apiHeaders(),body:JSON.stringify({email,token,type:'email'})});acceptSession(response);await refreshData();}catch(err){setMessage(err.message,true)}}
function acceptSession(value){if(!value.access_token)throw new Error('Authentication returned no access token.');auth={token:value.access_token,refresh:value.refresh_token,expires:Date.now()+(Number(value.expires_in||300)*1000)};}
async function ensureToken(){if(!auth)throw new Error('AUTH_REQUIRED');if(auth.expires>Date.now()+45000)return auth.token;if(!auth.refresh){auth=null;throw new Error('SESSION_EXPIRED');}const v=await jsonReq(settings.url+'/auth/v1/token?grant_type=refresh_token',{method:'POST',headers:apiHeaders(),body:JSON.stringify({refresh_token:auth.refresh})});acceptSession(v);return auth.token;}
async function refreshData(){try{$('refresh').disabled=true;const token=await ensureToken();const data=await jsonReq('/api/overview',{headers:{Authorization:`Bearer ${token}`}});snapshot=data;$('signout').hidden=false;$('refresh').disabled=false;$('environment').textContent='Authenticated · '+(data.privilege?.role||'member');$('last-read').textContent='Backend read '+new Date(data.as_of).toLocaleTimeString();render();}catch(e){$('refresh').disabled=!auth;main.replaceChildren(intro('BACKEND ERROR','Unable to retrieve verified status',e.message));main.append(el('div',{class:'note'},'The source project was not modified. Confirm your account is on the SAC admin allowlist.'));}}
function renderOverview(){main.append(intro('CONTROL PLANE / LIVE DATA','System overview','Backend observations from the connected SAC database. A signed pre-enrollment challenge does not establish a production-enrolled node.'));
const metrics=el('div',{class:'metrics'}),counts=snapshot.counts||{};
for(const [label,key] of [['Enrolled nodes','enrolled_nodes'],['Capability proofs','capability_proofs'],['A2A contracts','execution_contracts'],['Transport receipts','transport_receipts']]){const m=el('section',{class:'panel metric'});append(m,el('span',{class:'k'},label),el('strong',{},counts[key]),el('span',{class:'sub'},'Verified database count'));metrics.append(m);}main.append(metrics);
const columns=el('div',{class:'columns'}),left=el('div'),right=el('div');const findings=panel('Open mainframe findings');
const active=(snapshot.findings||[]).filter(f=>f.status==='ACTIVE');if(active.length){for(const f of active){const a=el('article');append(a,el('b',{},f.code+' · '+f.severity),el('p',{},f.title));const list=left.querySelector('.list')||el('div',{class:'list'});list.append(a);if(!list.parentNode)findings.append(list);}}else findings.append(el('p',{class:'empty'},'No active findings in the current query.'));left.append(findings);
const runtime=panel('Runtime condition');const tel=snapshot.telemetry||{};['sampled_at','runner_enabled','runner_execution_proven','runner_state','queue_paused','production_qualified','qualified_providers','active_jobs'].forEach(k=>runtime.append(kv(k.replaceAll('_',' '),tel[k])));right.append(runtime);
const readiness=panel('Readiness snapshot');const r=snapshot.readiness||{};readiness.append(kv('Stage',r.stage||'unknown'),kv('Status',r.status||'unknown'),kv('As of',r.created_at||'unknown'));right.append(readiness);append(columns,left,right);main.append(columns,el('div',{class:'note'},snapshot.evidence_scope||'Evidence scope is limited to the connected data sources.'));}
function renderFederation(){main.append(intro('AGENT NETWORK','Federation readiness','These are real database candidate records, not evidence of independently operating provider runtimes.'));const p=panel('Registered runtime candidates');p.append(table([{title:'Candidate',value:r=>r.candidate_name},{title:'Provider',value:r=>r.provider_family},{title:'Integration',value:r=>pill(r.integration_state)},{title:'Unresolved gates',value:r=>(r.blocker_codes||[]).join(', ')||'None recorded'},{title:'Last verification',value:r=>r.last_verified_at||'Never'}],snapshot.candidates||[]));main.append(p);}
function renderIntegrations(){main.append(intro('INPUT ADAPTERS','Connector registry','Connection states are backed by the SAC connector registry. ChatGPT-side plugin connections are separate from runtime API authentication.'));const p=panel('Sources and integration readiness');p.append(table([{title:'Connector',value:r=>r.display_name},{title:'Purpose',value:r=>r.purpose},{title:'Adapter',value:r=>r.adapter_class},{title:'Surface',value:r=>r.access_surface},{title:'Status',value:r=>pill(r.state)},{title:'Last checked',value:r=>r.last_verified_at?new Date(r.last_verified_at).toLocaleDateString():'Not yet'}],snapshot.connectors||[]));main.append(p);}
function renderEvidence(){main.append(intro('SOURCE-ANCHORED INPUTS','Research evidence ingress','Accepts only structured public technical research metadata. Uploaded data enters quarantine and cannot automatically validate biological, cryptographic, or neural performance.'));const m=panel('Ingestion service');m.append(kv('Stored research records',snapshot.counts?.ingested_research_records),kv('Current assurance',snapshot.privilege?.aal||'aal1'),kv('Write requirement','Founder/admin + verified AAL2 MFA'));main.append(m);
const recent=panel('Recent ingested records');const history=snapshot.recent_evidence||[];
if(history.length)recent.append(table([{title:'Source',value:r=>r.connector_id},{title:'Type',value:r=>r.record_type},{title:'Status',value:r=>pill(r.provenance_status)},{title:'Acquired',value:r=>r.received_at?new Date(r.received_at).toLocaleString():'unknown'},{title:'SHA-256',value:r=>r.payload_sha256?.slice(0,20)+'…'||'unknown'}],history));
else recent.append(el('p',{class:'empty'},'No evidence ingested yet.'));
main.append(recent);
const harvest=panel('Retrieve public research metadata');harvest.classList.add('form-fields');
harvest.append(el('p',{class:'hint'},'Europe PMC public bibliographic index. Fixed, bounded searches; only metadata is saved and every record remains quarantined. One request per topic per hour.'));
const topic=el('select',{id:'research-topic'});
for(const [id,title] of [['mitochondrial_allotopy','Allotopic mitochondrial expression'],['mitochondrial_import','Mitochondrial protein import'],['endovascular_bci','Endovascular neural interfaces']])topic.append(el('option',{value:id},title));
const fetchButton=el('button',{class:'primary',type:'button',id:'research-fetch'},'Fetch research metadata');
fetchButton.disabled=snapshot.privilege?.aal!=='aal2';
append(harvest,el('label',{for:'research-topic'},'Research topic'),topic,fetchButton,el('p',{class:'hint',id:'research-fetch-message'},fetchButton.disabled?'Verify your authenticator (AAL2) before running source retrieval.':'Up to four indexed publications per retrieval.'));
main.append(harvest);
fetchButton.addEventListener('click',async()=>{fetchButton.disabled=true;const message=$('research-fetch-message');message.textContent='Requesting indexed public metadata…';try{
 const token=await ensureToken();
 const result=await jsonReq('/api/harvest',{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${token}`},body:JSON.stringify({topic:topic.value})});
 await refreshData();const current=$('research-fetch-message');
 if(current)current.textContent=`Europe PMC retrieval: ${result.received} records, ${result.stored} newly quarantined, ${result.duplicates} previously recorded; ${result.failed} storage errors. Upstream SHA-256: ${result.upstream_response_sha256}`;
 }catch(err){if(message.isConnected)message.textContent='Research retrieval unavailable: '+err.message;}finally{const b=$('research-fetch');if(b)b.disabled=snapshot?.privilege?.aal!=='aal2';}});
const form=panel('Submit a research source');form.classList.add('form-fields');const select=el('select',{id:'connector'});for(const item of snapshot.connectors||[]){const option=el('option',{value:item.connector_id},item.display_name);select.append(option);}append(form,el('label',{for:'connector'},'Source connector'),select,el('label',{for:'recordtype'},'Evidence type'));
const record=el('select',{id:'recordtype'});for(const k of ['paper','technical_reference','provider_status','operational_observation','research_note'])record.append(el('option',{value:k},k.replaceAll('_',' ')));form.append(record);
append(form,el('label',{for:'sourceurl'},'Public source URL (HTTPS)'),el('input',{id:'sourceurl',type:'url',placeholder:'https://doi.org/...'}),el('label',{for:'evidencejson'},'JSON metadata payload'),el('textarea',{id:'evidencejson',placeholder:'{"title":"Source paper", "doi":"10...", "finding":"..."}'}));
const btn=el('button',{class:'primary',type:'button',id:'submit-evidence'},'Submit to quarantine');btn.disabled=snapshot.privilege?.aal!=='aal2';form.append(btn,el('p',{class:'hint',id:'evidence-message'},btn.disabled?'MFA AAL2 not active: evidence writes are disabled. Configure a verified MFA factor for this Supabase Auth user.':'All records remain unverified until independently reviewed.'));main.append(form);btn.addEventListener('click',async()=>{btn.disabled=true;const msg=$('evidence-message');try{const payload=JSON.parse($('evidencejson').value),token=await ensureToken(),req={connector_id:$('connector').value,record_type:$('recordtype').value,source_url:$('sourceurl').value.trim()||null,observed_at:new Date().toISOString(),payload};const data=await jsonReq('/api/ingest',{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${token}`},body:JSON.stringify(req)});msg.textContent=`Quarantined evidence ${data.evidence_id}. Digest: ${data.payload_sha256}`;await refreshData();}catch(err){msg.textContent='Evidence rejected: '+err.message}finally{btn.disabled=snapshot?.privilege?.aal!=='aal2';}});}
function renderSecurity(){main.append(intro('ACCESS GOVERNANCE','Security & controls','The interface uses an existing Supabase Auth user with a service-side founder allowlist. Configure and verify an authenticator factor to authorize evidence uploads.'));
const p=panel('Current session');p.append(kv('Role',snapshot.privilege?.role||'unknown'),kv('Authenticator assurance',snapshot.privilege?.aal||'unknown'),kv('Application mode','Read-only until AAL2 is verified'),kv('MFA-gated ingestion',snapshot.privilege?.aal==='aal2'?'Eligible':'Blocked until AAL2'),kv('Password handling','Sent only to Supabase Auth'),kv('Session storage','In-memory only; re-authenticate on reload'),kv('Original SAC tables','Unmodified by this dashboard'));main.append(p);
const enrollPanel=panel('Authenticator app (TOTP) — setup or verify');
const factorArea=el('div',{id:'factor-area'},'Retrieving account MFA factors…');enrollPanel.append(factorArea);main.append(enrollPanel);
main.append(el('p',{class:'note'},'The QR and backup secret are displayed only for the current enrollment. Store recovery details in your authenticator manager, not in a Git repository. Every privileged write is independently checked by Supabase Auth and the server-side MFA gate.'));
showMfaControls(factorArea);
}
async function showMfaControls(slot){
 try{
   const token=await ensureToken();const client=createMfaClient(settings,token);const factors=await client.verifiedTotpFactors();
   if(!slot.isConnected)return;
   slot.replaceChildren();
   if(snapshot?.privilege?.aal==='aal2'){slot.append(el('p',{class:'success'},'Second factor verified for this session.'));return;}
   if(!factors.length&&!pendingMfa){
     slot.append(el('p',{class:'hint'},'No verified authenticator was found. Enroll an authenticator app for this account.'));
     const begin=el('button',{type:'button',class:'primary'},'Enroll TOTP authenticator');slot.append(begin);
     begin.addEventListener('click',async()=>{begin.disabled=true;try{const activeToken=await ensureToken();pendingMfa=await createMfaClient(settings,activeToken).enrollTotp();showPendingFactor(slot);}catch(e){slot.append(el('p',{class:'error'},'Enrollment failed: '+e.message));begin.disabled=false;}});
     return;
   }
   if(pendingMfa){showPendingFactor(slot);return;}
   slot.append(el('p',{class:'hint'},'Your authenticator factor is registered. Enter the current six-digit code to unlock MFA-gated research ingestion.'));
   showMfaVerification(slot,factors[0].id);
 }catch(e){if(slot.isConnected)slot.replaceChildren(el('p',{class:'error'},'MFA status unavailable: '+e.message));}
}
function showPendingFactor(slot){
 if(!pendingMfa)return;slot.replaceChildren(el('p',{class:'hint'},'Scan the enrollment QR with your authenticator or manually enter the secret below. Then verify the current six-digit code.'));
 const qr=pendingMfa.qrCode;
 if(typeof qr==='string'&&qr.startsWith('<svg')&&qr.length<20000){
   const image=el('img',{alt:'Temporary TOTP enrollment QR code'});image.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(qr);image.width=190;image.height=190;image.style.background='#fff';image.style.padding='9px';slot.append(image);
 }
 slot.append(el('p',{class:'hint'},'Manual enrollment secret — visible only until navigation or refresh:'));
 const secret=el('code',{},pendingMfa.secret);secret.className='mfa-secret';slot.append(secret);
 showMfaVerification(slot,pendingMfa.id);
}
function showMfaVerification(slot,factorId){
 const wrapper=el('div',{class:'mfa-actions'});
 const code=el('input',{type:'text',maxlength:'6',inputmode:'numeric',autocomplete:'one-time-code','aria-label':'Six-digit authenticator code',placeholder:'6-digit code'});
 const btn=el('button',{type:'button',class:'primary'},'Verify authenticator');const status=el('p',{class:'hint','role':'status'},'');
 wrapper.append(code,btn,status);slot.append(wrapper);
 btn.addEventListener('click',async()=>{btn.disabled=true;status.textContent='Verifying second factor…';try{
   const token=await ensureToken();const result=await createMfaClient(settings,token).challengeAndVerify(factorId,code.value.trim());
   acceptSession(result);pendingMfa=null;code.value='';status.textContent='Authenticator verified.';await refreshData();
 }catch(e){status.textContent='MFA verification failed: '+e.message;}finally{btn.disabled=false;}});
}

function render(){main.replaceChildren();const views={overview:renderOverview,federation:renderFederation,integrations:renderIntegrations,evidence:renderEvidence,security:renderSecurity};(views[view]||renderOverview)();$('current-view').textContent=view.charAt(0).toUpperCase()+view.slice(1);document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===view));}
async function signOut(){try{if(auth)await fetch(settings.url+'/auth/v1/logout',{method:'POST',headers:{apikey:settings.publishableKey,Authorization:`Bearer ${auth.token}`}});}catch{}auth=null;snapshot=null;pendingMfa=null;location.reload();}
async function init(){document.querySelectorAll('#nav button').forEach(b=>b.addEventListener('click',()=>{view=b.dataset.view;if(snapshot)render();}));$('refresh').addEventListener('click',refreshData);$('signout').addEventListener('click',signOut);$('login').addEventListener('submit',signIn);$('request-code').addEventListener('click',requestCode);$('verify-code').addEventListener('click',verifyCode);try{settings=await jsonReq('/api/config');}catch(e){setMessage('Configuration unavailable: '+e.message,true);$('login-password').disabled=true;}}
init();