// UI uses only already-authorized Supabase overview data, not historical claims.
const integer=v=>Number.isSafeInteger(v)&&v>=0?v:null;
function count(rows,name){return integer(rows?.[name]);}
export function assessArchitecture(snapshot){
  if(!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot))throw new Error('INVALID_BACKEND_SNAPSHOT');
  const c=snapshot.counts||{},tele=snapshot.telemetry||{},priv=snapshot.privilege||{};
  const entries=[
   ['Founder AAL2 session',priv.aal==='aal2'?'SESSION_AAL2_REPORTED':'UNVERIFIED','AAL2 does not independently prove owner commissioning'],
   ['Node enrollment',count(c,'enrolled_nodes')>0?'RECORDS_PRESENT':'BLOCKED','Independent host identity and approved founder grant still require verification'],
   ['Capability proofs',count(c,'capability_proofs')>0?'RECORDS_PRESENT':'BLOCKED','A capability row alone is not provider authentication'],
   ['Signed execution contracts',count(c,'execution_contracts')>0?'RECORDS_PRESENT':'BLOCKED','Task-scoped authorization, leases and downstream effects require proof'],
   ['External model outcomes',count(c,'execution_results')>0?'RECORDS_PRESENT':'BLOCKED','Must have metered vendor inference IDs and independent evaluation'],
   ['Transport receipts',count(c,'transport_receipts')>0?'RECORDS_PRESENT':'BLOCKED','Local integrity-probe receipts do not prove inference or encryption'],
   ['Private recipient encryption','UNVERIFIED','Earlier v0.33 source is not automatically part of the active v0.34 gateway'],
   ['Provider qualification',integer(tele.qualified_providers)>0?'RECORDS_PRESENT':'BLOCKED','Provider accounts, backend credentials and real requests must be verified'],
   ['Backup and restoration','UNVERIFIED','Dynamic plus prior-day backup with an independently tested restore required'],
   ['Production federation',tele.production_qualified===true?'CLAIM_REQUIRES_INDEPENDENT_PROOF':'BLOCKED','No promotion based on a status flag or a healthy deployment'],
  ];
  return {as_of:snapshot.as_of||null,summary:'Read-only evidence classification; this UI cannot commission provider nodes or authorize dispatch.',
    required:entries.length,items:entries.map(([name,state,limitation])=>({name,state,limitation})),
    qualified:false,dispatch_authorized:false};
}