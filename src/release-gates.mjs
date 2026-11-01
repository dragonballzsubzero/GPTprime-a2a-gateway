/* Immutable assessment of independently supplied evidence. Fail closed.
 * A database row count, signature, simulated test, or HTTP READY cannot
 * satisfy an external-provider and three-host consensus production gate.
 */
export const GATES=Object.freeze([
  'owner_aal2','founder_bound','authorized_budget','three_independent_nodes',
  'three_real_qualified_providers','three_metered_signed_inference_receipts',
  'cross_host_signed_a2a','revocation_replay_negative_tests',
  'backup_and_restore_proof','approved_and_reversible_release',
]);
export const LEVELS=Object.freeze(['PROPOSED','IMPLEMENTED','LOCALLY_VERIFIED','EXTERNALLY_VERIFIED','PRODUCTION_QUALIFIED']);
export function assessRelease(evidence){
  if(!evidence||typeof evidence!=='object'||Array.isArray(evidence))throw new Error('INVALID_EVIDENCE');
  const gates=Object.fromEntries(GATES.map(id=>[id,{verified:false,reason:'MISSING_INDEPENDENT_PROOF'}]));
  for(const [id,item] of Object.entries(evidence)){
    if(!Object.hasOwn(gates,id))throw new Error('UNKNOWN_GATE');
    if(!item||typeof item!=='object'||Array.isArray(item)||!Object.hasOwn(item,'level')||!Object.hasOwn(item,'verified')||!Object.hasOwn(item,'receipt_sha256'))throw new Error('INVALID_GATE_RECORD');
    if(!LEVELS.includes(item.level)||typeof item.verified!=='boolean'||(item.receipt_sha256!==null&&!(typeof item.receipt_sha256==='string'&&/^[0-9a-f]{64}$/.test(item.receipt_sha256))))throw new Error('INVALID_GATE_RECORD');
    if(item.verified&&(!['EXTERNALLY_VERIFIED','PRODUCTION_QUALIFIED'].includes(item.level)||!item.receipt_sha256))throw new Error('UNSUPPORTED_PROOF_PROMOTION');
    gates[id]={verified:item.verified,reason:item.verified?'REPORTED_EXTERNAL_RECEIPT_PENDING_INDEPENDENT_APPRAISAL':'NOT_VERIFIED',level:item.level};
  }
  // Even individually credible self-reports must pass independently appraised
  // trust anchors. This function cannot mint a production authorization.
  return Object.freeze({status:'NOT_PRODUCTION_QUALIFIED',authorized_to_dispatch:false,
    candidate_gates:Object.freeze(gates),needs_independent_appraisal:true,
    verified_gate_reports:Object.values(gates).filter(x=>x.verified).length,required_gate_reports:GATES.length});
}