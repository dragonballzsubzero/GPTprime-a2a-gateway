/** SAC research-provenance gate v0.34: schema/logic checks only, never scientific validation.
 * A completed metadata contract cannot independently prove measured phenomena.
 */
const HEX = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/;
const REQUIRED_STAGES = ['translation','mitochondrial_import','membrane_insertion','complex_assembly','functional_readout'];
const iso = s => typeof s === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(s) && Number.isFinite(Date.parse(s));
const str = x => typeof x === 'string' && x.trim().length>0;
const digest = x => typeof x === 'string' && HEX.test(x);
const number = x => typeof x === 'number' && Number.isFinite(x);

/** Provenance acceptance returns ready_for_external_review, never 'validated'. */
export function inspectEvidence(e) {
 const problems=[],warnings=[];
 const need=(ok,why)=>{if(!ok)problems.push(why);};
 need(e && typeof e==='object'&&!Array.isArray(e),'INVALID_RECORD');
 if(!e||typeof e!=='object'||Array.isArray(e))return {state:'incomplete',problems,warnings,scientifically_validated:false};
 need(e.version==='SAC-SCIENCE-EVIDENCE-1','VERSION_MISMATCH');
 need(e.domain==='mitochondrial'||e.domain==='endovascular_bci','UNSUPPORTED_DOMAIN');
 need(str(e.claim_id)&&ID.test(e.claim_id),'CLAIM_ID');
 need(str(e.claim) && e.claim.length<=2000,'CLAIM_DESCRIPTION');
 need(digest(e.raw_data_sha256),'RAW_DATA_DIGEST');
 need(Number.isSafeInteger(e.raw_size_bytes)&&e.raw_size_bytes>0,'RAW_SIZE');
 need(str(e.protocol_id),'PROTOCOL_ID');
 need(iso(e.acquired_utc),'ACQUISITION_TIMESTAMP');
 need(str(e.instrument_id),'INSTRUMENT_ID');
 need(digest(e.calibration_sha256),'CALIBRATION_DIGEST');
 need(str(e.custodian_id),'CUSTODIAN_ID');
 need(Array.isArray(e.controls)&&e.controls.length>0 && e.controls.every(str),'CONTROLS');
 need(e.synthetic===false,'REAL_DATA_REQUIRED');
 need(e.analysis && typeof e.analysis==='object','ANALYSIS_PLAN');
 if(e.analysis){
  need(e.analysis.preregistered===true,'PREREGISTRATION');
  need(Number.isSafeInteger(e.analysis.n)&&e.analysis.n>=2,'SAMPLE_COUNT');
  need(str(e.analysis.primary_endpoint),'PRIMARY_ENDPOINT');
  need(number(e.analysis.effect_estimate),'EFFECT_ESTIMATE');
  need(Array.isArray(e.analysis.confidence_interval)&&e.analysis.confidence_interval.length===2 && e.analysis.confidence_interval.every(number) && e.analysis.confidence_interval[0]<=e.analysis.confidence_interval[1],'CONFIDENCE_INTERVAL');
  need(number(e.analysis.p_value)&&e.analysis.p_value>=0&&e.analysis.p_value<=1,'P_VALUE');
  if(Number.isSafeInteger(e.analysis.n)&&e.analysis.n<10)warnings.push('SMALL_SAMPLE_REQUIRES_DESIGN_SPECIFIC_REVIEW');
 }
 if(e.domain==='mitochondrial'){
  const stages=e.outcomes || {};
  for(const key of REQUIRED_STAGES){
   const stage=stages[key] || {};
   need(str(stage.assay_id) && digest(stage.raw_data_sha256) && str(stage.control_id),`MITO_STAGE_${key.toUpperCase()}`);
  }
  need(e.genetic_code_corrected===true,'MITO_CODON_RECODING_NOT_DOCUMENTED');
  need(e.import_topology_tested===true,'MITO_IMPORT_TOPOLOGY_NOT_DOCUMENTED');
 }
 if(e.domain==='endovascular_bci'){
  const split=e.validation_split||{};
  need(split.heldout_sessions===true,'BCI_SESSION_GENERALIZATION_MISSING');
  need(split.heldout_participants===true,'BCI_PARTICIPANT_GENERALIZATION_MISSING');
  need(str(e.electrode_geometry_id),'BCI_GEOMETRY_MISSING');
  need(str(e.artifact_control_id),'BCI_ARTIFACT_CONTROL_MISSING');
  need(number(e.decoding_accuracy) && e.decoding_accuracy>=0 && e.decoding_accuracy<=1,'BCI_ACCURACY_INVALID');
  need(number(e.baseline_accuracy) && e.baseline_accuracy>=0 && e.baseline_accuracy<=1,'BCI_BASELINE_INVALID');
 }
 return {state:problems.length?'incomplete':'ready_for_external_review',problems,warnings,scientifically_validated:false};
}