// Public Europe PMC metadata normalization for SAC Console v1.2.
// This module never retrieves abstracts/full text and never treats a match as a verified finding.
export const TOPICS = Object.freeze({
  mitochondrial_allotopy: '"allotopic expression" AND ATP8',
  mitochondrial_import: '"mitochondrial protein import" AND ATP6',
  endovascular_bci: 'endovascular AND Stentrode'
});
export const MAX_RESULTS = 4;
const acceptedSources = new Set(['MED','PMC','PPR']);
const asBounded = (v,n=300) => typeof v==='string' ? v.replace(/[\u0000-\u001F\u007F]/g,' ').trim().slice(0,n) : '';
export function isTopic(value) { return typeof value==='string' && Object.hasOwn(TOPICS,value); }
export function queryUrl(topic){
 if (!isTopic(topic)) throw new Error('INVALID_TOPIC');
 const u=new URL('https://www.ebi.ac.uk/europepmc/webservices/rest/search');
 u.searchParams.set('query',TOPICS[topic]);
 u.searchParams.set('format','json');
 u.searchParams.set('resultType','lite');
 u.searchParams.set('pageSize',String(MAX_RESULTS));
 u.searchParams.set('sort','P_PDATE_D desc');
 return u.toString();
}
export function normalizeSearch(body){
 if(!body || typeof body!=='object' || Array.isArray(body) || body.errCode || body.error) throw new Error('INVALID_SOURCE_RESPONSE');
 const records=body.resultList?.result;
 if(!Array.isArray(records)||records.length>100) throw new Error('INVALID_SOURCE_RESPONSE');
 const result=[]; const seen=new Set();
 for (const a of records.slice(0,MAX_RESULTS)){
  if(!a || typeof a!=='object') continue;
  const source=asBounded(a.source,8), id=asBounded(a.id,60);
  const title=asBounded(a.title,550);
  if(!acceptedSources.has(source)||!/^[-A-Za-z0-9_.]{3,60}$/.test(id)||!title) continue;
  if(seen.has(source+':'+id)) continue;
  seen.add(source+':'+id);
  const doi=asBounded(a.doi,240);
  const payload={source,id,title,doi:/^10\.\d{4,9}\/[\w.()\-;/:%]+$/i.test(doi)?doi:null,
   publication_year:/^(19|20)\d{2}$/.test(String(a.pubYear??''))?Number(a.pubYear):null,
   journal:asBounded(a.journalTitle,200)||null,
   authors:asBounded(a.authorString,500)||null,
   pmid:/^\d{4,12}$/.test(String(a.pmid??''))?String(a.pmid):null,
   is_open_access:a.isOpenAccess==='Y'||a.isOpenAccess===true,
   citation_count:Number.isSafeInteger(Number(a.citedByCount))&&Number(a.citedByCount)>=0?Number(a.citedByCount):null,
   source_database:'Europe PMC (public bibliographic metadata)',
   evidence_kind:'index_metadata_not_full_text_or_experimental_validation'};
  result.push({id,source,source_url:`https://europepmc.org/article/${source}/${id}`,payload});
 }
 return result;
}
export function canonical(value){
 if(Array.isArray(value)) return value.map(canonical);
 if(value&&typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
 return value;
}
export function recordSigningInput(record){
 return JSON.stringify(canonical({connector_id:'europepmc',record_type:'paper',source_url:record.source_url,payload:record.payload}));
}