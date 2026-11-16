import {AUDIT_MAX_LOG_BYTES} from './audit-ledger.mjs';

const MAX_RESPONSE=2*AUDIT_MAX_LOG_BYTES+32768;
/** A separately scoped reader credential cannot append audit events. */
export function createAuditSnapshotClient({origin,secretProvider,fetchImpl=fetch}){
  const u=new URL(origin);
  if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||(u.pathname!=='/'&&u.pathname!==''))
    throw new Error('HTTPS_BASE_ORIGIN_REQUIRED');
  if(typeof secretProvider!=='function')throw new Error('AUDIT_READER_CREDENTIAL_REQUIRED');
  return {async snapshot(){
    const secret=await secretProvider();
    if(typeof secret!=='string'||secret.length<32||/[\r\n]/.test(secret))throw new Error('AUDIT_READER_CREDENTIAL_UNAVAILABLE');
    const res=await fetchImpl(u.origin+'/snapshot',{method:'GET',redirect:'error',signal:AbortSignal.timeout(30000),
      headers:{authorization:'Bearer '+secret}});
    if(!res.ok||!res.body)throw new Error('AUDIT_SNAPSHOT_UNAVAILABLE');
    const reader=res.body.getReader(),chunks=[];let size=0;
    try{
      for(;;){const part=await reader.read();if(part.done)break;size+=part.value.length;
        if(size>MAX_RESPONSE){await reader.cancel();throw new Error('AUDIT_SNAPSHOT_TOO_LARGE');}chunks.push(part.value);}
    }finally{reader.releaseLock();}
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
    if(!value||Array.isArray(value)||typeof value!=='object'||Object.keys(value).sort().join(',')!=='head,lines'||
       typeof value.lines!=='string')throw new Error('AUDIT_SNAPSHOT_INVALID');
    return value;
  }};
}
