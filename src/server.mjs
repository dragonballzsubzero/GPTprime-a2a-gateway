import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {verifyEnvelope,signedReceipt,sha256,FileReplayStore,parseStrictWire} from './transport.mjs';

export function createGateway({nodeId,privatePem,trustStore,stateDir,clock=Date.now}){
  if(!nodeId||!privatePem||!trustStore||!stateDir)throw new Error('MISSING_GATEWAY_CONFIGURATION');
  const store=new FileReplayStore(stateDir);
  return http.createServer(async (req,res)=>{
    const reply=(code,obj)=>{res.writeHead(code,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(obj));};
    if(req.method==='GET'&&req.url==='/healthz')return reply(200,{status:'ready',protocol:'SAC-A2A-TRANSPORT-1',version:'0.34',node_id:nodeId,scope:'local_integrity_probe_only',production_qualified:false});
    if(req.method!=='POST'||req.url!=='/sac/v0.34/dispatch')return reply(404,{error:'NOT_FOUND'});
    if(req.headers['content-type']!=='application/json')return reply(415,{error:'UNSUPPORTED_CONTENT_TYPE'});
    let chunks=[],length=0;
    try{
      for await(const chunk of req){length+=chunk.length;if(length>131072)throw new Error('BODY_TOO_LARGE');chunks.push(chunk);}
      const envelope=parseStrictWire(Buffer.concat(chunks));
      const v=verifyEnvelope(envelope,trustStore,{now:clock(),recipient:nodeId});
      await store.claim(v.sender,v.nonce,v.requestHash);
      // Deterministic probe; it does NOT invoke a model provider or external service.
      const digest=sha256(v.payload);
      const receipt=signedReceipt({node_id:nodeId,request_sha256:v.requestHash,result_sha256:digest,privatePem,now:clock()});
      await store.saveReceipt(receipt);
      return reply(200,{receipt});
    }catch(err){
      const e=err.message||'INTERNAL_ERROR';
      const client=['INVALID_OBJECT','INVALID_FIELDS','UNSUPPORTED_PROTOCOL','INVALID_NODE','INVALID_IDENTIFIER','INVALID_TIMESTAMP','UNSUPPORTED_OPERATION','INVALID_BASE64URL','NONCANONICAL_BASE64URL','INVALID_NONCE','INVALID_WINDOW','EXPIRED_OR_FUTURE','RECIPIENT_MISMATCH','UNTRUSTED_SENDER','BAD_SIGNATURE_LENGTH','INVALID_SIGNATURE','BODY_TOO_LARGE_OR_ENCODING','NONCANONICAL_WIRE_JSON','REPLAY_DETECTED','BODY_TOO_LARGE'];
      return reply(e==='REPLAY_DETECTED'?409:client.includes(e)?400:500,{error:client.includes(e)?e:'PROCESSING_FAILED'});
    }
  });
}
if(process.argv[1]?.endsWith('/server.mjs')){
  const required=['SAC_NODE_ID','SAC_PRIVATE_KEY_PATH','SAC_TRUST_STORE_PATH','SAC_STATE_DIR'];
  for(const key of required)if(!process.env[key])throw new Error('Required environment setting missing: '+key);
  const nodeId=process.env.SAC_NODE_ID;
  const privatePem=await readFile(process.env.SAC_PRIVATE_KEY_PATH,'utf8');
  const trustStore=JSON.parse(await readFile(process.env.SAC_TRUST_STORE_PATH,'utf8'));
  const gateway=createGateway({nodeId,privatePem,trustStore,stateDir:process.env.SAC_STATE_DIR});
  const host=process.env.SAC_BIND||'127.0.0.1';
  const port=Number(process.env.SAC_PORT||8765);
  if(!Number.isInteger(port)||port<1||port>65535)throw new Error('INVALID_PORT');
  gateway.listen(port,host,()=>console.log(JSON.stringify({listen:host+':'+port,node_id:nodeId,production_qualified:false})));
}