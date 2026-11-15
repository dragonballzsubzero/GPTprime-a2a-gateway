import http from 'node:http';
import {BrokerError} from './core.mjs';

const MAX_BODY=12000;
async function readCanonicalBody(req){
  const parts=[]; let n=0;
  for await (const part of req){
    n+=part.length;
    if(n>MAX_BODY)throw new BrokerError('BODY_TOO_LARGE',413);
    parts.push(part);
  }
  const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts));
  const value=JSON.parse(text);
  if(!value || typeof value!=='object' || Array.isArray(value) || JSON.stringify(value)!==text)
    throw new BrokerError('NONCANONICAL_BODY',400);
  return value;
}

/** A host may attach this handler to its private ingress; no privileged adapter is created here. */
export function createBrokerHttpServer(broker){
  if(!broker?.propose || !broker?.execute)throw new Error('BROKER_REQUIRED');
  return http.createServer(async (req,res)=>{
    const reply=(status,body)=>{if(!res.headersSent)res.writeHead(status,{
      'content-type':'application/json; charset=utf-8','cache-control':'no-store',
      'x-content-type-options':'nosniff'});res.end(JSON.stringify(body));};
    if(req.method==='GET' && req.url==='/healthz')return reply(200,{status:'staged',production_qualified:false});
    if(req.method!=='POST' || !['/propose','/execute'].includes(req.url))return reply(404,{error:'NOT_FOUND'});
    if((req.headers['content-type']||'').split(';')[0].trim().toLowerCase()!=='application/json')return reply(415,{error:'JSON_REQUIRED'});
    const header=req.headers.authorization || '';
    if(!/^Bearer [A-Za-z0-9._-]{20,4096}$/.test(header))return reply(401,{error:'AUTH_REQUIRED'});
    try {
      const body=await readCanonicalBody(req);
      const result=await (req.url==='/propose'?broker.propose:broker.execute)(header.slice(7),body);
      return reply(result.status==='PROPOSED'?202:result.status==='EXECUTED_AUDIT_PENDING'?202:200,result);
    } catch(err){
      if(err instanceof BrokerError)return reply(err.status,{error:err.code});
      if(err instanceof SyntaxError || err instanceof TypeError)return reply(400,{error:'INVALID_JSON_OR_UTF8'});
      return reply(503,{error:'BROKER_UNAVAILABLE'});
    }
  });
}
