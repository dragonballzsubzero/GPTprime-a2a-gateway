import http from 'node:http';
import {createHash,timingSafeEqual} from 'node:crypto';

/** Loopback-only HTTP component; production TLS and broker egress are external gates. */
export function createAuditHttpServer({ledger,bearerToken}){
  if(!ledger?.append || !ledger?.signedHead || typeof bearerToken!=='string' || bearerToken.length<32 || /[\r\n]/.test(bearerToken))
    throw new Error('AUDIT_CONFIGURATION_INVALID');
  const expected=createHash('sha256').update(bearerToken).digest();
  return http.createServer(async(req,res)=>{
    const reply=(status,obj)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(obj));};
    const isAppend=req.method==='POST'&&req.url==='/append';
    const isHead=req.method==='GET'&&req.url==='/head';
    if(!isAppend&&!isHead)return reply(404,{error:'NOT_FOUND'});
    const h=req.headers.authorization||'';
    const supplied=h.startsWith('Bearer ')?h.slice(7):'';
    const candidate=createHash('sha256').update(supplied).digest();
    if(!timingSafeEqual(expected,candidate))return reply(401,{error:'AUTH_REQUIRED'});
    if(isHead){
      try{return reply(200,await ledger.signedHead());}catch{return reply(503,{error:'AUDIT_UNAVAILABLE'});}
    }
    if((req.headers['content-type']||'').split(';')[0].trim().toLowerCase()!=='application/json')return reply(415,{error:'JSON_REQUIRED'});
    try {
      let chunks=[],size=0;
      for await(const part of req){size+=part.length;if(size>12000)throw new Error('BODY_TOO_LARGE');chunks.push(part);}
      const raw=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));
      const event=JSON.parse(raw);
      if(JSON.stringify(event)!==raw)throw new Error('NONCANONICAL_BODY');
      return reply(200,await ledger.append(event));
    }catch{return reply(400,{error:'AUDIT_REJECTED'});}
  });
}
