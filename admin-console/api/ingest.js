export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='POST')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 const auth=req.headers.authorization;
 if(typeof auth!=='string'||!/^Bearer [A-Za-z0-9_.-]+$/.test(auth)||auth.length>13000)return res.status(401).json({error:'AUTH_REQUIRED'});
 const raw=JSON.stringify(req.body??{});
 if(Buffer.byteLength(raw,'utf8')>65536)return res.status(413).json({error:'PAYLOAD_TOO_LARGE'});
 const url=process.env.SAC_SUPABASE_URL,key=process.env.SAC_SUPABASE_PUBLISHABLE_KEY;
 if(!url||!key)return res.status(503).json({error:'BACKEND_NOT_CONFIGURED'});
 try{
  const response=await fetch(`${url}/functions/v1/sac-admin-bridge-v1`,{method:'POST',headers:{Authorization:auth,apikey:key,'Content-Type':'application/json'},body:raw,signal:AbortSignal.timeout(16000)});
  const txt=await response.text();res.setHeader('Content-Type','application/json; charset=utf-8');
  res.status(response.status).send(txt.length<15000?txt:JSON.stringify({error:'UPSTREAM_TOO_LARGE'}));
 }catch{return res.status(503).json({error:'BACKEND_UNAVAILABLE'});}
}