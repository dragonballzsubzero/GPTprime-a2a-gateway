export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='GET')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 const authorization=req.headers.authorization;
 if(typeof authorization!=='string'||!/^Bearer [A-Za-z0-9_.-]+$/.test(authorization)||authorization.length>13000)return res.status(401).json({error:'AUTH_REQUIRED'});
 const url=process.env.SAC_SUPABASE_URL, key=process.env.SAC_SUPABASE_PUBLISHABLE_KEY;
 if(!url||!key)return res.status(503).json({error:'BACKEND_NOT_CONFIGURED'});
 try{
  const response=await fetch(`${url}/functions/v1/sac-admin-bridge-v1`,{method:'GET',headers:{Authorization:authorization,apikey:key,Accept:'application/json'},signal:AbortSignal.timeout(16000)});
  const txt=await response.text();res.setHeader('Content-Type','application/json; charset=utf-8');
  res.status(response.status).send(txt.length<200000?txt:JSON.stringify({error:'UPSTREAM_TOO_LARGE'}));
 }catch{return res.status(503).json({error:'BACKEND_UNAVAILABLE'});}
}