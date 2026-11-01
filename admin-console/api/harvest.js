// Authenticated pass-through; authorization, MFA and source requests are enforced in Supabase Edge.
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');
 res.setHeader('X-Content-Type-Options','nosniff');
 if(req.method!=='POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 const token=req.headers.authorization;
 if(typeof token!=='string'||!/^Bearer [A-Za-z0-9_.-]+$/.test(token)||token.length>13000) return res.status(401).json({error:'AUTH_REQUIRED'});
 const input=req.body;
 if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).length!==1||typeof input.topic!=='string'||input.topic.length>48) return res.status(422).json({error:'INVALID_TOPIC'});
 const url=process.env.SAC_SUPABASE_URL,key=process.env.SAC_SUPABASE_PUBLISHABLE_KEY;
 if(!url||!key||!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(url))return res.status(503).json({error:'BACKEND_NOT_CONFIGURED'});
 try{
  const upstream=await fetch(`${url}/functions/v1/sac-research-harvest-v1`,{
   method:'POST',headers:{Authorization:token,apikey:key,'Content-Type':'application/json'},
   body:JSON.stringify({topic:input.topic}),redirect:'error',signal:AbortSignal.timeout(22000)});
  const response=await upstream.text();
  res.setHeader('Content-Type','application/json; charset=utf-8');
  res.status(upstream.status).send(response.length<=25000?response:JSON.stringify({error:'UPSTREAM_TOO_LARGE'}));
 }catch{res.status(503).json({error:'RESEARCH_SOURCE_UNAVAILABLE'});}
}