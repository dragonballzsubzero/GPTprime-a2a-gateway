export default function handler(req,res){
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  const url=process.env.SAC_SUPABASE_URL, key=process.env.SAC_SUPABASE_PUBLISHABLE_KEY;
  if(!url||!key||!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(url))return res.status(503).json({error:'BACKEND_NOT_CONFIGURED'});
  return res.status(200).json({url,publishableKey:key,release:'1.1.0'});
}