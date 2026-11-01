// Explicit negative readiness until independent owner, node and provider proofs exist.
const headers = {'Cache-Control':'no-store','Content-Type':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff'};
export default {
  fetch(request) {
    if(request.method !== 'GET') return new Response(JSON.stringify({error:'METHOD_NOT_ALLOWED'}),{status:405,headers:{...headers,Allow:'GET'}});
    return new Response(JSON.stringify({status:'BLOCKED',reason:'OWNER_NODE_PROVIDER_COMMISSIONING_REQUIRED',external_inference_enabled:false,production_qualified:false}),{status:503,headers});
  }
};