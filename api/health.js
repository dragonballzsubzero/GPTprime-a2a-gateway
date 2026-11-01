// Vercel serverless compatibility surface. A deployment is NOT an enrolled AI node.
const headers = {'Cache-Control':'no-store','Content-Type':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff'};
export default {
  fetch(request) {
    if(request.method !== 'GET') return new Response(JSON.stringify({error:'METHOD_NOT_ALLOWED'}),{status:405,headers:{...headers,Allow:'GET'}});
    return new Response(JSON.stringify({service:'SAC-A2A-TRANSPORT',compatibility_version:'0.36.0-candidate',gateway_surface:'serverless_readiness_only',signed_dispatch_enabled:false,provider_execution_verified:false,production_qualified:false}),{status:200,headers});
  }
};