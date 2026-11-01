// Deny by construction: serverless instance memory is not a durable replay store.
// Real A2A dispatch must use the separately authorized, persistent trust/lease backend.
const headers = {'Cache-Control':'no-store','Content-Type':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff'};
export default {
  fetch(request) {
    if(request.method !== 'POST') return new Response(JSON.stringify({error:'METHOD_NOT_ALLOWED'}),{status:405,headers:{...headers,Allow:'POST'}});
    return new Response(JSON.stringify({error:'SIGNED_DISPATCH_NOT_COMMISSIONED',authorized_to_dispatch:false,reason:'NO_AUTHENTICATED_NODE_OR_DURABLE_REPLAY_CONTRACT'}),{status:503,headers});
  }
};