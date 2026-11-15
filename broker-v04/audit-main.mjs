import {openAuditLedger} from './audit-ledger.mjs';
import {createAuditHttpServer} from './audit-http.mjs';
import {readPrivateFile} from './secrets.mjs';

for(const name of ['SAC_AUDIT_DIR','SAC_AUDIT_SINK_ID','SAC_AUDIT_PRIVATE_KEY_PATH','SAC_AUDIT_TOKEN_PATH'])
  if(!process.env[name])throw new Error('Missing configuration: '+name);
const host=process.env.SAC_AUDIT_BIND||'127.0.0.1';
if(!['127.0.0.1','::1'].includes(host))throw new Error('LOOPBACK_ONLY');
const port=Number(process.env.SAC_AUDIT_PORT||8791);
if(!Number.isInteger(port)||port<1||port>65535)throw new Error('INVALID_PORT');
const privatePem=await readPrivateFile(process.env.SAC_AUDIT_PRIVATE_KEY_PATH);
const bearerToken=(await readPrivateFile(process.env.SAC_AUDIT_TOKEN_PATH)).trim();
const ledger=await openAuditLedger({directory:process.env.SAC_AUDIT_DIR,sinkId:process.env.SAC_AUDIT_SINK_ID,privatePem});
const server=createAuditHttpServer({ledger,bearerToken});
server.listen(port,host,()=>console.log(JSON.stringify({service:'sac-audit-v04',bind:host,port,production_qualified:false})));
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>server.close(async()=>{await ledger.close();process.exit(0);}));
