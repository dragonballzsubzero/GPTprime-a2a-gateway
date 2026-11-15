import {readFile} from 'node:fs/promises';
import {createBroker} from './core.mjs';
import {createSupabaseAdapters,createHttpsAuditClient} from './adapters.mjs';
import {createBrokerHttpServer} from './http.mjs';
import {readPrivateFile} from './secrets.mjs';

const required=['SAC_SUPABASE_ORIGIN','SAC_SUPABASE_ANON_KEY','SAC_SUPABASE_SERVICE_KEY_PATH',
                'SAC_AUDIT_ORIGIN','SAC_AUDIT_TOKEN_PATH','SAC_AUDIT_SINK_ID','SAC_AUDIT_PUBLIC_JWK_PATH',
                'SAC_BROKER_AUDIENCE','SAC_BROKER_ENVIRONMENT'];
for(const name of required)if(!process.env[name])throw new Error('Missing configuration: '+name);
const host=process.env.SAC_BROKER_BIND||'127.0.0.1';
if(!['127.0.0.1','::1'].includes(host))throw new Error('LOOPBACK_ONLY');
const port=Number(process.env.SAC_BROKER_PORT||8790);
if(!Number.isInteger(port)||port<1||port>65535)throw new Error('INVALID_PORT');
const serviceKey=(await readPrivateFile(process.env.SAC_SUPABASE_SERVICE_KEY_PATH)).trim();
const adapters=createSupabaseAdapters({origin:process.env.SAC_SUPABASE_ORIGIN,
  anonKey:process.env.SAC_SUPABASE_ANON_KEY,serviceKey});
const audit=createHttpsAuditClient({origin:process.env.SAC_AUDIT_ORIGIN,
  secretProvider:async()=>(await readPrivateFile(process.env.SAC_AUDIT_TOKEN_PATH)).trim()});
const trustedAudit={id:process.env.SAC_AUDIT_SINK_ID,
  public_jwk:JSON.parse(await readFile(process.env.SAC_AUDIT_PUBLIC_JWK_PATH,'utf8'))};
const broker=createBroker({...adapters,audit,trustedAudit,audience:process.env.SAC_BROKER_AUDIENCE,
                           environment:process.env.SAC_BROKER_ENVIRONMENT});
createBrokerHttpServer(broker).listen(port,host,()=>console.log(JSON.stringify({
  service:'sac-broker-v04',bind:host,port,production_qualified:false,scope:'audit_canary_only'})));
