import {readFile} from 'node:fs/promises';
import {openAuditWitness} from './audit-witness.mjs';
import {createAuditSnapshotClient} from './audit-witness-client.mjs';
import {readPrivateFile} from './secrets.mjs';

for(const name of ['SAC_WITNESS_DIR','SAC_AUDIT_ORIGIN','SAC_AUDIT_READER_TOKEN_PATH',
                   'SAC_AUDIT_SINK_ID','SAC_AUDIT_PUBLIC_JWK_PATH'])
  if(!process.env[name])throw new Error('Missing configuration: '+name);
const bootstrap=process.env.SAC_WITNESS_BOOTSTRAP==='1';
const expectedHead=process.env.SAC_WITNESS_EXPECTED_HEAD_PATH?
  JSON.parse(await readPrivateFile(process.env.SAC_WITNESS_EXPECTED_HEAD_PATH)):null;
const trusted={id:process.env.SAC_AUDIT_SINK_ID,
  public_jwk:JSON.parse(await readFile(process.env.SAC_AUDIT_PUBLIC_JWK_PATH,'utf8'))};
const source=createAuditSnapshotClient({origin:process.env.SAC_AUDIT_ORIGIN,
  secretProvider:async()=>(await readPrivateFile(process.env.SAC_AUDIT_READER_TOKEN_PATH)).trim()});
const witness=await openAuditWitness({directory:process.env.SAC_WITNESS_DIR,trusted,expectedHead,bootstrap});
try{
  const head=await witness.checkpoint(await source.snapshot());
  // Retain this signed head through an independent operator/storage boundary.
  process.stdout.write(JSON.stringify(head)+'\n');
}finally{await witness.close();}
