// Test-only subprocess: start a separate Node runtime for an isolated SAC node.
// No provider API, public network, TEE, or BFT behavior is implied.
import {createGateway} from '../src/server.mjs';
import {readFile} from 'node:fs/promises';
const required=['SAC_NODE_ID','SAC_PRIVATE_KEY_PATH','SAC_TRUST_STORE_PATH','SAC_STATE_DIR'];
for(const k of required)if(!process.env[k])throw new Error(k+' unset');
const server=createGateway({
 nodeId:process.env.SAC_NODE_ID,
 privatePem:await readFile(process.env.SAC_PRIVATE_KEY_PATH,'utf8'),
 trustStore:JSON.parse(await readFile(process.env.SAC_TRUST_STORE_PATH,'utf8')),
 stateDir:process.env.SAC_STATE_DIR
});
server.listen(0,'127.0.0.1',()=>process.send?.({ready:true,port:server.address().port}));
process.on('message',m=>{if(m==='stop')server.close(()=>process.exit(0));});