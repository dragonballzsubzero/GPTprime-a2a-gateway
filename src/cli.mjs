import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {generateIdentity,createEnvelope,verifyEnvelope,verifyReceipt,sha256} from './transport.mjs';
const [command,...args]=process.argv.slice(2);
try {
 if(command==='keygen' && args.length===1){
   await mkdir(args[0],{recursive:true,mode:0o700});
   const k=generateIdentity();
   await writeFile(resolve(args[0],'private.pem'),k.private_pem,{flag:'wx',mode:0o600});
   await writeFile(resolve(args[0],'public.pem'),k.public_pem,{flag:'wx',mode:0o644});
   console.log('Identity generated; enroll public.pem in a separately approved trust store.');
 }else if(command==='sign'&&args.length===5){
   const [pemFile,sender,recipient,payloadFile,outFile]=args;
   const e=createEnvelope({privatePem:await readFile(pemFile,'utf8'),sender,recipient,payload:await readFile(payloadFile)});
   await writeFile(outFile,JSON.stringify(e),{flag:'wx',mode:0o600}); console.log(outFile);
 }else if(command==='verify'&&args.length===2){
   const [trustFile,envelopeFile]=args;
   const t=JSON.parse(await readFile(trustFile,'utf8'));
   const e=JSON.parse(await readFile(envelopeFile,'utf8'));
   const v=verifyEnvelope(e,t);
   console.log(JSON.stringify({valid:true,request_sha256:v.requestHash,payload_sha256:sha256(v.payload)}));
 }else if(command==='verify-receipt'&&args.length===2){
   const [pubFile,receiptFile]=args;
   const r=JSON.parse(await readFile(receiptFile,'utf8'));
   verifyReceipt(r,await readFile(pubFile,'utf8'));
   console.log(JSON.stringify({valid:true,request_sha256:r.request_sha256,result_sha256:r.result_sha256,execution_class:r.execution_class}));
 }else if(command==='send'&&args.length===2){
   const [url,file]=args;
   const res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:await readFile(file)});
   console.log(JSON.stringify({http_status:res.status,data:await res.json()})); if(!res.ok)process.exitCode=1;
 }else {console.error('Commands: keygen DIR | sign PRIVATE_PEM SENDER RECIPIENT PAYLOAD_FILE OUTPUT_JSON | verify TRUST_JSON ENVELOPE_JSON | verify-receipt PUB_PEM RECEIPT_JSON | send URL ENVELOPE_JSON');process.exitCode=2;}
}catch(err){console.error(err.message);process.exitCode=1;}