import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,symlinkSync,rmSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const script=path.resolve('broker-v04/worker/run-triage.sh');
function fixture(fn){
  const dir=mkdtempSync(path.join(tmpdir(),'sac-worker-v04-'));
  try{
    const bin=path.join(dir,'bin'),intake=path.join(dir,'intake');mkdirSync(bin);mkdirSync(intake);
    const seccomp=path.join(dir,'seccomp.json'),input=path.join(intake,'file.txt'),record=path.join(dir,'args');
    writeFileSync(seccomp,'{}');writeFileSync(input,'fixture');
    writeFileSync(path.join(bin,'docker'),"#!/bin/sh\nif [ \"$1\" = info ]; then echo '[\"name=rootless\"]'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$MOCK_DOCKER_ARGS\"\n",{mode:0o755});
    const env={...process.env,PATH:bin+':'+process.env.PATH,SAC_TRIAGE_IMAGE:'example/image@sha256:'+'a'.repeat(64),
      SAC_SECCOMP_PROFILE:seccomp,SAC_TRIAGE_INTAKE_ROOT:intake,MOCK_DOCKER_ARGS:record};
    fn({dir,env,input,intake,record});
  }finally{rmSync(dir,{recursive:true,force:true});}
}
test('triage wrapper rejects mutable image, out-of-intake and symlink paths',()=>fixture(({dir,env,input,intake})=>{
  let p=spawnSync('sh',[script,input],{env:{...env,SAC_TRIAGE_IMAGE:'example/image:latest'},encoding:'utf8'});
  assert.notEqual(p.status,0);
  const outside=path.join(dir,'outside');writeFileSync(outside,'fixture');
  p=spawnSync('sh',[script,outside],{env,encoding:'utf8'});assert.notEqual(p.status,0);
  const symlink=path.join(intake,'link');symlinkSync(input,symlink);
  p=spawnSync('sh',[script,symlink],{env,encoding:'utf8'});assert.notEqual(p.status,0);
}));
test('triage wrapper passes restrictive arguments to a mocked rootless Docker CLI',()=>fixture(({env,input,record})=>{
  const syntax=spawnSync('sh',['-n',script],{encoding:'utf8'});assert.equal(syntax.status,0,syntax.stderr);
  const p=spawnSync('sh',[script,input],{env,encoding:'utf8'});assert.equal(p.status,0,p.stderr);
  const args=readFileSync(record,'utf8').split('\n');
  for(const required of ['--pull=never','--network=none','--read-only','--user=65534:65534','--cap-drop=ALL',
    '--security-opt=no-new-privileges','--pids-limit=32','--memory=256m','--memory-swap=256m','--cpus=0.5'])
    assert.ok(args.includes(required),required);
  assert.ok(args.some(x=>x.startsWith('seccomp=')));
}));
test('v0.4 scanner entry returns failure for rejected input and advisory for inert text',()=>fixture(({dir,input})=>{
  const entry=path.join(dir,'triage_entry.py'),scanner=path.join(dir,'triage_worker.py');
  copyFileSync('broker-v04/worker/triage_entry.py',entry);
  copyFileSync('broker-v03/worker/triage_worker.py',scanner);
  let p=spawnSync('python3',['-I','-B',entry,input],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);assert.equal(JSON.parse(p.stdout).status,'ADVISORY_ONLY');
  const archive=path.join(dir,'traversal.zip');
  p=spawnSync('python3',['-c',"import zipfile,sys;z=zipfile.ZipFile(sys.argv[1],'w');z.writestr('../escape','inert');z.close()",archive],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);
  p=spawnSync('python3',['-I','-B',entry,archive],{encoding:'utf8'});
  assert.equal(p.status,1,p.stderr);assert.equal(JSON.parse(p.stdout).reason,'ZIP_PATH_TRAVERSAL');
  p=spawnSync('python3',['-I','-B',entry,path.join(dir,'missing')],{encoding:'utf8'});
  assert.equal(p.status,1,p.stderr);assert.equal(JSON.parse(p.stdout).status,'REJECT');
}));
