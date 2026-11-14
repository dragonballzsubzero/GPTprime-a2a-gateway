import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

function withTemp(fn) {
  const dir=mkdtempSync(join(tmpdir(),'sac-broker-triage-'));
  try{return fn(dir);}finally{rmSync(dir,{recursive:true,force:true});}
}
function scan(path) {
  const p=spawnSync('python3',['-I','-B','broker-v03/worker/triage_worker.py',path],{encoding:'utf8'});
  assert.ok(p.status===0||p.status===1,p.stderr);
  return JSON.parse(p.stdout);
}
test('worker classifies benign utf8 without executing it',()=>withTemp(dir=>{
  const f=join(dir,'text.txt');writeFileSync(f,'audit canary is inert\n');
  const r=scan(f);assert.equal(r.status,'ADVISORY_ONLY');assert.equal(r.format,'utf8');assert.equal(r.sha256.length,64);
}));
test('worker detects PDF active marker but does not render PDF',()=>withTemp(dir=>{
  const f=join(dir,'sample.pdf');writeFileSync(f,'%PDF-1.4\n/JavaScript\n%%EOF\n');
  const r=scan(f);assert.equal(r.format,'pdf');assert.ok(r.flags.includes('PDF_ACTIVE_CONTENT_MARKER'));
}));
test('worker rejects symlink as file input',()=>withTemp(dir=>{
  const f=join(dir,'real.txt'),link=join(dir,'link.txt');writeFileSync(f,'hello');
  symlinkSync(f,link);assert.equal(scan(link).status,'REJECT');
}));
test('worker rejects path-traversing ZIP metadata without extraction',()=>withTemp(dir=>{
  const f=join(dir,'traversal.zip');
  const p=spawnSync('python3',['-c',"import zipfile,sys; z=zipfile.ZipFile(sys.argv[1],'w');z.writestr('../escape.txt','safe fixture');z.close()",f],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);assert.equal(scan(f).reason,'ZIP_PATH_TRAVERSAL');
}));
test('worker rejects oversized file',()=>withTemp(dir=>{
  const f=join(dir,'large.bin');writeFileSync(f,Buffer.alloc(10*1024*1024+1));
  assert.equal(scan(f).reason,'FILE_TYPE_OR_SIZE');
}));
