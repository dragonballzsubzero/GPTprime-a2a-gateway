import test from 'node:test';
import assert from 'node:assert/strict';
import {readdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';

test('all v0.4 runtime modules pass the active Node syntax check',()=>{
  for(const file of readdirSync('broker-v04').filter(x=>x.endsWith('.mjs'))){
    const r=spawnSync(process.execPath,['--check',path.join('broker-v04',file)],{encoding:'utf8'});
    assert.equal(r.status,0,`${file}: ${r.stderr}`);
  }
});
