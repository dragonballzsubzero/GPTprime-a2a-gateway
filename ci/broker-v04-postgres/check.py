#!/usr/bin/env python3
"""Exercise the actual candidate SQL in an explicitly disposable CI container."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import time

container = os.environ.get('SAC_TEST_POSTGRES_CONTAINER', '')
if os.environ.get('GITHUB_ACTIONS') != 'true' or not re.fullmatch(r'[a-f0-9]{12,64}', container):
    raise SystemExit('This check requires the disposable GitHub Actions PostgreSQL service container')
image = subprocess.check_output(['docker','inspect','--format','{{.Config.Image}}',container], text=True).strip()
if image != 'postgres:17.6':
    raise SystemExit('Unexpected test service image')
base = ['docker','exec','-i',container,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres']

def psql(sql, ok=True):
    p = subprocess.run(base, input=sql, text=True, capture_output=True, timeout=25)
    if ok and p.returncode:
        raise AssertionError(f'PostgreSQL returned {p.returncode}: {p.stderr}')
    return p

def check(condition, message):
    if not condition: raise AssertionError(message)
    print('PASS', message, flush=True)

def query(sql):
    return psql(sql).stdout.strip()

def execute(nonce, *, tag='ci', owner_kid='owner-key-1', node_kid='node-key-1',
            iat=None, exp=None):
    assert re.fullmatch('[a-f0-9]{32}', nonce)
    now = int(time.time())
    iat = now - 1 if iat is None else iat
    exp = now + 60 if exp is None else exp
    args = ["'11111111-1111-4111-8111-111111111111'", "'test.node'", "'test-run'",
            "'"+'a'*64+"'", "'"+nonce+"'", "'22222222-2222-4222-8222-222222222222'",
            "'"+tag+"'", str(iat), str(exp), "'"+owner_kid+"'", "'"+node_kid+"'",
            "'"+'b'*64+"'", "'"+'c'*64+"'", "'"+'d'*64+"'"]
    return 'select public.sac_broker_v04_execute_canary('+','.join(args)+')::text;'

def result(sql):
    return json.loads(query(sql))

def start_hold(sql):
    p = subprocess.Popen(base, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.stdin.write(sql)
    p.stdin.close()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise AssertionError('lock holder exited early: '+p.stderr.read())
        n = query("select count(*) from pg_catalog.pg_stat_activity where pid<>pg_backend_pid() "
                  "and state='active' and wait_event='PgSleep' and query like '%ci-lock-holder%';")
        if n == '1': return p
        time.sleep(.05)
    p.terminate()
    raise AssertionError('lock holder never became active')

print('PostgreSQL', query('show server_version;'), 'container image', image, flush=True)
psql(Path('ci/broker-v04-postgres/fixture.sql').read_text())
psql(Path('broker-v04/sql/execute-canary.candidate.sql').read_text())
duplicate=psql(Path('broker-v04/sql/execute-canary.candidate.sql').read_text(),ok=False)
check(duplicate.returncode!=0 and 'SAC_BROKER_V04_FUNCTION_ALREADY_EXISTS' in duplicate.stderr,
      'installation refuses to overwrite an existing function')

nonce='1'*32
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    replies=list(pool.map(lambda _: result(execute(nonce)), range(16)))
check(sum(x.get('executed') is True for x in replies)==1 and
      sum(x.get('reason')=='GRANT_REPLAY' for x in replies)==15,
      '16 independent PostgreSQL clients spend one nonce exactly once')
check(query('select count(*) from sac_broker_v03.executions')=='1' and
      query('select count(*) from sac_broker_v03.audit_evidence')=='2',
      'one canary and two audit-hash rows commit atomically')
check(query('show fsync;')=='on' and query('show synchronous_commit;')=='on',
      'fixture uses synchronous PostgreSQL durability settings')

# Crash the disposable server with one uncommitted nonce, then verify both
# committed replay state and rollback of the interrupted transaction.
crashNonce='f'*32
holder=start_hold("begin; insert into sac_broker_v03.spent_grants(owner_id,nonce,action_digest) "
  "values('11111111-1111-4111-8111-111111111111','"+crashNonce+"',repeat('a',64)); "
  "select pg_sleep(30) /* ci-lock-holder */; rollback;")
subprocess.run(['docker','kill','--signal','KILL',container],check=True,capture_output=True,text=True,timeout=20)
holder.wait(timeout=10)
subprocess.run(['docker','start',container],check=True,capture_output=True,text=True,timeout=20)
deadline=time.monotonic()+30
while time.monotonic()<deadline:
    probe=psql('select 1;',ok=False)
    if probe.returncode==0: break
    time.sleep(.2)
else: raise AssertionError('PostgreSQL did not recover after crash')
check(result(execute(nonce)).get('reason')=='GRANT_REPLAY' and
      query('select count(*) from sac_broker_v03.executions')=='1' and
      query("select count(*) from sac_broker_v03.spent_grants where nonce='"+crashNonce+"'")=='0',
      'crash recovery retains committed replay state and rolls back the interrupted transaction')

cases=[('2'*32, {'tag':'different'}, 'PROPOSAL_MISMATCH'),
       ('3'*32, {'owner_kid':'different'}, 'KEYS_ROTATED_OR_INACTIVE'),
       ('4'*32, {'node_kid':'different'}, 'KEYS_ROTATED_OR_INACTIVE'),
       ('5'*32, {'iat':int(time.time())-20,'exp':int(time.time())-10}, 'GRANT_EXPIRED_OR_INVALID')]
for nonce, kwargs, reason in cases:
    actual=result(execute(nonce,**kwargs))
    check(actual.get('executed') is False and actual.get('reason')==reason, reason+' denies')
check(query('select count(*) from sac_broker_v03.executions')=='1', 'denials write no effects')

psql("update gptprime_v19.a2a_current_trust_gate_v1 set identity_quarantine='QUARANTINED' where node_id='test.node';")
check(result(execute('6'*32)).get('reason')=='EXISTING_A2A_TRUST_GATE_DENIED', 'quarantined node denied')
psql("update gptprime_v19.a2a_current_trust_gate_v1 set identity_quarantine=null where node_id='test.node';")

holder=start_hold("begin; update sac_broker_v03.node_keys set enabled=false where node_id='test.node'; "
                  "select pg_sleep(2) /* ci-lock-holder */; commit;")
reply=result(execute('7'*32))
check(holder.wait(timeout=10)==0 and reply.get('reason')=='KEYS_ROTATED_OR_INACTIVE',
      'concurrent key revocation commits before a waiting admission')
psql("update sac_broker_v03.node_keys set enabled=true where node_id='test.node';")

nonce='8'*32
holder=start_hold("begin; insert into sac_broker_v03.spent_grants(owner_id,nonce,action_digest) "
  "values('11111111-1111-4111-8111-111111111111','"+nonce+"',repeat('a',64)); "
  "select pg_sleep(4) /* ci-lock-holder */; rollback;")
now=int(time.time())
p=psql(execute(nonce,iat=now-1,exp=now+2),ok=False)
check(holder.wait(timeout=10)==0 and p.returncode!=0 and 'GRANT_EXPIRED_DURING_ATOMIC_RESERVATION' in p.stderr,
      'expiry while waiting on a nonce rolls back the reservation')
check(query("select count(*) from sac_broker_v03.spent_grants where nonce='"+nonce+"'")=='0' and
      query('select count(*) from sac_broker_v03.executions')=='1', 'expired wait writes no effect or spent nonce')

for role in ('anon','authenticated','service_role'):
    p=psql('set role '+role+'; '+execute('9'*32),ok=False)
    check(p.returncode!=0 and 'permission denied' in p.stderr, role+' cannot call the candidate function')

psql('grant usage on schema sac_broker_v03, gptprime_v19, extensions to broker_fixture; '
     'grant execute on function public.sac_broker_v04_execute_canary(uuid,text,text,text,text,uuid,text,bigint,bigint,text,text,text,text,text) to broker_fixture;')
p=psql('set role broker_fixture; '+execute('a'*32),ok=False)
check(p.returncode!=0 and 'permission denied' in p.stderr,
      'invoker cannot execute without table access; database privilege redesign is still required')
print('PostgreSQL candidate checks completed; fixture is not a production trust gate.',flush=True)
