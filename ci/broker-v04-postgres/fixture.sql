-- Isolated synthetic CI database. Never run against a real project.
create role anon nologin;
create role authenticated nologin;
create role broker_fixture nologin;
create schema extensions;
create extension pgcrypto with schema extensions;
create schema sac_broker_v03;
create schema gptprime_v19;

create table sac_broker_v03.owner_keys (
  owner_id uuid primary key, public_jwk jsonb not null, key_id text not null,
  enabled boolean not null default false, activated_at timestamptz
);
create table sac_broker_v03.node_keys (
  node_id text primary key, public_jwk jsonb not null, key_id text not null,
  enabled boolean not null default false, activated_at timestamptz
);
create table gptprime_v19.a2a_current_trust_gate_v1 (
  node_id text primary key, dispatch_authorized boolean, owner_enrolled boolean,
  current_node_key_status text, identity_quarantine text
);
create table sac_broker_v03.proposals (
  proposal_id uuid primary key default gen_random_uuid(), owner_id uuid not null,
  node_id text not null, run_id text not null, action_digest text not null,
  action jsonb not null, unique(owner_id,node_id,run_id,action_digest)
);
create table sac_broker_v03.spent_grants (
  owner_id uuid not null, nonce text not null, action_digest text not null,
  spent_at timestamptz not null default now(), primary key(owner_id,nonce)
);
create table sac_broker_v03.executions (
  execution_id uuid primary key default gen_random_uuid(), owner_id uuid not null,
  proposal_id uuid not null references sac_broker_v03.proposals(proposal_id),
  node_id text not null, action_digest text not null, operation text not null
    check(operation='audit_canary'), resource text not null
    check(resource='sac://broker/canary'), canary_tag text not null,
  grant_sha256 text not null, effect_sha256 text not null, receipt_sha256 text not null
);
create table sac_broker_v03.audit_evidence (
  evidence_id uuid primary key default gen_random_uuid(), execution_id uuid not null
    references sac_broker_v03.executions(execution_id), source text not null,
  evidence_sha256 text not null
);

-- Fixture substitute for the existing v0.3 lookup, not a reconstruction of
-- the production trust view or its surrounding security-definer policy.
create function public.sac_broker_v03_keys(p_owner uuid,p_node text) returns jsonb
language sql stable set search_path=pg_catalog as $$
  select coalesce((select jsonb_build_object('allowed',true,'owner_kid',o.key_id,'node_kid',n.key_id)
    from sac_broker_v03.owner_keys o join sac_broker_v03.node_keys n on n.node_id=p_node
    join gptprime_v19.a2a_current_trust_gate_v1 g on g.node_id=n.node_id
    where o.owner_id=p_owner and o.enabled and o.activated_at is not null
    and n.enabled and n.activated_at is not null and g.dispatch_authorized
    and g.owner_enrolled and g.current_node_key_status='ACTIVE' and g.identity_quarantine is null),
    jsonb_build_object('allowed',false));
$$;
insert into sac_broker_v03.owner_keys values
 ('11111111-1111-4111-8111-111111111111','{}','owner-key-1',true,now());
insert into sac_broker_v03.node_keys values ('test.node','{}','node-key-1',true,now());
insert into gptprime_v19.a2a_current_trust_gate_v1 values ('test.node',true,true,'ACTIVE',null);
insert into sac_broker_v03.proposals(proposal_id,owner_id,node_id,run_id,action_digest,action)
values ('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',
 'test.node','test-run',repeat('a',64),
 '{"node":"test.node","run":"test-run","operation":"audit_canary","resource":"sac://broker/canary","parameters":{"tag":"ci"}}');
