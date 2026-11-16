-- REVIEW CANDIDATE ONLY; NOT A MIGRATION, NOT INSTALLED OR PRODUCTION QUALIFIED.
-- Depends on existing sac_broker_v03 tables and trust gate. Provision a narrowly
-- scoped caller and create a real migration through the Supabase CLI after review.
-- The trusted application verifies node/owner Ed25519 signatures and the separate
-- audit signature BEFORE calling this SECURITY INVOKER function. SQL does not
-- cryptographically validate the audit or owner signature. No public caller may
-- execute it. This candidate deliberately does not auto-create grants or keys.

begin;
do $guard$
begin
  if pg_catalog.to_regprocedure('public.sac_broker_v04_execute_canary(uuid,text,text,text,text,uuid,text,bigint,bigint,text,text,text,text,text)') is not null then
    raise exception 'SAC_BROKER_V04_FUNCTION_ALREADY_EXISTS';
  end if;
end $guard$;
create function public.sac_broker_v04_execute_canary(
  p_owner uuid, p_node text, p_run text, p_digest text, p_nonce text,
  p_proposal uuid, p_canary_tag text, p_grant_iat bigint, p_grant_exp bigint,
  p_owner_kid text, p_node_kid text, p_grant_sha256 text,
  p_audit_intent_sha256 text, p_audit_ack_sha256 text
) returns jsonb
language plpgsql security invoker set search_path = pg_catalog as $$
declare
  k jsonb;
  selected_owner_kid text;
  selected_node_kid text;
  g record;
  x_id uuid;
  effect_hash text;
  receipt_hash text;
  current_epoch bigint;
begin
  if p_owner is null or p_proposal is null or p_node is null or p_run is null
     or p_digest is null or p_nonce is null or p_canary_tag is null
     or p_grant_iat is null or p_grant_exp is null or p_owner_kid is null or p_node_kid is null
     or p_grant_sha256 is null or p_audit_intent_sha256 is null or p_audit_ack_sha256 is null
     or p_node !~ '^[A-Za-z0-9_.:-]{1,100}$' or p_run !~ '^[A-Za-z0-9_.:-]{1,100}$'
     or p_canary_tag !~ '^[A-Za-z0-9_.:-]{1,64}$' or p_nonce !~ '^[a-f0-9]{32}$'
     or p_digest !~ '^[a-f0-9]{64}$' or p_grant_sha256 !~ '^[a-f0-9]{64}$'
     or p_audit_intent_sha256 !~ '^[a-f0-9]{64}$' or p_audit_ack_sha256 !~ '^[a-f0-9]{64}$'
     or p_owner_kid !~ '^[A-Za-z0-9_.:-]{1,128}$' or p_node_kid !~ '^[A-Za-z0-9_.:-]{1,128}$'
  then return jsonb_build_object('executed',false,'reason','INVALID_EFFECT_INPUT'); end if;

  -- Key rows are held through commit so their update/revocation serializes with
  -- this transaction. Quarantine writers must also coordinate on the same node
  -- admission lock; that deployment protocol remains an explicit release gate.
  perform pg_advisory_xact_lock(hashtextextended('sac-broker-node:'||p_node,0));
  select key_id into selected_owner_kid from sac_broker_v03.owner_keys
    where owner_id=p_owner and enabled and activated_at is not null for share;
  select key_id into selected_node_kid from sac_broker_v03.node_keys
    where node_id=p_node and enabled and activated_at is not null for share;
  if selected_owner_kid is distinct from p_owner_kid or selected_node_kid is distinct from p_node_kid then
    return jsonb_build_object('executed',false,'reason','KEYS_ROTATED_OR_INACTIVE');
  end if;
  select dispatch_authorized,owner_enrolled,current_node_key_status,identity_quarantine
    into g from gptprime_v19.a2a_current_trust_gate_v1 where node_id=p_node;
  if not found or g.dispatch_authorized is not true or g.owner_enrolled is not true
     or g.current_node_key_status is distinct from 'ACTIVE' or g.identity_quarantine is not null then
    return jsonb_build_object('executed',false,'reason','EXISTING_A2A_TRUST_GATE_DENIED');
  end if;
  k:=public.sac_broker_v03_keys(p_owner,p_node);
  if k->>'allowed' is distinct from 'true' or k->>'owner_kid' is distinct from p_owner_kid
     or k->>'node_kid' is distinct from p_node_kid then
    return jsonb_build_object('executed',false,'reason','KEYS_ROTATED_OR_INACTIVE');
  end if;
  current_epoch:=floor(extract(epoch from clock_timestamp()))::bigint;
  if p_grant_iat>current_epoch or p_grant_exp<=current_epoch or p_grant_exp<=p_grant_iat
     or p_grant_exp-p_grant_iat>180 then
    return jsonb_build_object('executed',false,'reason','GRANT_EXPIRED_OR_INVALID');
  end if;
  if not exists(select 1 from sac_broker_v03.proposals where proposal_id=p_proposal
      and owner_id=p_owner and node_id=p_node and run_id=p_run and action_digest=p_digest
      and action->>'node'=p_node and action->>'run'=p_run
      and action->>'operation'='audit_canary' and action->>'resource'='sac://broker/canary'
      and action->'parameters'->>'tag'=p_canary_tag) then
    return jsonb_build_object('executed',false,'reason','PROPOSAL_MISMATCH');
  end if;
  insert into sac_broker_v03.spent_grants(owner_id,nonce,action_digest)
    values(p_owner,p_nonce,p_digest) on conflict do nothing;
  if not found then return jsonb_build_object('executed',false,'reason','GRANT_REPLAY'); end if;
  -- A concurrent insert can wait on the unique constraint. Recheck wall-clock
  -- expiry after waiting; raise so the nonce insertion is rolled back as well.
  if p_grant_exp<=floor(extract(epoch from clock_timestamp()))::bigint then
    raise exception 'GRANT_EXPIRED_DURING_ATOMIC_RESERVATION';
  end if;
  effect_hash:=encode(extensions.digest((p_owner::text||':'||p_node||':'||p_digest||':'||p_canary_tag)::bytea,'sha256'),'hex');
  receipt_hash:=encode(extensions.digest(('SAC-BROKER-V04:'||p_owner::text||':'||p_digest||':'||p_nonce)::bytea,'sha256'),'hex');
  insert into sac_broker_v03.executions(owner_id,proposal_id,node_id,action_digest,operation,resource,
    canary_tag,grant_sha256,effect_sha256,receipt_sha256)
    values(p_owner,p_proposal,p_node,p_digest,'audit_canary','sac://broker/canary',p_canary_tag,
           p_grant_sha256,effect_hash,receipt_hash) returning execution_id into x_id;
  insert into sac_broker_v03.audit_evidence(execution_id,source,evidence_sha256)
    values(x_id,'v04_intent_sha256',p_audit_intent_sha256),
          (x_id,'v04_signed_audit_ack_sha256',p_audit_ack_sha256);
  if p_grant_exp<=floor(extract(epoch from clock_timestamp()))::bigint then
    raise exception 'GRANT_EXPIRED_DURING_EFFECT_TRANSACTION';
  end if;
  return jsonb_build_object('executed',true,'execution_id',x_id,'effect_sha256',effect_hash,
    'reconciliation_status','PENDING_INDEPENDENT_RECONCILIATION');
end $$;

revoke all on function public.sac_broker_v04_execute_canary(uuid,text,text,text,text,uuid,text,bigint,bigint,text,text,text,text,text)
  from public,anon,authenticated,service_role;
do $acl$
declare f oid:=pg_catalog.to_regprocedure('public.sac_broker_v04_execute_canary(uuid,text,text,text,text,uuid,text,bigint,bigint,text,text,text,text,text)');
begin
  if f is null or pg_catalog.has_function_privilege('anon',f,'EXECUTE') or
     pg_catalog.has_function_privilege('authenticated',f,'EXECUTE') or
     pg_catalog.has_function_privilege('service_role',f,'EXECUTE') or
     exists(select 1 from pg_catalog.pg_proc p,
       lateral pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
       where p.oid=f and a.grantee=0 and a.privilege_type='EXECUTE') then
    raise exception 'SAC_BROKER_V04_UNSAFE_FUNCTION_ACL';
  end if;
end $acl$;
-- An operator must explicitly grant EXECUTE to the narrow trusted runtime role
-- after reviewing table/view/RPC privileges. No grant is made by this candidate.
commit;
