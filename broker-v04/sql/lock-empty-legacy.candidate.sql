-- REVIEW CANDIDATE ONLY. This disables v0.3 execution via API roles and
-- direct writes to broker tables, while leaving the v0.3 lookup/propose
-- RPCs in place. It deliberately refuses to operate on a nonempty broker.
-- It does not provision a replacement admission boundary or credentials.

begin;

-- Serialize the emptiness check with inserts and key activation. Once the
-- transaction commits, new v0.3 effects through service_role are denied.
lock table sac_broker_v03.owner_keys,sac_broker_v03.node_keys,
  sac_broker_v03.proposals,sac_broker_v03.spent_grants,
  sac_broker_v03.executions,sac_broker_v03.audit_evidence in share mode;

do $guard$
begin
  if pg_catalog.to_regprocedure('public.sac_broker_v03_execute_canary(uuid,text,text,text,text,uuid,text,text,text)') is null then
    raise exception 'SAC_BROKER_LEGACY_FUNCTION_MISSING';
  end if;
  if exists(select 1 from sac_broker_v03.owner_keys) or exists(select 1 from sac_broker_v03.node_keys)
     or exists(select 1 from sac_broker_v03.proposals) or exists(select 1 from sac_broker_v03.spent_grants)
     or exists(select 1 from sac_broker_v03.executions) or exists(select 1 from sac_broker_v03.audit_evidence) then
    raise exception 'SAC_BROKER_LEGACY_NOT_EMPTY';
  end if;
end $guard$;

revoke all on function public.sac_broker_v03_execute_canary(uuid,text,text,text,text,uuid,text,text,text)
  from public,anon,authenticated,service_role;
revoke insert,update,delete,truncate on sac_broker_v03.owner_keys,sac_broker_v03.node_keys,
  sac_broker_v03.proposals,sac_broker_v03.spent_grants,
  sac_broker_v03.executions,sac_broker_v03.audit_evidence from public,anon,authenticated,service_role;

do $check$
declare
  r text;
  t regclass;
  f oid:=pg_catalog.to_regprocedure('public.sac_broker_v03_execute_canary(uuid,text,text,text,text,uuid,text,text,text)');
begin
  foreach r in array array['anon','authenticated','service_role'] loop
    if pg_catalog.has_function_privilege(r,f,'EXECUTE') then
      raise exception 'SAC_BROKER_LEGACY_EXECUTE_STILL_GRANTED: %',r;
    end if;
    foreach t in array array['sac_broker_v03.owner_keys'::regclass,'sac_broker_v03.node_keys'::regclass,
      'sac_broker_v03.proposals'::regclass,'sac_broker_v03.spent_grants'::regclass,
      'sac_broker_v03.executions'::regclass,'sac_broker_v03.audit_evidence'::regclass] loop
      if pg_catalog.has_table_privilege(r,t,'INSERT,UPDATE,DELETE,TRUNCATE') then
        raise exception 'SAC_BROKER_LEGACY_WRITE_STILL_GRANTED: % %',r,t;
      end if;
    end loop;
  end loop;
end $check$;
commit;
