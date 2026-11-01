-- Additive, staging-only ledger for SAC-A2A-TRANSPORT-1 v0.34.
-- Does NOT enroll nodes, grant provider credentials, execute inference, or authorize production.
-- Existing SAC tables and v0.33 files remain unchanged.
create table if not exists public.sac_transport_receipts_v034 (
  receipt_id uuid primary key default gen_random_uuid(),
  protocol text not null default 'SAC-A2A-TRANSPORT-1' check (protocol='SAC-A2A-TRANSPORT-1'),
  version text not null default '0.34' check (version='0.34'),
  node_id text not null check (node_id ~ '^[a-z][a-z0-9._-]{2,63}$'),
  sender_id text not null check (sender_id ~ '^[a-z][a-z0-9._-]{2,63}$'),
  message_id text not null check (message_id ~ '^[a-f0-9]{32}$'),
  nonce text not null check (nonce ~ '^[a-f0-9]{32}$'),
  request_sha256 text not null check (request_sha256 ~ '^[a-f0-9]{64}$'),
  result_sha256 text not null check (result_sha256 ~ '^[a-f0-9]{64}$'),
  signature_b64url text not null check (signature_b64url ~ '^[A-Za-z0-9_-]{86}$'),
  execution_class text not null check (execution_class='local_integrity_probe'),
  verification_state text not null default 'unverified' check (verification_state in ('unverified','server_verified')),
  verification_receipt_sha256 text check (verification_receipt_sha256 is null or verification_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  recorded_at timestamptz not null default now(),
  constraint sac_v034_unique_nonce unique (sender_id, nonce),
  constraint sac_v034_unique_request unique (request_sha256),
  constraint sac_v034_verified_provenance check (verification_state='unverified' or verification_receipt_sha256 is not null)
);
comment on table public.sac_transport_receipts_v034 is 'Staging signed integrity probe ledger; no inference/consensus/biology proof. Only trusted server may insert after offline signature verification. Append-only.';
alter table public.sac_transport_receipts_v034 enable row level security;
revoke all on table public.sac_transport_receipts_v034 from public, anon, authenticated;
grant select, insert on table public.sac_transport_receipts_v034 to service_role;

create or replace function public.sac_transport_receipts_v034_no_mutation()
returns trigger language plpgsql set search_path=pg_catalog as $$
begin
  raise exception 'SAC v0.34 evidence records are append-only';
end;
$$;
revoke all on function public.sac_transport_receipts_v034_no_mutation() from public, anon, authenticated;
drop trigger if exists sac_transport_receipts_v034_immutable on public.sac_transport_receipts_v034;
create trigger sac_transport_receipts_v034_immutable
before update or delete on public.sac_transport_receipts_v034
for each row execute function public.sac_transport_receipts_v034_no_mutation();

-- First release intentionally has no public SELECT/INSERT policy. The service
-- credential is server-only and must never be embedded in clients or uploaded.