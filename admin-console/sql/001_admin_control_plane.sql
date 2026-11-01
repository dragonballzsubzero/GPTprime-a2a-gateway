-- SAC Mainframe Admin Control Plane 1.0
-- Additive only; legacy tables untouched. No credentials or personal email fields.
CREATE TABLE IF NOT EXISTS public.sac_console_admins_v1 (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('founder','admin','viewer')),
  enabled boolean NOT NULL DEFAULT true,
  granted_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.sac_console_admins_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sac_console_admins_v1 FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.sac_console_admins_v1 TO service_role;
COMMENT ON TABLE public.sac_console_admins_v1 IS 'Privileged access allowlist; no browser direct-access policies.';

-- Bootstrap only the single existing confirmed-email account, and only as
-- a read-only, MFA-gated-write founder principal. No email/password in this table.
INSERT INTO public.sac_console_admins_v1 (user_id,role)
SELECT id,'founder' FROM auth.users
WHERE email_confirmed_at IS NOT NULL
  AND (SELECT count(*) FROM auth.users)=1
ON CONFLICT (user_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.sac_connector_registry_v1 (
 connector_id text PRIMARY KEY CHECK (connector_id ~ '^[a-z][a-z0-9_-]{1,63}$'),
 display_name text NOT NULL,
 purpose text NOT NULL,
 access_surface text NOT NULL CHECK (access_surface IN ('vercel','supabase','github','chatgpt_connector','internal_framework','third_party')),
 state text NOT NULL CHECK (state IN ('connected','registered','needs_connection','needs_service_auth','unavailable','blocked')),
 adapter_class text NOT NULL,
 account_scope text,
 credential_ref text,
 evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
 last_verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.sac_connector_registry_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sac_connector_registry_v1 FROM PUBLIC, anon, authenticated;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.sac_connector_registry_v1 TO service_role;
COMMENT ON TABLE public.sac_connector_registry_v1 IS 'Metadata-only connector ledger; secret values prohibited. ChatGPT connector access does not imply external API authorization.';

CREATE TABLE IF NOT EXISTS public.sac_connector_evidence_v1 (
 evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 connector_id text NOT NULL REFERENCES public.sac_connector_registry_v1(connector_id),
 record_type text NOT NULL CHECK (record_type IN ('paper','technical_reference','provider_status','operational_observation','research_note')),
 source_url text,
 observed_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 payload jsonb NOT NULL,
 payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
 provenance_status text NOT NULL DEFAULT 'quarantined' CHECK (provenance_status IN ('quarantined','verified','rejected')),
 created_by uuid REFERENCES auth.users(id),
 CONSTRAINT sac_evidence_connector_digest_uk UNIQUE(connector_id,payload_sha256),
 CONSTRAINT sac_evidence_url_scheme CHECK(source_url IS NULL OR source_url ~ '^https://')
);
ALTER TABLE public.sac_connector_evidence_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sac_connector_evidence_v1 FROM PUBLIC, anon, authenticated;
GRANT SELECT,INSERT ON public.sac_connector_evidence_v1 TO service_role;
CREATE INDEX IF NOT EXISTS sac_connector_evidence_recency_idx ON public.sac_connector_evidence_v1(received_at DESC);
COMMENT ON TABLE public.sac_connector_evidence_v1 IS 'Evidence ingress quarantine. Hashes and records are not signed source authenticity claims. Never store credentials, PHI, or secrets.';

-- Audit-only trigger: enforce append-only at database level for evidence records.
CREATE OR REPLACE FUNCTION public.sac_connector_evidence_immutable_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'SAC evidence is append-only';
END;
$$;
REVOKE ALL ON FUNCTION public.sac_connector_evidence_immutable_v1() FROM PUBLIC, anon, authenticated;
DROP TRIGGER IF EXISTS sac_connector_evidence_immutable_trigger_v1 ON public.sac_connector_evidence_v1;
CREATE TRIGGER sac_connector_evidence_immutable_trigger_v1
BEFORE UPDATE OR DELETE ON public.sac_connector_evidence_v1
FOR EACH ROW EXECUTE FUNCTION public.sac_connector_evidence_immutable_v1();

INSERT INTO public.sac_connector_registry_v1(connector_id,display_name,purpose,access_surface,state,adapter_class,account_scope,evidence,last_verified_at)
VALUES
('vercel','Vercel','Protected site hosting and deployment logs','vercel','connected','deployment','existing_team','{"verified":"connected_team"}',now()),
('supabase','Supabase','Auth, database, edge functions, evidence ledger','supabase','connected','backend','existing_project','{"project_ref":"lhezpozllgszjbrnpqoi"}',now()),
('github','GitHub','Version-controlled gateway and admin interface','github','connected','source_control','existing_account','{"repo_visibility":"mixed"}',now()),
('coupler','Coupler.io','ETL, dataset import/export, analytics feeds','chatgpt_connector','needs_connection','etl','workspace_264267','{"credential_count":0,"datasets":0}',now()),
('tinyfish','TinyFish','Source research / approved browser workflow','chatgpt_connector','needs_service_auth','research_adapter','chatgpt_session','{"backend_api_credentials":"not_transferred"}',now()),
('consensus','Consensus','Academic source discovery and peer-reviewed evidence','chatgpt_connector','needs_service_auth','research_adapter','chatgpt_session','{"backend_api_credentials":"not_transferred"}',now()),
('lifescience','Life Science Research','Biomedical publications and evidence','chatgpt_connector','needs_service_auth','research_adapter','chatgpt_session','{"backend_api_credentials":"not_transferred"}',now()),
('powerset','Powerset Research','Technical analytics and repository research','chatgpt_connector','needs_service_auth','research_adapter','chatgpt_session','{"backend_api_credentials":"not_transferred"}',now()),
('precise_math','Precise Special Functions','Independent specialist numerical calculations','chatgpt_connector','needs_service_auth','computation_adapter','chatgpt_session','{"backend_api_credentials":"not_transferred"}',now()),
('datacamp','DataCamp','Engineering learning and training content','chatgpt_connector','needs_service_auth','knowledge_adapter','chatgpt_session','{"backend_api_credentials":"not_transferred"}',now()),
('gptprime_evolution','GPTPrime Evolution','Local framework and release lifecycle','internal_framework','registered','framework','SAC_Mainframe','{"current_release":"0.34.1"}',now()),
('sac_mainframe_evolution','SAC Mainframe Evolution','Node orchestration and release lifecycle','internal_framework','registered','framework','SAC_Mainframe','{"state":"preproduction"}',now())
ON CONFLICT(connector_id) DO NOTHING;