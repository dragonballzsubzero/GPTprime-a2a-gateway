-- SAC Console 1.2 / public research adapter. Additive; existing data preserved.
-- An integration record != an active provider credential or validated science.
INSERT INTO public.sac_connector_registry_v1(connector_id,display_name,purpose,access_surface,state,adapter_class,account_scope,evidence)
VALUES ('europepmc','Europe PMC (public literature index)','Bounded bibliographic searches for mitochondrial/BCI work','third_party','registered','public_https_feed','public_source_no_login',
'{"source":"https://www.ebi.ac.uk/europepmc/webservices/rest/search","auth":"none","contract":"public metadata only; AAL2 owner invocation","assurance":"quarantined until independent review"}'::jsonb)
ON CONFLICT(connector_id) DO NOTHING;
CREATE TABLE IF NOT EXISTS public.sac_feed_claims_v1 (
 claim_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 actor_id uuid NOT NULL REFERENCES auth.users(id),
 topic text NOT NULL CHECK(topic IN ('mitochondrial_allotopy','mitochondrial_import','endovascular_bci')),
 hour_bucket timestamptz NOT NULL,
 claimed_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT sac_feed_claim_rate UNIQUE(actor_id,topic,hour_bucket)
);
ALTER TABLE public.sac_feed_claims_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sac_feed_claims_v1 FROM PUBLIC,anon,authenticated;
GRANT SELECT,INSERT ON public.sac_feed_claims_v1 TO service_role;
COMMENT ON TABLE public.sac_feed_claims_v1 IS 'AAL2 admin hourly topic claims, append-only; no provider passwords or API tokens.';
CREATE OR REPLACE FUNCTION public.sac_feed_claim_immutable_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'SAC feed claims are append-only'; END; $$;
REVOKE ALL ON FUNCTION public.sac_feed_claim_immutable_v1() FROM PUBLIC,anon,authenticated;
DROP TRIGGER IF EXISTS sac_feed_claim_immutable_trigger_v1 ON public.sac_feed_claims_v1;
CREATE TRIGGER sac_feed_claim_immutable_trigger_v1 BEFORE UPDATE OR DELETE ON public.sac_feed_claims_v1
FOR EACH ROW EXECUTE FUNCTION public.sac_feed_claim_immutable_v1();