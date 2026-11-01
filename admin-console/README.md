# SAC Mainframe Admin Console — v1.1.0

Deployed to the existing SAC Vercel team with deployment authentication set to **all**. The site is GitHub-backed and connects to a Supabase Edge Function. No secret credentials or signing keys are stored here.

## Production interface

`https://sac-mainframe-command-center.vercel.app/`

1. Sign in to Vercel with your existing permitted team account.
2. Sign in to the console with the existing, confirmed Supabase Auth account.
3. Under **Security & access**, enroll an app-authenticator (TOTP) or challenge an existing factor. The QR and manual secret are displayed in browser memory, never in source control. Verify to obtain an AAL2 JWT.
4. View live node readiness, provider blockers, deployment-stage metadata, connector registry, and the quarantined research evidence ledger.
5. Upload research metadata with founder/admin role + AAL2. Records are quarantined; cryptographic authenticity, external inference and scientific claims require separate independent acceptance tests.

## Implementation

- **Database**: additive `sql/001_admin_control_plane.sql`, plus a small subsequent FK-index migration. Tables `public.sac_console_admins_v1`, `sac_connector_registry_v1`, `sac_connector_evidence_v1`; all RLS-enabled and inaccessible to anon/authenticated Data API roles.
- **Edge**: `supabase/functions/sac-admin-bridge-v1`, verify_jwt=true, explicit founder allowlist and user Auth check. Privileged service-role key stays inside Supabase-managed Edge environment.
- **Site**: `web/` uses static HTML/CSS/JS and server-side Vercel function proxy with public publishable key only; no browser/service privileged secrets. CSP prohibits third-party scripts; Node 22.
- **Security**: short-lived bearer sessions in memory, TOTP verification before scientific record writes, read-only original SAC tables. The app protects page access at Vercel and API at Supabase.
- **Validation**: `cd web && npm test && npm run check` (14 local tests on Node 22.16); repeat in GitHub Actions. Database schema and deployment were independently read back through connected plugins. A complete authenticated end-to-end browser journey requires actual account-holder sign-in.

## Connector onboarding status

The 12 metadata adapters are registered in the database, not all authenticated as server-side runtime integrations. ChatGPT plugin access is not automatically transferable to the Vercel/Supabase app.

- Vercel, Supabase, GitHub: linked using existing user connectors.
- Consensus, TinyFish, Precise Special Functions, DataCamp: independent ChatGPT-side read pilots performed; metadata written as quarantined evidence, but server runtime credentials still unprovisioned.
- Coupler.io: workspace exists, no credentials/datasets. Connect your provider at https://app.coupler.io/app/source/connections/new . Do not paste access tokens into this chat.
- Life Science Research / Amass: usage quota exhausted until 2026-11-03; https://app.amass.tech/settings/subscription .
- Powerset Research: a connected search execution failed due to missing server-side `pytz` module; currently blocked.
- GPTPrime Evolution and SAC Mainframe Evolution: internal release and orchestration framework labels, not network credentials.

## Remaining production gates

AAL2 enrollment, authenticated console read test, provider/runtime-specific service auth, verified A2A cross-provider job, independently cryptographically signed inference receipts, controlled runtime deployment and rollbacks. Site readiness must not be confused with federation readiness.

## Preservation and credential policy

All mutations here are additive/versioned. The v0.33/v0.34 research source and earlier admin v1 files remain separately preserved. The project uses existing identities; **no new external accounts were created**. No passwords, refresh/access tokens, QR secrets, service-role credentials, recovery codes, or private keys are committed to any repository, including private repositories. Use Vercel/Supabase managed secrets and a separate secure password manager for credentials. Keep an account inventory containing nonsecret provider names, account purpose, approval status, connection timestamps, and vault reference IDs only.