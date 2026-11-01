# SAC Mainframe Admin Console v1.2.0

Adds a **real public-source ingestion path** to the v1.1.0 deployed admin framework. Existing releases are preserved separately.

## Operations
- Live admin console: https://sac-mainframe-command-center.vercel.app/
- Vercel Authentication protects deployments; Supabase Auth email/password then verified TOTP AAL2 gates sensitive writes.
- Choose **Research evidence**, select one fixed Europe PMC topic, and **Fetch research metadata**. Up to four results from one API call, at most one attempt per topic and user per UTC hour. The server performs the fetch; the browser never supplies arbitrary URLs.
- New metadata is stored in `sac_connector_evidence_v1` with status `quarantined`, durable digest and source URL. A hash confirms normalized data integrity, **not** authenticity of the upstream publisher, validity of the paper, or any biological effect.
- Existing connector adapter registry and DAG federation evidence remain untouched.

## Tests
```
cd web
npm test
npm run check
node --check ../supabase/functions/sac-research-harvest-v1/index.js
```
The first 27 tests use mock network/identity data. They do not replace live owner AAL2 end-to-end testing, upstream uptime verification, a BFT run, or clinical/biological validation.

## Source and deployment
- `web/research/normalize.mjs`: allowlisted topics, bounded metadata normalization and canonicalization.
- `web/api/harvest.js`: strict method/auth/body validation and fixed Supabase Edge proxy.
- `supabase/functions/sac-research-harvest-v1/`: Deno Edge function, service-only trust boundary and ingest.
- `sql/002_public_research_ingest.sql`: additive RLS-locked table and connector metadata record.
- `web/test/research-feed.test.mjs`, `web/test/harvest-edge.test.mjs`: validation, denials, replay, and backend fixture cases.

No production keys, MFA enrollment QR, credentials, or third-party account passwords are distributed with the code. The deployed Vercel project already has its own publishable-key and project URL configuration; the privileged service-role key remains only on Supabase Edge. Do not put secrets into public or private Git repositories.

## Source reference
Europe PMC REST Web Service: https://dev.europepmc.org/RestfulWebService (provider documentation, metadata API).

## Remaining acceptance gates
- Vercel build and deployment for v1.2, production alias verification.
- Supabase Edge function active version and table RLS verification.
- Owner completes real TOTP registration and signs in to test the live AAL2 source fetch.
- Independently enrolled external provider identity and signed inference receipts to advance A2A beyond local test processes.