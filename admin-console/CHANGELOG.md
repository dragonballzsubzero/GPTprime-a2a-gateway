# SAC Mainframe Admin Console release history

## v1.2.0 — 2026-11-01
- Added fixed-topic Europe PMC public bibliographic retrieval: allotopic expression, mitochondrial import, endovascular BCI.
- Added `sac-research-harvest-v1` Deno Edge endpoint with verified Supabase Auth identity, enabled founder/admin allowlist, and mandatory AAL2 for retrieval writes.
- Added Postgres `sac_feed_claims_v1` per-actor/topic/hour anti-abuse gate and registered `europepmc` public metadata adapter.
- Added fixed-domain HTTPS retrieval, response size cap, normalized metadata-only payload, SHA-256 evidence digests, duplicate suppression, and quarantine-only insertion.
- Added Vercel server-side proxy `/api/harvest` and in-console manual pull control.
- Expanded local regression coverage from 14 to 27; synthetic fixtures do not count as real upstream/clinical validation.
- Retains v1.1 production and v0.33–v0.34.1 archive baselines unchanged; no new external login identities, tokens, or credential material.

## v1.1.0 — 2026-11-01
- MFA enrollment and verification (TOTP) client, backend read-only/gated evidence ingress.

## v1.0.0 — 2026-11-01
- Protected command center and JWT-guarded Supabase admin bridge.