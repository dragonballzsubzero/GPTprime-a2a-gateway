# SAC Admin Console Changelog

## v1.1.0 — 2026-11-01
- Added same-origin-protected admin dashboard with Supabase Auth user login and evidence ledger.
- Added self-service MFA TOTP enrollment, factor discovery, challenge and verification for AAL2-gated evidence writes; secret remains in volatile browser memory.
- Added independent `mfa-client.mjs` with 7 new negative/positive Node tests (14 total).
- Deployed new Edge Function v2 with recent evidence metadata and no direct browser DB access.
- Registered 12 connector input adapters; stored 4 quarantined pilot records; flagged Coupler, Amass and Powerset blockers.
- Applied FK evidence index performance correction.

## v1.0.0 — 2026-11-01
- Initial Vercel-protected admin site, secure proxy, allowlist-gated Supabase control-plane schema and evidence quarantine.
- Initial Edge Function v1 and 7 local tests.