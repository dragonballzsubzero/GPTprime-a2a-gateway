# SAC-A2A-TRANSPORT-1 version history

## v0.34.1 — 2026-11-01
- Add `src/evidence.mjs` as a strict provenance-only mitochondrial/BCI research metadata gate.
- Add six positive and negative verification tests in `test/evidence.test.mjs` (23 total tests).
- Add `docs/SCIENTIFIC_EVIDENCE_CONTRACT.md` identifying research promotion prerequisites and validation limits.
- Preserve transport wire protocol 0.34 and nonbreaking staging table `sac_transport_receipts_v034`.
- Preserve prior v0.34.0 release ZIP as separate Library artifact, with hash.

## v0.34.0 — 2026-11-01
- Implement signer-bound request and receipt hashing using Ed25519 and exact delimiter-safe input.
- Add strict Node transport wire parsing, timestamp and payload limits, replay nonce persistence, and loopback HTTP exchange.
- Add Python 3.13 independent signature validator, 17 passing Node/Python regression tests including a three-process loopback exchange.
- Apply additive staging-only Supabase migration with RLS and immutable evidence trigger. No provider credentials, identities, or production promotion.
- Publish identical transport source to GPTPrime, GeminiPrime and LlamaPrime gateway repositories.

## v0.33 — archived research baseline
- Research audit and legacy pre-enrollment signature verification scripts copied unchanged, identified by SHA-256 in release manifest.
- These archival artifacts are evidence snapshots, not activated production code.