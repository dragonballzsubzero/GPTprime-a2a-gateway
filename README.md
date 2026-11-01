# SAC Gateway — v0.36.0 candidate (hosting & replay hardening)

This is an additive gateway compatibility release. **The operational API denies inference and dispatch** until real owner AAL2 commissioning, independent node enrollment, provider credentials, authenticated grants and a shared durable replay/lease backend are verified. A Vercel READY deployment does not establish live federation.

- Local native `src/server.mjs` and existing `0.34` integrity tests are preserved.
- `src/confidential-frame.mjs` implements candidate recipient encryption (X25519/HKDF-SHA256/AES-256-GCM) and Ed25519 signatures; decryption precedes the atomic replay claim and neither operation authorizes effects.
- `api/health.js`, `api/ready.js`, `api/dispatch.js` are non-Express Vercel Functions. They return explicit readiness/commissioning denials; these are NOT A2A v1 interoperability endpoints.
- `vercel.json` sets framework to null. The corresponding Vercel project framework preset must also be set to null; Node 22.x and SSO protection remain.
- Test commands: `npm run check && npm test`. Every gateway repo must pass hosted GitHub CI before merge.
- See `docs/VERCEL_HOSTING_RUNBOOK.md` and versioned changelog. Keep prior releases and private evidence archives untouched.

---

# SAC-A2A-TRANSPORT-1 v0.34.1 — executable integrity transport

**Status:** locally tested Node+Python signed integrity probe; **not production, provider inference, A2A 1.0 wire compatibility, or BFT consensus**.

This release hardens v0.33 without editing the v0.33 archival baseline. It replaces descriptive attestation acknowledgments with actual Ed25519-signed request/receipt bytes, enforces strict payload and timestamp checking, rejects duplicate/replayed nonces on disk, and gives independent cross-runtime signature validation.

## Requirements
Node.js >=22.16.0 <23; Python >=3.13 for cross-runtime verification; Python `cryptography>=43`. No Node npm dependencies.

## Test
```sh
npm test
npm run check
```

## Offline two-identity demo
```sh
mkdir -p .demo
node src/cli.mjs keygen .demo/alice
node src/cli.mjs keygen .demo/bob
python - <<'PY'
import json
from pathlib import Path
Path('.demo/trust.json').write_text(json.dumps({'alice.node':Path('.demo/alice/public.pem').read_text()}))
Path('.demo/payload.txt').write_text('hello SAC transport!\n')
PY
SAC_NODE_ID=bob.node SAC_PRIVATE_KEY_PATH=.demo/bob/private.pem \
SAC_TRUST_STORE_PATH=.demo/trust.json SAC_STATE_DIR=.demo/state \
SAC_BIND=127.0.0.1 SAC_PORT=8765 node src/server.mjs
# In another terminal:
node src/cli.mjs sign .demo/alice/private.pem alice.node bob.node .demo/payload.txt .demo/request.json
node src/cli.mjs verify .demo/trust.json .demo/request.json
node src/cli.mjs send http://127.0.0.1:8765/sac/v0.34/dispatch .demo/request.json
python scripts/verify_cross_runtime.py request .demo/trust.json .demo/request.json
```

**Security:** store private PEMs exclusively outside source control; never publish an endpoint without network authentication, mTLS/reverse-proxy hardening, rate limits, and centralized durable replay controls. The server binds to loopback by default. No automatic node enrollment or identity trust occurs. The `.demo/` path is gitignored.

## Contents
- `src/transport.mjs`: exact-byte request signing, verification, receipt signatures, nonce claims.
- `src/server.mjs`: loopback HTTP signed integrity probe.
- `src/cli.mjs`: create keys/sign/verify/send.
- `scripts/verify_cross_runtime.py`: Python independent Ed25519 verifier.
- `scripts/analyze_telemetry.py`: read-only monitoring analysis without false statistical independence.
- `scripts/demo_worker.mjs`: isolated subprocess node harness used by the three-process integration test.
- `src/evidence.mjs`: independent scientific metadata gate that cannot auto-promote biological or neural claims.
- `test/`: 23 executable tests, including three-process exchange and biology/BCI claim-gating regressions.
- `migrations/001_sac_transport_v034.sql`: additive, service-only, RLS-protected, append-only staging evidence table.
- `archive/v033/`: immutable copies of three supplied prior research artifacts.
- `docs/EVIDENCE_GATES.md`: acceptance criteria and non-claims.
- `docs/SCIENTIFIC_EVIDENCE_CONTRACT.md`: structured mitochondrial and neural research provenance gates.

## Version history
- v0.33 (archived): research audit and three expired pre-enrollment signature verifications.
- v0.34.0 (2026-11-01): Node signed integrity probe + independent Python verifier + replay persistence + 23 automated tests, including three isolated local Node processes and scientific evidence gates + additive staging schema design.