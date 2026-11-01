# SAC gateway additive changelog

## 0.36.0-candidate — 2026-11-01
- Replace incompatible Express deployment assumptions with standalone Vercel Node functions (`/api/health`, `/api/ready`, `/api/dispatch`) and `framework: null` manifest. Existing local Node server remains preserved.
- No public or session-coupled provider inference is enabled. `/api/dispatch` denies by construction until durable node identity, replay and effect grants are independently commissioned. All routes protected by existing Vercel Authentication settings.
- Fix validly signed but AEAD-invalid frame consuming a durable nonce before authentication. Move atomic replay claim after successful decryption but before release of plaintext; clear plaintext on claim failure. Regression retains original valid frame.
- Add local negative tests for all routes, nonce exhaustion attack and existing 0.35 and 0.34 tests. Source-only candidate awaiting provider/owner sign-in and production qualification.
- Preserve all previous releases as archived branches/artifacts, never rewrite history.