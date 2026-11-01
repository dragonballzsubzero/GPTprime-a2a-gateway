# SAC v0.34 evidence gates

## Current release (verified locally)
- Node 22.16.0, Python 3.13.5; `npm test` passes 17 local integrity-probe regression tests, including a three-process cross-node round trip.
- Signed request, trust-store verification, canonical transport envelope, strict field set and times, exact payload digest, disk-backed atomic nonce claim, signed receipt, persisted receipt.
- Python validates Node-generated Ed25519 signatures independently.
- Historical v0.33 audit files are copied unchanged into `archive/v033`.

## Strict non-claims
- This is **not** official A2A 1.0 message/send compatibility; it is a SAC extension endpoint. A2A 1.0 adapter is a separate deliverable.
- No provider inference API, GPU/TEE attestation, multi-host identity attestation, BFT consensus, key rotation service, distributed ledger finality, or biological actuation is implemented.
- `healthz` means local listener health, not production qualification.
- The filesystem nonce store is intended for one node with shared persistent volume; multi-host deployments require transactional centralized nonce claims.
- `parseStrictWire` uses **Node-specific JSON canonical serialization**, not RFC 8785 JCS. An interoperable RFC 8785 implementation requires a separate audited canonicalizer.
- Signature verification establishes key consistency only. Trusted provider-to-key binding and secure custody remain independent obligations.
- No claim of zero latency, unbreakable encryption, absolute invisibility, or cryptographic nonrepudiation under key compromise.

## Promotion requirements
1. Owner-managed credential ceremony; separate, hardware-backed node keys; independently checked public-key binding.
2. Real provider credentials with metered model inference and separately collected provider receipt.
3. A2A 1.0 protocol adapter with authenticated task lifecycle and signed agent card per published spec.
4. Durable transactional replay nonce claims, multi-process locks, mTLS behind non-public ingress, request-size limits and rate limiting.
5. External verifier of receipt chain; negative tests including key compromise, revocation, duplicate keys and clock skew.
6. Fault-injected validator test with at least 3f+1 nodes for target BFT model; record finality proof separately.
7. Full CI and staging ingress deployment tests before any production promotion.
8. Distinct wet-lab/BCI experimental acquisition evidence for any biological or neural assertion.

## Biological/BCI evidence contract
Every biology or neural claim must reference separate `instrument_id`, `calibration_id`, `raw_data_sha256`, `sample_or_subject_scope`, `experimental_protocol_version`, `controls`, `blind_analysis_plan`, `effect_size`, `uncertainty_interval`, and `review_status`. Any missing essential field prevents promotion to 'validated'.