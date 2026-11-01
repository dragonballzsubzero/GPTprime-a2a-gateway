# SAC Independent-Node Compatibility Candidate v0.35

This package adds **local software tests**, not activated model providers or a production rollout.

- `src/confidential-frame.mjs`: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM confidential frame, Ed25519 sender signature, nonce, short expiry, recipient/capability/policy binding. Requires trusted external sender/receiver key pins and durable nonce admission; does not establish HPKE interoperability, TLS/mTLS, model execution, or federation authority.
- `src/release-gates.mjs`: a fail-closed evidence classification helper. Even if a record claims external verification, this helper never grants dispatch or production qualification, because signed external appraisals are a separate trust boundary.
- `test/confidential-*.test.mjs`, `test/release-gates.test.mjs`: malicious edit, wrong key, stale policy, recipient, replay, timeout, 100 independent **software key** fixtures, 720 deterministic mutation attempts and failure labels.
- Owner console `architecture/assess.mjs` is a read-only view on authenticated backend state; its estimates do not confer authorization.

Do not send keys in prompts, commit private secrets or enable model provider actions merely because the tests pass. Preserve earlier source code, old transport versions, quarantine and revocation controls. Real provider identity, owner AAL2, budget, enrollment and externally metered signed inference remain commissioning prerequisites.