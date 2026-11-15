# v0.4 qualification record

| Capability | Source | Local evidence | Remaining gate |
| --- | --- | --- | --- |
| Authenticated caller | Supabase Auth adapter and AAL2 claim check | Mock Auth responses; denial, outage and malformed-response cases | Live signed-in session, active-factor/session revocation, cross-user and authentication-boundary testing |
| Owner approval | Separate interactive signer; exact v0.4 grant | Real throwaway Ed25519 signatures, alteration and key-confusion denials | Trusted owner key enrollment and independently verified approval |
| Node proposal | Provider-neutral node identity and host signer | Real throwaway signatures; trust lookup fixtures | Separately enrolled identity and actual upstream gateway integration |
| Single canary effect | Strict schema and separate v0.4 transaction candidate | Fixture store, replay and concurrency tests | SQL candidate not deployed or executed; distributed replay, commit ambiguity, key and quarantine races remain untested |
| Independent audit | Signed intent/result, distinct audit key, fsync-backed single writer | Separate local process, restart, signature, replay, tamper and result-failure tests | Independent operator, TLS/mTLS, immutable external storage, head anchoring, backup and failure testing |
| Reconciliation | Verifies matching intent/result and a separately signed observation against configured public keys | Synthetic observation and bad-signature/mismatch cases | Read-only external observer and source attestation not provisioned or evaluated |
| File processing | Rootless/network-denied Docker candidate, pinned image and reviewed seccomp required | Static worker fixtures and mocked Docker CLI arguments | Actual runtime, kernel, hostile-document, escape, time/memory and network-denial tests |
| Credential isolation | Private-file permissions; separate owner, node and auditor key roles | Wrong-mode, symlink, hardlink and signing-key tests | Process isolation, least-privilege database roles, rotation and trusted key custody not established |
| Model evaluation | Protocol makes no assumptions about model provider | Synthetic action proposals only | Controlled, authorized live-model test with independently verifiable provider and effect evidence |

The current live v0.3 deployment and database were inspected read-only. Its three existing preview identities remained revoked and quarantined, and zero owner/node keys were enrolled at the time of inspection. v0.4 has not been deployed; the new candidate does not confer any authority on those identities.

No automated check in this repository should promote the release to production. A reviewer must verify the deployed artifacts and all required independent evidence under the actual host and operator boundaries.
