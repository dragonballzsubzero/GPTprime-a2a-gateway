# v0.4 qualification record

| Capability | Source | Local evidence | Remaining gate |
| --- | --- | --- | --- |
| Authenticated caller | Supabase Auth, signed AAL2 claims and existing owner/session/MFA-factor database gate, rechecked after audit | Mock Auth and gate responses; denial, outage, malformed-response and intervening revocation cases | Live signed-in session, actual factor/session revocation, cross-user and authentication-boundary testing; gate-to-commit race |
| Owner approval | Separate interactive signer; exact v0.4 grant | Real throwaway Ed25519 signatures, alteration and key-confusion denials | Trusted owner key enrollment and independently verified approval |
| Node proposal | Provider-neutral node identity and host signer | Real throwaway signatures; trust lookup fixtures | Separately enrolled identity and actual upstream gateway integration |
| Single canary effect | Strict schema and separate v0.4 transaction candidate | Fixture store plus CI workflow for isolated PostgreSQL and concurrent clients; inspect run results | SQL candidate not deployed; production trust gate, distributed replicas, commit ambiguity, coordinated quarantine races and privilege boundary remain unqualified |
| Independent audit | Signed intent/result and signed chain links, distinct audit key, fsync-backed single writer | Separate local process, restart, signature, interior-deletion, replay and result-failure tests | Independent operator, TLS/mTLS, immutable external storage, externally anchored head, backup and failure testing |
| Reconciliation | v2 observer verifies owner grant and independently supplied row; signed observation binds owner, proposal and grant; audit-only recovery never repeats effect | Synthetic source/observation, cross-grant, bad-signature and mismatch cases | Read-only external observer and source attestation not provisioned or evaluated |
| File processing | Rootless/network-denied Docker candidate, pinned image and reviewed seccomp required | Static worker fixtures, mocked CLI, and CI workflow for a real container on the runner daemon; inspect run results | Rootless production runtime, reviewed seccomp, hostile-document corpus, escape, time/memory and network-denial tests |
| Credential isolation | Private-file permissions; separate owner, node and auditor key roles | Wrong-mode, symlink, hardlink and signing-key tests | Process isolation, least-privilege database roles, rotation and trusted key custody not established |
| Model evaluation | Protocol makes no assumptions about model provider; pinned CPU smoke harness under `ci/broker-v04-model-eval` | Synthetic fixture proposals; inspect any bounded live-model job separately | Commissioned model/provider, owner-approved live canary and independently verifiable effect evidence |

The current live v0.3 deployment and database were inspected read-only. Its three existing preview identities remained revoked and quarantined, and zero owner/node keys were enrolled at the time of inspection. v0.4 has not been deployed; the new candidate does not confer any authority on those identities.

No automated check in this repository should promote the release to production. A reviewer must verify the deployed artifacts and all required independent evidence under the actual host and operator boundaries.
