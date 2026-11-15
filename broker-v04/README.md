# Model-independent execution broker v0.4 — review candidate

**Status: local tests only; not deployed and not production-qualified.** This is additive to `broker-v03` and does not enable `api/dispatch.js`. The only effect is the existing database-only `audit_canary`; arbitrary shell, network, file, repository and provider effects are not exposed.

## Flow

1. An independently enrolled adapter proposes a narrowly defined action. Its host-controlled signer signs the v0.3 node-proposal domain; the model supplies no key. `proposal-client.mjs` accepts an injected signing function and checks the result against the trusted node public key.
2. The broker authenticates the caller using Supabase Auth, requires signed AAL2 claims and the existing node/owner trust lookup, verifies the node signature and stores the proposal. Node names are not hardcoded to a model provider.
3. On a trusted owner machine, `owner-approve.mjs` displays the validated proposal and requires the owner to type `APPROVE ` followed by its exact action digest in a terminal. It creates a short-lived v0.4 grant bound to owner, node, run, action digest, proposal, nonce, both key IDs, broker audience and environment. Owner signing keys are never sent to the broker or model.
4. `/execute` rechecks the node signature and owner signature, action, scope and expiration. It requires an independent audit sink's **signed intent acknowledgment** before calling the v0.4 atomic canary RPC. The database candidate rechecks time, trusted key IDs, trust gate, stored proposal and unique owner/nonce in one transaction.
5. After an effect, the broker asks the audit sink to append a signed result. Missing result acknowledgments produce `EXECUTED_AUDIT_PENDING`; uncertain database outcomes produce `EXECUTION_OUTCOME_UNKNOWN_DO_NOT_RETRY`. Neither state authorizes retrying the effect. A separately signed observation can be checked with `reconcile.mjs`.

The protocol never treats matching hashes, a local test, an audit log entry or a signature alone as proof of an external effect, operator independence or actual provider inference.

## Included components

- `core.mjs`, `http.mjs`: authenticated, strictly shaped proposal and execution handling; compact JSON rejects duplicate-member ambiguity.
- `adapters.mjs`: Supabase Auth / existing v0.3 key and proposal RPC adapters plus a **v0.4-only** execution RPC adapter; HTTPS audit client. No fallback to the old execution RPC.
- `owner-approve.mjs`, `proposal-client.mjs`: independent owner signing on a trusted terminal and host-controlled node signing.
- `audit-ledger.mjs`, `audit-http.mjs`, `audit-main.mjs`: a separate single-writer, fsync-backed, signed, idempotent local audit process; a loopback HTTP service for a separately configured TLS boundary. The log is not immutable storage and lacks an externally anchored head.
- `reconcile.mjs`: verifies audit acknowledgments and a distinct signed observer statement against trusted keys supplied in a separate owner-controlled configuration file. A valid signature establishes an attestation, not the source's factual independence.
- `sql/execute-canary.candidate.sql`: transaction proposal only. It is not a Supabase migration and has not been applied or validated against PostgreSQL. It grants no runtime role. Use the current Supabase CLI to create and review a real migration before any database change.
- `worker/`: candidate rootless, offline, resource-limited triage wrapper with pinned image and explicit seccomp profile requirements. The wrapper has only been tested with a mocked Docker CLI; the actual runtime and isolation boundary have not been validated. The underlying v0.3 scanner remains advisory and does not render or sanitize documents.

## Local checks

```sh
npm test
npm run check
node --test test/broker-v04*.test.mjs
```

The tests use generated throwaway keys, synthetic auth and database fixtures, and a separately spawned **local** audit process. The replay concurrency test exercises a fixture store, not multiple PostgreSQL replicas. No external user, provider, owner signing key, live model or production system is invoked.

## Endpoint contracts

Run `broker-main.mjs` on an authorized trusted host after explicit provisioning. It binds loopback only; a separately managed ingress supplies TLS and network controls. `POST /propose` accepts compact JSON with exactly `action`, `node_kid`, and `node_signature_b64url`. After owner review, `POST /execute` requires those fields plus `proposal_id`, `grant`, `owner_kid`, and `grant_signature_b64url`. The caller passes its user JWT as `Authorization: Bearer <user-jwt>`; authentication is checked server-side. Neither the API nor the supplied client generates an owner approval.

For owner review, the owner supplies a compact JSON file containing exactly `action`, `action_digest`, `proposal_id`, `node_kid`, and `node_signature_b64url`; its trusted local configuration must point to independently provisioned owner and node public JWK files. `owner-approve.mjs` rejects non-interactive use and loads the owner private key only after the terminal confirmation. Audit/observer public keys and source allowlists used by `reconcile.mjs` must come from a **separate** owner-controlled file; never trust keys included in model-provided evidence.

Host configuration is explicit through `SAC_SUPABASE_ORIGIN`, `SAC_SUPABASE_ANON_KEY`, `SAC_SUPABASE_SERVICE_KEY_PATH`, `SAC_AUDIT_ORIGIN`, `SAC_AUDIT_TOKEN_PATH`, `SAC_AUDIT_SINK_ID`, `SAC_AUDIT_PUBLIC_JWK_PATH`, `SAC_BROKER_AUDIENCE` and `SAC_BROKER_ENVIRONMENT`. Secret files must be absolute, regular, single-link, owner-owned, and inaccessible to group/other users. The audit process has its own `SAC_AUDIT_DIR`, `SAC_AUDIT_PRIVATE_KEY_PATH`, and `SAC_AUDIT_TOKEN_PATH`. Configure distinct process identities, secrets and storage; the example alone does not establish separation.

## Release gates and limits

- The v0.4 RPC is intentionally **not installed** and has no execute grant. The adapter fails closed when it is absent. Existing v0.3 behavior, including its edge-only time/key checks, remains unchanged until separately reviewed and migrated.
- Transactional expiry and key-row rechecks in the SQL candidate require actual PostgreSQL testing. The candidate takes an advisory per-node admission lock, but quarantine/revocation writers must adopt the same lock and be tested for concurrent races. A check immediately before transaction return does not guarantee a commit-time wall-clock deadline.
- The current gateway uses a privileged service credential in its trusted process. Private-file controls reduce accidental exposure but do not provide least-privilege roles, a hardware security module, or isolation against a compromised broker. Supabase Auth `getUser` and signed AAL2 checks do not independently establish current session/factor revocation status.
- The SQL candidate uses `SECURITY INVOKER`; making it executable would require its caller to hold direct rights on the underlying tables. Those rights could bypass the intended function, so the candidate is **not a production authorization boundary**. Redesign and independently review database-side privilege separation and signature admission before granting execution or enabling effects.
- The audit process has a separate key and durable local log, but no external append-only or WORM sink, no external head anchoring, no multi-writer durability, and no independently operated observer is provisioned. A crash may leave a lock requiring deliberate operator recovery. Audit-result failure after an effect must be reconciled without resubmitting the grant.
- Actual rootless container execution, hostile-document tests, egress denial, credential boundaries, distributed replay races, backups, external reconciliation, owner enrollment, and controlled live-model evaluation remain required. The model provider, production configuration and existing quarantine state are unchanged by these source files.
