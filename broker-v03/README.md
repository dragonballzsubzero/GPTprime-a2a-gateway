# SAC model-independent execution broker v0.3.0 — staged

Deployment target: existing Supabase project, function `sac-broker-v03` version 1. Existing gateway runtime is unchanged. No owner or node signing keys are enrolled.

## Security contract

1. Authenticated user JWT verified by Supabase Auth.
2. A2A identity must pass existing `gptprime_v19.a2a_current_trust_gate_v1`, including uncompromised key and owner enrollment.
3. Model-proposed action must carry a valid Ed25519 node signature over `sac.node-proposal.v3\\n` + recursively key-sorted JSON.
4. Owner must separately sign an exact-action grant over `sac.exact-action.v3\\n` + canonical grant fields, TTL <= 180 s.
5. Broker validates exact node, owner, run, proposal ID, digest, nonce and canary resource.
6. Single database transaction spends nonce and records approved canary side effect and pending audit receipt.
7. Audit status is PENDING_INDEPENDENT_RECONCILIATION until an independently operated verifier attests it.

## Endpoints

Supabase Edge base: `https://<project-ref>.supabase.co/functions/v1/sac-broker-v03`.
POST /propose accepts `{ action, node_kid, node_signature_b64url }` with owner Authorization JWT.
POST /execute adds `{ proposal_id, grant, owner_kid, grant_signature_b64url }` to the same signed action.
GET /status returns non-secret release state for an authenticated owner.

The *only executable effect* in this stage is `audit_canary` on `sac://broker/canary` with parameters `{tag: 'ASCII_1_TO_64'}`. This is a database-only canary, not provider inference, arbitrary egress, email, shell, repository or cloud write.

## Release gates

BLOCKED: all three pre-existing model identities are REVOKED/QUARANTINED and dispatch_authorized=false in the live gate. No signing keys configured. No external live-model evaluation or owner-approved action grant exists. Existing `api/dispatch.js` remains fail-closed.

## Remaining production qualification

Deploy hostile-document decoders in a separate network-disabled worker with bounded CPU/memory and no credentials. Provision offline/HSM-backed owner keys and independently attested node keys. Add a second independent audit log/reconciler, operational IAM separation, failover replay tests and a canary-only authorized live-model test. Merge only after review and CI.

This feature branch preserves existing repository files and archived baselines.
