# Vercel compatibility and commissioning runbook

Root issue: the three existing Vercel gateway projects use framework=express, but the source includes a native Node HTTP server in `src/server.mjs` and zero Express imports. Express detection fails at build.

Corrective configuration: project framework=null, Node.js 22.x, source root. The repository now includes `vercel.json` with no framework and `/api/*.js` Node.js functions. It does not substitute an ephemeral Vercel process memory for durable replay admission.

Acceptance stages:
1. GitHub CI: `npm run check`, `npm test`; all negative routes and replay tests pass.
2. Vercel preview (after quota permits): verify READY from exact source commit; keep Vercel Authentication=all.
3. Protected GET /api/health must return 200 and production_qualified:false; GET /api/ready must return 503; POST /api/dispatch must return 503. Test through authenticated `vercel curl`, not disable protection.
4. No real A2A effects until the signed v0.33 Supabase transport is bound to independently enrolled host-owned keys, issuer policy, a shared durable replay/lease store, current grants and metered provider evidence.
5. Release change must not silently elevate an index/debugger/transport health endpoint into provider execution authority.

Limitations: Vercel deployment quota previously returned 402 `api-deployments-free-per-day`; do not bypass quota or spend without owner confirmation. Every failed deploy must be recorded as a failure, not READY.