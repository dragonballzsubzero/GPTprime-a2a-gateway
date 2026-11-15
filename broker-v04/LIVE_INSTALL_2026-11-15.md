# Locked v0.4 function installation — 2026-11-15

The Supabase management API applied migration `20261115192002_sac_broker_v04_deny_all_install` to the connected project. The exact submitted `execute-canary.candidate.sql` bytes have SHA-256 `afc2ea4ef35d35c81f10c6597520948f660bb5ea64b48ac0a989cf5110d71427`. Its historical source header describes its status before installation.

Readback found `public.sac_broker_v04_execute_canary` owned by `postgres`, `SECURITY INVOKER`, with `search_path=pg_catalog`, function-definition MD5 `26dd97d8e73c63cd9a4e276164c62924` and ACL `{postgres=X/postgres}`. Effective execute checks were false for `PUBLIC`, `anon`, `authenticated`, and `service_role`. The migration refuses to overwrite a pre-existing function and asserts those denials before commit. Disposable PostgreSQL CI reproduced Supabase's default `service_role` function grant and verified it was removed.

At readback the live broker had zero active owner keys, zero active node keys and zero executions. The three existing preview identities remained revoked and quarantined. No runtime execution grant was made. This installation is not a production authorization boundary, does not independently verify signatures in PostgreSQL, and must remain locked until a separately reviewed admission and privilege design is deployed.
