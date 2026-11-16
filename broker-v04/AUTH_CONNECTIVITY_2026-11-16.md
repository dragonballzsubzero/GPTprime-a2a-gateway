# Owner sign-in connectivity investigation

The owner console accepted a secure credential-submission flow on 2026-11-15, but displayed `Sign-in failed: signal timed out`. A subsequent console refresh reported `signedIn: false`. No password, one-time code, bearer token or email address is recorded here. This attempt did not establish an owner session or enroll a factor.

Supabase Auth logs recorded an HTTP 500 `unexpected_failure` for a password-grant request at **2026-11-15 23:59:27 UTC**, during the sign-in attempt. The associated error reported that a connection to the local PostgreSQL endpoint was canceled while dialing; the request duration was approximately 5.2 seconds. A request ID was not correlated, so the log entry is consistent with, but does not conclusively identify, the console failure. The logs do not establish whether the supplied credentials were correct. Other Auth 500/context-canceled events were recorded at **2026-11-15 03:51:21 UTC**, before either broker migration, but may have a different immediate cause.

The management API reported the project `ACTIVE_HEALTHY` and the health advisor returned no findings. Two read-only management SQL queries subsequently timed out; a later `SELECT 1` succeeded. One later PostgreSQL snapshot showed 15 of 60 connections, zero sessions waiting on a lock, and zero sessions owned by `supabase_auth_admin`. This single snapshot does not establish sustained capacity, root cause, or current Auth health. The observed behavior is intermittent; do not characterize the broker migrations or the submitted credentials as its proven cause.

The checked-in owner-console source at commit `0486319bd09dc6c51b147c80cfa680f3fd45a256` configures a 15-second bounded Auth fetch. No console source, Auth credentials, database passwords, service configuration, or project restart was changed during this investigation.

## Next diagnostic steps

1. Inspect Supabase Auth and PostgreSQL service-health and connection logs around the timestamps above, redacting user identifiers and secrets. Correlate request IDs and durations in the provider dashboard; distinguish cancellation caused upstream from database unavailability.
2. Check service health, connection-pool availability and recent provider incidents. A healthy management status or one successful SQL query is insufficient to establish the Auth path is healthy. Do not rotate database credentials, modify Auth schema privileges, or restart a shared production project without a specific diagnosis and impact assessment.
3. When the Auth service is responding, have the owner explicitly retry through the secure sign-in flow. Verify a real user session, enroll and verify MFA under owner control, and then independently verify owner binding. The broker remains locked until its separate admission and production gates pass.

The available evidence does not establish whether the database privilege changes contributed to this attempt's failure. The failure does not authorize creating keys or substituting a fixture approval.
