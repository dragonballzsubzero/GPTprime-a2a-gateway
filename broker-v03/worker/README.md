# Sandboxed file triage

A deliberately small static scanner. Run with `docker build -f broker-v03/worker/Dockerfile -t sac-broker-triage:v03 .` then `sh broker-v03/worker/run-isolated.sh <path>`. The shell wrapper forces no network, read-only filesystem, non-root UID, no privileges, pids/memory/CPU constraints and a read-only input mount.

**Not qualified:** container runtime image is not pinned to a verified immutable digest; seccomp/AppArmor profile, container escape testing, content disarm and reconstruction, authoritative PDF and Office renderer inspection, OCR, malware scanning, timeouts and a production artifact intake service are not provided. The scanner never executes or extracts archive members. All outputs remain untrusted.
