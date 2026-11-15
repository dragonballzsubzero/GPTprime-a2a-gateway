#!/usr/bin/env bash
# Functional checks of isolation flags on the CI Docker daemon. This is NOT a
# rootless-daemon qualification or a proof of resistance to container escape.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
work="${RUNNER_TEMP:?}/sac-triage-smoke"
mkdir -p "$work/intake"
mkdir -p "$work/staged"
chmod 755 "$work" "$work/intake"
chmod 700 "$work/staged"
printf 'inert test fixture\n' > "$work/intake/benign.txt"
chmod 644 "$work/intake/benign.txt"
python3 - "$work/intake/traversal.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1],'w') as z:
    z.writestr('../outside.txt','inert')
PY
chmod 644 "$work/intake/traversal.zip"
python3 -I -B broker-v04/worker/stage_input.py "$work/intake" "$work/intake/benign.txt" "$work/staged/benign"
python3 -I -B broker-v04/worker/stage_input.py "$work/intake" "$work/intake/traversal.zip" "$work/staged/traversal"
printf 'changed after staging\n' > "$work/intake/benign.txt"
docker pull python:3.13-slim
base=$(docker image inspect --format '{{index .RepoDigests 0}}' python:3.13-slim)
case "$base" in *@sha256:*) ;; *) echo 'Docker did not resolve a digest' >&2; exit 1;; esac
echo "Resolved smoke-test Python base: $base"
docker build --build-arg "BASE_IMAGE=$base" -f broker-v04/worker/Dockerfile -t sac-triage-ci:local .
args=(--rm --network=none --read-only --user=65534:65534 --cap-drop=ALL
      --security-opt=no-new-privileges --pids-limit=32 --memory=256m --memory-swap=256m
      --cpus=0.5 --ulimit nofile=64:64 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m)
benign=$(docker run "${args[@]}" --mount "type=bind,src=$work/staged/benign,dst=/input/item,readonly" sac-triage-ci:local /input/item)
python3 - "$benign" <<'PY'
import hashlib,json,sys
x=json.loads(sys.argv[1]); assert x['status']=='ADVISORY_ONLY' and x['format']=='utf8',x
assert x['sha256']==hashlib.sha256(b'inert test fixture\n').hexdigest(),x
print('PASS real container triages the original staged snapshot after intake changes')
PY
set +e
traversal=$(docker run "${args[@]}" --mount "type=bind,src=$work/staged/traversal,dst=/input/item,readonly" sac-triage-ci:local /input/item)
status=$?
set -e
test "$status" -eq 1
python3 - "$traversal" <<'PY'
import json,sys
x=json.loads(sys.argv[1]); assert x['status']=='REJECT' and x['reason']=='ZIP_PATH_TRAVERSAL',x
print('PASS real container rejects path-traversing ZIP metadata')
PY
docker run "${args[@]}" --mount "type=bind,src=$work/staged/benign,dst=/input/item,readonly" \
  --entrypoint python sac-triage-ci:local -I -c '
import os,socket
assert os.geteuid()==65534
with open("/proc/self/status") as f:
    assert next(x for x in f if x.startswith("CapEff:")).split()[1]=="0000000000000000"
for p in ("/etc/sac-ci-probe", "/input/item"):
    try:
        with open(p,"w") as f: f.write("blocked")
    except OSError: pass
    else: raise AssertionError("writable path: "+p)
s=socket.socket();s.settimeout(2)
try: s.connect(("1.1.1.1",443))
except OSError: pass
else: raise AssertionError("unexpected network connection")
finally: s.close()
print("PASS container UID, capabilities, read-only mounts and network smoke checks")
'
printf '{}' > "$work/seccomp.json"
if ! docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'; then
  set +e
  msg=$(SAC_TRIAGE_IMAGE="python@sha256:$(printf 'a%.0s' {1..64})" \
    SAC_SECCOMP_PROFILE="$work/seccomp.json" SAC_TRIAGE_INTAKE_ROOT="$work/intake" \
    sh broker-v04/worker/run-triage.sh "$work/intake/benign.txt" 2>&1)
  status=$?
  set -e
  test "$status" -ne 0
  case "$msg" in *'Rootless Docker is required'*) ;; *) echo "$msg" >&2; exit 1;; esac
  echo 'PASS wrapper denies the actual rootful CI daemon'
else
  echo 'Rootless daemon detected; rootless wrapper execution still requires a pinned built image and reviewed seccomp profile'
fi
