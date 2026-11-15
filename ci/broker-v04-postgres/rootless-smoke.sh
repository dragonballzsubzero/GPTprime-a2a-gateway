#!/usr/bin/env bash
# Test-only rootless daemon on a disposable GitHub-hosted runner. The seccomp
# profile below is deliberately incomplete and is NOT a production profile.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
sudo apt-get update -qq
sudo apt-get install -y -qq uidmap rootlesskit slirp4netns docker-ce-rootless-extras
if sysctl kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null
fi
if ! grep -q "^$(id -un):" /etc/subuid; then sudo usermod --add-subuids 100000-165535 "$(id -un)"; fi
if ! grep -q "^$(id -un):" /etc/subgid; then sudo usermod --add-subgids 100000-165535 "$(id -un)"; fi
export XDG_RUNTIME_DIR="${RUNNER_TEMP:?}/sac-rootless-runtime"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/docker.sock"
log="$RUNNER_TEMP/sac-rootless-dockerd.log"
dockerd-rootless.sh --host="$DOCKER_HOST" --data-root="$RUNNER_TEMP/sac-rootless-data" >"$log" 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true' EXIT
ready=0
for _ in $(seq 1 90); do
  if docker info >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$daemon" 2>/dev/null; then break; fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then cat "$log" >&2; exit 1; fi
docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'
echo 'PASS separate Docker daemon reports rootless mode'
docker pull python:3.13-slim
base=$(docker image inspect --format '{{index .RepoDigests 0}}' python:3.13-slim)
case "$base" in *@sha256:*) ;; *) exit 1;; esac
docker build --build-arg "BASE_IMAGE=$base" -f broker-v04/worker/Dockerfile -t localhost:5000/sac-triage:ci .
docker pull registry:2
docker run -d --network=host --name sac-test-registry registry:2 >/dev/null
pushed=0
for _ in $(seq 1 10); do
  if docker push localhost:5000/sac-triage:ci; then pushed=1; break; fi
  sleep 1
done
test "$pushed" -eq 1
image=$(docker image inspect --format '{{index .RepoDigests 0}}' localhost:5000/sac-triage:ci)
case "$image" in localhost:5000/sac-triage@sha256:*) ;; *) echo 'No immutable built-image digest' >&2; exit 1;; esac
work="$RUNNER_TEMP/sac-rootless-intake"
mkdir -p "$work"
printf 'rootless fixture\n' >"$work/sample.txt"
chmod 644 "$work/sample.txt"
profile="$RUNNER_TEMP/sac-ci-seccomp.json"
printf '%s\n' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace","mount","umount2","unshare","setns","bpf","keyctl"],"action":"SCMP_ACT_ERRNO"}]}' >"$profile"
report=$(SAC_TRIAGE_IMAGE="$image" SAC_SECCOMP_PROFILE="$profile" SAC_TRIAGE_INTAKE_ROOT="$work" \
  sh broker-v04/worker/run-triage.sh "$work/sample.txt")
python3 - "$report" <<'PY'
import hashlib,json,sys
x=json.loads(sys.argv[1]);assert x['status']=='ADVISORY_ONLY',x
assert x['sha256']==hashlib.sha256(b'rootless fixture\n').hexdigest(),x
print('PASS rootless wrapper stages and scans the pinned built image')
PY
python3 - "$work/traversal.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1],'w') as z:z.writestr('../outside','inert')
PY
chmod 644 "$work/traversal.zip"
set +e
report=$(SAC_TRIAGE_IMAGE="$image" SAC_SECCOMP_PROFILE="$profile" SAC_TRIAGE_INTAKE_ROOT="$work" \
  sh broker-v04/worker/run-triage.sh "$work/traversal.zip")
status=$?
set -e
test "$status" -eq 1
python3 - "$report" <<'PY'
import json,sys
x=json.loads(sys.argv[1]);assert x['status']=='REJECT' and x['reason']=='ZIP_PATH_TRAVERSAL',x
print('PASS rootless wrapper rejects a traversal archive with a failing status')
PY
echo 'CI-only seccomp profile and ephemeral host are not production qualification.'
