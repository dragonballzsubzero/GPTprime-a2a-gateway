#!/bin/sh
# Local staging candidate. Host/daemon, profile, image and namespace isolation
# must be independently verified before production use.
set -eu
if [ "$#" -ne 1 ]; then echo 'Usage: run-triage.sh <absolute-input-file>' >&2; exit 2; fi
: "${SAC_TRIAGE_IMAGE:?Set an immutable image reference}"
: "${SAC_SECCOMP_PROFILE:?Set an absolute reviewed seccomp profile}"
: "${SAC_TRIAGE_INTAKE_ROOT:?Set a host-controlled absolute intake directory}"
input=$1
case "$input" in /*) ;; *) echo 'Input must be absolute' >&2; exit 2;; esac
case "$input" in *','*|*'
'*) echo 'Unsupported input path' >&2; exit 2;; esac
case "$SAC_SECCOMP_PROFILE" in /*) ;; *) echo 'Seccomp profile must be absolute' >&2; exit 2;; esac
case "$SAC_TRIAGE_INTAKE_ROOT" in /*) ;; *) echo 'Intake root must be absolute' >&2; exit 2;; esac
if [ -L "$input" ] || [ ! -f "$input" ] || [ -L "$SAC_SECCOMP_PROFILE" ] || [ ! -f "$SAC_SECCOMP_PROFILE" ]; then
  echo 'Input and seccomp profile must be regular, non-symlink files' >&2; exit 2
fi
intake=$(realpath -e -- "$SAC_TRIAGE_INTAKE_ROOT")
resolved=$(realpath -e -- "$input")
case "$resolved" in "$intake"/*) ;; *) echo 'Input is outside the intake root' >&2; exit 2;; esac
if [ "$resolved" != "$input" ]; then echo 'Input path must be canonical with no symlink components' >&2; exit 2; fi
if ! printf '%s\n' "$SAC_TRIAGE_IMAGE" | grep -Eq '^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$'; then
  echo 'A sha256-pinned image reference is required' >&2; exit 2
fi
if ! docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'; then
  echo 'Rootless Docker is required for this staging profile' >&2; exit 2
fi
exec timeout --kill-after=3s 30s docker run --rm --pull=never --network=none \
  --read-only --user=65534:65534 --cap-drop=ALL --security-opt=no-new-privileges \
  --security-opt "seccomp=$SAC_SECCOMP_PROFILE" --pids-limit=32 --memory=256m \
  --memory-swap=256m --cpus=0.5 --ulimit nofile=64:64 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount "type=bind,src=$input,dst=/input/item,readonly" \
  "$SAC_TRIAGE_IMAGE" /input/item
