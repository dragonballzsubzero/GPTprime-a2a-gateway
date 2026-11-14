#!/bin/sh
set -eu
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then echo "usage: run-isolated.sh FILE" >&2; exit 2; fi
artifact="$(realpath -- "$1")"
docker run --rm --network none --read-only --cap-drop ALL \
 --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 \
 --user 65532:65532 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
 --mount "type=bind,source=$artifact,target=/input/artifact,readonly" \
 sac-broker-triage:v03
