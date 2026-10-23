#!/bin/bash
# Linux Docker host only. Runtime has no external network connection.
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
IMAGE=sb4027-local-133601:repro
NAME=sb4027-local-133601-run
HOST_NETNS_ID=$(readlink /proc/self/ns/net)
if docker container inspect "$NAME" >/dev/null 2>&1; then
    printf 'Container %s already exists; refusing to reuse it.\n' "$NAME" >&2
    exit 1
fi
if [[ -d results && -n "$(find results -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    printf 'results/ is not empty; move the previous results before starting a new run.\n' >&2
    exit 1
fi
mkdir -p results
docker build --progress=plain --tag "$IMAGE" .
docker run --rm --name "$NAME" --label codex.lab=sb4027-local-133601 \
    --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    --sysctl net.ipv4.ip_forward=1 \
    --env "HOST_NETNS_ID=$HOST_NETNS_ID" \
    --mount "type=bind,source=$PWD/results,target=/results" \
    "$IMAGE"
printf 'Results: %s/results/summary.json\n' "$PWD"
