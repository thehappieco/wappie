#!/bin/sh
# Traces what the workers do inside the jail over the whole corpus and prints
# it against media-jail/profiles/node-worker.txt (trace.mjs), for reviewing a
# profile change (docs/mcp-enclave.md §16.6: every added syscall is reviewed).
# Privileged, on an arm64 host with cgroup v2, like check-image.sh --jail.
#   deploy/enclave/jailcheck/trace-profile.sh <reader image>
set -eu

image=${1:?usage: trace-profile.sh <reader image>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
rust_image=${RUST_IMAGE:-$(sed -n 's/^ARG RUST_IMAGE=//p' "$here/../Dockerfile")}
node_image=${NODE_IMAGE:-$(sed -n 's/^ARG NODE_IMAGE=//p' "$here/../Dockerfile")}
tag=wappie-reader-jailcheck:trace-$$
trap 'docker rmi -f "$tag" > /dev/null 2>&1 || true' EXIT
docker build -q -f "$here/Dockerfile" --target trace --build-arg READER_IMAGE="$image" \
  --build-arg RUST_IMAGE="$rust_image" --build-arg NODE_IMAGE="$node_image" -t "$tag" "$root" > /dev/null
docker run --rm --privileged --cgroupns private --network none \
  -v "$root/deploy/enclave/media-jail/profiles/node-worker.txt:/opt/jailcheck/node-worker.txt:ro" \
  "$tag" trace
