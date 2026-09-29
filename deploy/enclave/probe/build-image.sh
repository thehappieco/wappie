#!/bin/sh
# Builds the A1 probe image (deploy/enclave/probe/Dockerfile.probe) from this
# checkout, in the order it layers: the reader image exactly as
# `make enclave-image` builds it (deploy/enclave/Dockerfile; its build markers
# stay, the probe never boots main.mjs for real), the jail check on top of it
# as check-image.sh --jail builds it (deploy/enclave/jailcheck, target
# `check`), then the probe. probe.sh runs this on the parent; it also serves a
# local smoke run (README.md). The two intermediate images keep their tags
# (<tag>-reader, <tag>-jailcheck) so a rebuild reuses their layers.
#
#   deploy/enclave/probe/build-image.sh <tag>
set -eu

tag=${1:?usage: build-image.sh <tag>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

arch=$(docker version --format '{{.Server.Arch}}')
[ "$arch" = arm64 ] || { echo "build-image.sh: the enclave is arm64; this Docker builds $arch" >&2; exit 1; }

# The commit's time, as make enclave-image passes it; any value builds.
epoch=$(git -C "$root" log -1 --format=%ct 2> /dev/null || date +%s)
rust_image=$(sed -n 's/^ARG RUST_IMAGE=//p' "$root/deploy/enclave/Dockerfile")
node_image=$(sed -n 's/^ARG NODE_IMAGE=//p' "$root/deploy/enclave/Dockerfile")

echo "build-image.sh: $tag-reader (deploy/enclave/Dockerfile)"
docker build -q -f "$root/deploy/enclave/Dockerfile" --build-arg SOURCE_DATE_EPOCH="$epoch" -t "$tag-reader" "$root" > /dev/null
echo "build-image.sh: $tag-jailcheck (deploy/enclave/jailcheck, target check)"
docker build -q -f "$root/deploy/enclave/jailcheck/Dockerfile" --target check --build-arg READER_IMAGE="$tag-reader" \
  --build-arg RUST_IMAGE="$rust_image" --build-arg NODE_IMAGE="$node_image" -t "$tag-jailcheck" "$root" > /dev/null
echo "build-image.sh: $tag (deploy/enclave/probe/Dockerfile.probe)"
docker build -q -f "$here/Dockerfile.probe" --build-arg JAILCHECK_IMAGE="$tag-jailcheck" \
  --build-arg RUST_IMAGE="$rust_image" -t "$tag" "$root" > /dev/null
echo "build-image.sh: $tag built"
