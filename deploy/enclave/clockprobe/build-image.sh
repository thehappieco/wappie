#!/bin/sh
# Builds the clock probe image (deploy/enclave/clockprobe/Dockerfile.clockprobe)
# from this checkout: first the reader image exactly as `make enclave-image`
# builds it (deploy/enclave/Dockerfile), tagged <tag>-reader, then the probe
# on top of it, tagged <tag>. clockprobe.sh runs this on the parent; it also
# serves a local smoke run (README.md). Never a release: the reader image's
# KMS markers stay, and the probe never starts main.mjs.
#
#   deploy/enclave/clockprobe/build-image.sh <tag>
set -eu

tag=${1:?usage: build-image.sh <tag>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

arch=$(docker version --format '{{.Server.Arch}}')
[ "$arch" = arm64 ] || { echo "build-image.sh: the enclave is arm64; this Docker builds $arch" >&2; exit 1; }

# The commit's time, as make enclave-image passes it; any value builds.
epoch=$(git -C "$root" log -1 --format=%ct 2> /dev/null || date +%s)
rust_image=$(sed -n 's/^ARG RUST_IMAGE=//p' "$root/deploy/enclave/Dockerfile")

echo "build-image.sh: $tag-reader (deploy/enclave/Dockerfile)"
docker build -q -f "$root/deploy/enclave/Dockerfile" --build-arg SOURCE_DATE_EPOCH="$epoch" -t "$tag-reader" "$root" > /dev/null
echo "build-image.sh: $tag (deploy/enclave/clockprobe/Dockerfile.clockprobe)"
docker build -q -f "$here/Dockerfile.clockprobe" --build-arg READER_IMAGE="$tag-reader" \
  --build-arg RUST_IMAGE="$rust_image" -t "$tag" "$root" > /dev/null
echo "build-image.sh: $tag built"
