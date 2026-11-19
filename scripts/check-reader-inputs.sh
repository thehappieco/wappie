#!/usr/bin/env bash
# The attested reader's image measures more than packages/client's build
# (scripts/check-client-dist.sh checks that). deploy/enclave/Dockerfile
# copies packages/mcp and packages/mcp-http whole, prunes src/ and test/,
# deletes *.ts and *.map, and installs each package's production
# dependencies from its lockfile. It builds the attachment workers from
# their own files, and nsm-attest and media-jail from their Cargo files and
# sources. All of it goes into PCR0, built by the Dockerfile and build.sh
# (which writes the KMS key ARNs into constants.mjs), so those two are
# compared too. A change to any of these bytes needs a reader release.
# This check refuses one: it compares every such file at a
# baseline commit and in the working tree, byte for byte. No install is
# needed, since the lockfiles, which are compared, fix the dependencies, and
# the file: copies of packages/client and packages/mcp are covered by
# check-client-dist.sh and by the mcp files here.
#
#   scripts/check-reader-inputs.sh [baseline]
#
# The baseline defaults to f7babbe, main when this check began (2026-11-10).
# It is not the image the pilot runs. Main already differed there from release
# A's c9ec561 and from 2b540ba, which reader 0.6.0's measurements name:
# packages/mcp-http/enclave/main.mjs (711465a, a test seam for the
# challenge listener) and deploy/enclave/build.sh (91fab1d). The next reader
# release carries those. Move the baseline only with a reader release, or
# with a reason recorded in the commit that moves it. The commit must be in
# the repository (CI fetches it).
set -euo pipefail

base=${1:-f7babbeeb0a386981eee8d1cee5c2dd071a9d2df}
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/base" "$work/head"

# The paths the image takes, as the Dockerfile copies them. The workers'
# directory is removed from mcp-http's copy and built from its own files.
paths=(packages/mcp packages/mcp-http deploy/enclave)
worker=packages/mcp-http/enclave/media/worker
worker_files=("$worker/package.json" "$worker/package-lock.json" "$worker/image.mjs"
	"$worker/pdf.mjs" "$worker/office.mjs" "$worker/lib")
enclave_files=(deploy/enclave/Dockerfile deploy/enclave/build.sh deploy/enclave/entrypoint.sh
	deploy/enclave/nsm-attest/Cargo.toml deploy/enclave/nsm-attest/Cargo.lock deploy/enclave/nsm-attest/src
	deploy/enclave/media-jail/Cargo.toml deploy/enclave/media-jail/Cargo.lock deploy/enclave/media-jail/src
	deploy/enclave/media-jail/profiles)

git -C "$root" cat-file -e "$base^{commit}" 2>/dev/null || {
	echo "check-reader-inputs: $base is not in this repository (git fetch origin $base)" >&2
	exit 2
}
git -C "$root" archive --format=tar "$base" "${paths[@]}" | tar -x -C "$work/base"
# The working tree as it is, tracked and new files alike, never an install.
(cd "$root" && git ls-files -z -co --exclude-standard -- "${paths[@]}") |
	(cd "$root" && tar --null -T - -cf -) | tar -x -C "$work/head"

sum() {
	if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# measured prints the sha256 of every file the image takes from the tree.
measured() {
	(
		cd "$1"
		{
			for p in packages/mcp packages/mcp-http; do
				[ -d "$p" ] || continue
				find "$p" -path "$worker" -prune -o -type d \( -name src -o -name test -o -name node_modules \) -prune -o \
					-type f ! -name '*.ts' ! -name '*.map' -print
			done
			for f in "${worker_files[@]}" "${enclave_files[@]}"; do
				[ -e "$f" ] && find "$f" -type f -print
			done
		} | LC_ALL=C sort | while IFS= read -r f; do sum "$f"; done
	)
}

measured "$work/base" >"$work/base.sums"
measured "$work/head" >"$work/head.sums"
if ! diff -u "$work/base.sums" "$work/head.sums"; then
	echo "check-reader-inputs: the reader image's inputs differ from $base: the attested reader's PCR0 would move" >&2
	exit 1
fi
echo "check-reader-inputs: $(wc -l <"$work/head.sums" | tr -d ' ') measured files equal $base's"
