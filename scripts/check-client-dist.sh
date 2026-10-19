#!/usr/bin/env bash
# The attested reader's image builds packages/client and measures what is
# left of it into PCR0 (deploy/enclave/Dockerfile: src/ and test/ pruned,
# *.ts and *.map deleted, the production dependencies from its lockfile).
# A change that moves those bytes needs a reader release, so this check
# refuses one: it builds packages/client at a baseline commit and in the
# working tree, and compares every file the image keeps, byte for byte.
# Type-only edits (a .d.ts differs) pass; a runtime one fails.
#
#   scripts/check-client-dist.sh [baseline]
#
# The baseline defaults to c9ec561, release A's merge (decision 0038), whose
# client the pilot's reader runs; release B changes no byte of it (the plan's
# DB18). The commit must be in the repository (CI fetches it).
set -euo pipefail

base=${1:-c9ec561ca2cc669cdec12d5d90523269c3c2396a}
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/base" "$work/head"

git -C "$root" cat-file -e "$base^{commit}" 2>/dev/null || {
	echo "check-client-dist: $base is not in this repository (git fetch origin $base)" >&2
	exit 2
}
git -C "$root" archive --format=tar "$base" packages/client | tar -x -C "$work/base"
# The working tree as it is, tracked and new files alike, never its
# node_modules or a dist built before.
(cd "$root" && git ls-files -z -co --exclude-standard -- packages/client) |
	(cd "$root" && tar --null -T - -cf -) | tar -x -C "$work/head"

sum() {
	if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# measured prints the sha256 of every file the image keeps, relative to the
# package: the build's output and the package's own files, not what npm
# installs (the lockfile, which is kept, fixes that).
measured() {
	(
		cd "$1/packages/client"
		npm ci --no-audit --no-fund --loglevel=error >/dev/null
		npm run --silent build >/dev/null
		find . -path ./node_modules -prune -o -type d \( -name src -o -name test \) -prune -o \
			-type f ! -name '*.ts' ! -name '*.map' -print | LC_ALL=C sort | while IFS= read -r f; do sum "$f"; done
	)
}

measured "$work/base" >"$work/base.sums"
measured "$work/head" >"$work/head.sums"
if ! diff -u "$work/base.sums" "$work/head.sums"; then
	echo "check-client-dist: packages/client's measured files differ from $base: the attested reader's PCR0 would move" >&2
	exit 1
fi
echo "check-client-dist: $(wc -l <"$work/head.sums" | tr -d ' ') measured files equal $base's"
