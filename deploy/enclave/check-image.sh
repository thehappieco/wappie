#!/bin/sh
# Static checks on a built reader image, run by CI and by build.sh before an
# EIF is made. Nothing here starts the reader: main.mjs is only parsed.
#   deploy/enclave/check-image.sh <image>
set -eu

image=${1:?usage: check-image.sh <image>}

# shellcheck disable=SC2016 # the script runs inside the image, not here.
docker run --rm --network none --entrypoint /bin/sh "$image" -c '
set -eu
fail() { echo "check-image: $*" >&2; exit 1; }

# Measured environment: NODE_ENV and what the base image sets, nothing that
# configures the reader (docs/mcp-enclave.md §10.1).
env | grep -q "^NODE_ENV=production$" || fail "NODE_ENV is not production"
if env | grep -E "^(WAPPIE|WS)_" > /dev/null; then fail "reader configuration in the environment"; fi

[ ! -e /var/log/apk.log ] || fail "/var/log/apk.log is in the image"
[ -x /entrypoint.sh ] || fail "no /entrypoint.sh"
sh -n /entrypoint.sh || fail "entrypoint.sh does not parse under the image shell"
command -v socat > /dev/null || fail "socat missing"
command -v ip > /dev/null || fail "ip missing"

# Outside an enclave there is no /dev/nsm: exit 2 proves the binary runs;
# bad arguments exit 3 before the device is touched.
rc=0; nsm-attest - - - > /dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "nsm-attest without /dev/nsm exited $rc, want 2"
rc=0; nsm-attest zz - - > /dev/null 2>&1 || rc=$?
[ "$rc" = 3 ] || fail "nsm-attest with a bad argument exited $rc, want 3"

cd /app/packages/mcp-http/enclave
[ -f main.mjs ] || fail "enclave app (main.mjs) is missing"
[ -f package-lock.json ] || fail "enclave lockfile is missing"
node --check main.mjs || fail "main.mjs does not parse"
# Every production dependency of the enclave package must import from here
# (catches a package whose runtime lives under a pruned src/), and so must the
# pure modules DEPLOY and the tests rely on.
node --input-type=module -e "
  import { readFileSync } from \"node:fs\"
  const deps = Object.keys(JSON.parse(readFileSync(\"package.json\", \"utf8\")).dependencies ?? {})
  for (const name of deps) await import(name)
  await import(\"./constants.mjs\")
  await import(\"./policy.mjs\")
  await import(\"@whatserver2/mcp\")
  console.log(\"imports ok: \" + (deps.join(\" \") || \"(no dependencies)\"))
"
[ -z "$(find /app -type l)" ] || fail "symlink under /app"
echo "check-image: ok"
'
