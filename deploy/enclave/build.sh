#!/bin/bash
# Builds one reader release on an arm64 host with Docker and nitro-cli (the
# parent): the image, its EIF, the two rendered key policies and their hashes,
# and measurements.json (docs/mcp-enclave.md §9). Publishing is separate:
# pass --push to push the image (the digest then goes into measurements.json);
# the GitHub release reader-v<version> is created by hand from the output
# directory (commercial/docs/mcp-enclave-operations.md, "Release").
#
#   deploy/enclave/build.sh [--push] [--previous-pcr0 HEX] [--owner-arn ARN ...] [--out DIR]
#
# --previous-pcr0 is the PCR0 of the release now in production; the
# transition policy pins it and this one. Without it (the first release) the
# transition policy equals the steady one.
# --owner-arn (repeatable) names the principals the key policies let
# administer the keys and encrypt the relay secret (kms/render.py); the
# default is the account root. They are in the published policy, so every
# release must pass the same ones, or the policy hash changes.
#
# Environment (defaults in brackets):
#   KMS_READER_KEY_ARN, KMS_BOOT_KEY_ARN  required: the two keys by key-id ARN.
#                    The public constants.mjs carries markers for them; the
#                    build context gets the real values, so they are measured.
#   PARENT_ROLE_ARN  [arn:aws:iam::768406580484:role/wappie-enclave-spike-parent]
#                    PCR3 measures it, so it flows into both policies.
#   IMAGE_REPO       [ghcr.io/thehappieco/wappie-reader]
#   NODE_IMAGE, RUST_IMAGE  override the Dockerfile's pinned digests.
#   ALLOW_DIRTY=1    build from a tree with uncommitted changes (never with --push).
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
here=$root/deploy/enclave
push=0
previous=""
out=""
owners=()
while [ $# -gt 0 ]; do
  case "$1" in
    --push) push=1 ;;
    --previous-pcr0) previous=${2:?--previous-pcr0 needs a value}; shift ;;
    --owner-arn) owners+=(--owner-arn "${2:?--owner-arn needs an ARN}"); shift ;;
    --out) out=${2:?--out needs a directory}; shift ;;
    *) echo "usage: build.sh [--push] [--previous-pcr0 HEX] [--owner-arn ARN ...] [--out DIR]" >&2; exit 2 ;;
  esac
  shift
done

PARENT_ROLE_ARN=${PARENT_ROLE_ARN:-arn:aws:iam::768406580484:role/wappie-enclave-spike-parent}
IMAGE_REPO=${IMAGE_REPO:-ghcr.io/thehappieco/wappie-reader}
# Run Command shells and plain SSH sessions do not source nitro-cli's profile
# script (spike, Day 1: E51 without these).
export NITRO_CLI_ARTIFACTS=${NITRO_CLI_ARTIFACTS:-/var/lib/nitro_enclaves/artifacts}
export NITRO_CLI_BLOBS=${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs/}

die() { echo "build.sh: $*" >&2; exit 1; }
# Key ids, never aliases: an UpdateAlias would swap the key under the image.
key_arn='^arn:aws:kms:eu-west-1:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

[ "$(uname -m)" = aarch64 ] || die "build on arm64 (the parent is Graviton); this host is $(uname -m)"
command -v nitro-cli > /dev/null || die "nitro-cli is not installed"
command -v docker > /dev/null || die "docker is not installed"
if [ -n "$previous" ] && ! [[ "$previous" =~ ^[0-9a-f]{96}$ ]]; then
  die "--previous-pcr0 must be 96 lowercase hex characters"
fi
reader_key=${KMS_READER_KEY_ARN:?set KMS_READER_KEY_ARN (the wappie-mcp-reader key, by key id)}
boot_key=${KMS_BOOT_KEY_ARN:?set KMS_BOOT_KEY_ARN (the wappie-mcp-boot key, by key id)}
[[ "$reader_key" =~ $key_arn ]] || die "KMS_READER_KEY_ARN must be an eu-west-1 key-id ARN"
[[ "$boot_key" =~ $key_arn ]] || die "KMS_BOOT_KEY_ARN must be an eu-west-1 key-id ARN"
[ "$reader_key" != "$boot_key" ] || die "the reader and boot keys must differ"

commit=$(git -C "$root" rev-parse HEAD)
if [ -n "$(git -C "$root" status --porcelain)" ]; then
  [ "${ALLOW_DIRTY:-0}" = 1 ] || die "uncommitted changes; a release is built from a commit"
  [ "$push" = 0 ] || die "--push needs a clean tree"
fi
# The commit time, so two builds of one commit clamp to the same file times.
sde=$(git -C "$root" log -1 --format=%ct)

pinned() { sed -n "s/^ARG $1=//p" "$here/Dockerfile"; }
node_image=${NODE_IMAGE:-$(pinned NODE_IMAGE)}
rust_image=${RUST_IMAGE:-$(pinned RUST_IMAGE)}
for ref in "$node_image" "$rust_image"; do
  [[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || die "base image not pinned by digest: $ref"
done

# The build context is the commit (plus, with ALLOW_DIRTY, the uncommitted
# files git knows or would add), never stray local files, with the two key
# ARNs written into constants.mjs.
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
if [ -z "$(git -C "$root" status --porcelain)" ]; then
  git -C "$root" archive --format=tar HEAD | tar -xf - -C "$context"
else
  # Tracked files deleted in the tree are skipped (tar would stop on them).
  (cd "$root" && git ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' f; do [ ! -e "$f" ] || printf '%s\0' "$f"; done \
    | tar --null -T - -cf -) | tar -xf - -C "$context"
fi
python3 - "$context/packages/mcp-http/enclave/constants.mjs" "$reader_key" "$boot_key" <<'PY'
import pathlib, sys
path, reader, boot = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
text = path.read_text()
for marker, value in (("'@@KMS_READER_KEY_ARN@@'", reader), ("'@@KMS_BOOT_KEY_ARN@@'", boot)):
    if text.count(marker) != 1:
        sys.exit(f"build.sh: expected one {marker} in constants.mjs")
    text = text.replace(marker, "'" + value + "'")
path.write_text(text)
PY
! grep -q "'@@KMS_" "$context/packages/mcp-http/enclave/constants.mjs" || die "a KMS marker survived in constants.mjs"

tag=wappie-reader:${commit:0:12}
docker build -f "$context/deploy/enclave/Dockerfile" \
  --build-arg NODE_IMAGE="$node_image" --build-arg RUST_IMAGE="$rust_image" \
  --build-arg SOURCE_DATE_EPOCH="$sde" -t "$tag" "$context"
sh "$here/check-image.sh" "$tag"

# The image's own constants, read by the code that will run with them.
constants=$(docker run --rm --network none --entrypoint node -w /app/packages/mcp-http/enclave "$tag" \
  --input-type=module -e '
    const c = await import("./constants.mjs")
    console.log(JSON.stringify({ version: c.READER_VERSION, reader_id: c.READER_ID, origin: c.PUBLIC_ORIGIN,
      region: c.REGION, reader_key_arn: c.KMS_READER_KEY_ARN, boot_key_arn: c.KMS_BOOT_KEY_ARN }))')
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$constants" "$1"; }
version=$(field version)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "READER_VERSION is not x.y.z: $version"
[ "$(field reader_id)" = enclave ] || die "READER_ID is not enclave"
[ "$(field reader_key_arn)" = "$reader_key" ] || die "the image's reader key ARN is not the one given"
[ "$(field boot_key_arn)" = "$boot_key" ] || die "the image's boot key ARN is not the one given"

out=${out:-$root/dist/reader-$version}
[ ! -e "$out" ] || die "$out exists; keep each release's output, choose another --out"
mkdir -p "$out"
eif=wappie-reader-$version.eif
nitro-cli build-enclave --docker-uri "$tag" --output-file "$out/$eif" > "$out/build-enclave.json"
pcr() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"]["PCR" + sys.argv[2]])' "$out/build-enclave.json" "$1"; }
pcr0=$(pcr 0)
[[ "$pcr0" =~ ^[0-9a-f]{96}$ ]] || die "unexpected PCR0 from nitro-cli: $pcr0"

render() { python3 "$here/kms/render.py" "$1" --role-arn "$PARENT_ROLE_ARN" ${owners[@]+"${owners[@]}"} "${@:2}"; }
transition=(--pcr0 "$pcr0")
[ -z "$previous" ] || transition=(--pcr0 "$previous" --pcr0 "$pcr0")
render "$here/kms/reader-key-policy.template.json" "${transition[@]}" > "$out/reader-key-policy.transition.json"
render "$here/kms/reader-key-policy.template.json" --pcr0 "$pcr0" > "$out/reader-key-policy.steady.json"
render "$here/kms/boot-key-policy.template.json" "${transition[@]}" > "$out/boot-key-policy.transition.json"
render "$here/kms/boot-key-policy.template.json" --pcr0 "$pcr0" > "$out/boot-key-policy.steady.json"
# policy.mjs from the image is the one canonical form (§7); only the reader
# key's policy is hashed and published.
policy_hash() {
  docker run --rm -i --network none --entrypoint node "$tag" /app/packages/mcp-http/enclave/policy.mjs < "$1"
}
transition_sha=$(policy_hash "$out/reader-key-policy.transition.json")
steady_sha=$(policy_hash "$out/reader-key-policy.steady.json")
for h in "$transition_sha" "$steady_sha"; do
  [[ "$h" =~ ^[0-9a-f]{64}$ ]] || die "policy.mjs printed no hash: $h"
done

reference=""
if [ "$push" = 1 ]; then
  docker tag "$tag" "$IMAGE_REPO:$version"
  docker push "$IMAGE_REPO:$version"
  reference=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$tag" | grep -m1 "^$IMAGE_REPO@sha256:" || true)
  [ -n "$reference" ] || die "no repository digest after the push"
fi

nitro_version=$(nitro-cli --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
# Values travel as arguments, never spliced into the program text.
python3 - "$out" "$eif" "$version" "$commit" "$reference" "$node_image" "$rust_image" \
  "$nitro_version" "$constants" "$transition_sha" "$steady_sha" "$previous" "$pcr0" <<'PY'
import hashlib, json, os, pathlib, sys
(out, eif_name, version, commit, reference, node_image, rust_image, nitro_version, constants, transition, steady,
 previous, pcr0) = sys.argv[1:]
out = pathlib.Path(out)
c = json.loads(constants)
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
build = json.loads((out / "build-enclave.json").read_text())["Measurements"]
blobs = pathlib.Path(os.environ["NITRO_CLI_BLOBS"])
eif = out / eif_name


def pins(name, expected):
    """pins_pcr0: exactly the PCR0 values the rendered policy admits, read
    back from both statements that name them and checked against the build."""
    lists = {s["Sid"]: s["Condition"][op]["kms:RecipientAttestation:ImageSha384"]
             for s in json.loads((out / name).read_text())["Statement"]
             for op in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase")
             if s["Sid"] in ("EnclaveUse", "DenyOtherImages") and op in s.get("Condition", {})}
    if lists != {"EnclaveUse": expected, "DenyOtherImages": expected}:
        sys.exit(f"build.sh: {name} does not pin exactly {expected}")
    return expected


measurements = {
    "schema": "wappie-reader-measurements/v1",
    "reader_id": c["reader_id"],
    "version": version,
    "resource": c["origin"] + "/mcp",
    "source": {"repository": "thehappieco/wappie", "commit": commit},
    # null until --push: an unpushed build is not publishable.
    "image": {"reference": reference or None, "node_image": node_image, "rust_image": rust_image},
    "eif": {"file": eif.name, "sha256": digest(eif), "size": eif.stat().st_size},
    "pcrs": {n: build["PCR" + n] for n in ("0", "1", "2")},
    "nitro_cli": {"version": nitro_version,
                  "blobs": {p.name: digest(p) for p in sorted(blobs.iterdir()) if p.is_file()}},
    "kms": {"region": c["region"], "reader_key_arn": c["reader_key_arn"], "boot_key_arn": c["boot_key_arn"]},
    "policies": [
        {"phase": "transition", "file": "reader-key-policy.transition.json", "sha256": transition,
         "pins_pcr0": pins("reader-key-policy.transition.json", [previous, pcr0] if previous and previous != pcr0 else [pcr0])},
        {"phase": "steady", "file": "reader-key-policy.steady.json", "sha256": steady,
         "pins_pcr0": pins("reader-key-policy.steady.json", [pcr0])},
    ],
}
(out / "measurements.json").write_text(json.dumps(measurements, indent=2) + "\n")
PY
(cd "$out" && sha256sum -- *.json "$eif" > SHA256SUMS)

echo "reader $version from $commit"
echo "  PCR0 $pcr0"
echo "  policy sha256 transition $transition_sha, steady $steady_sha"
echo "  output $out"
[ -n "$reference" ] || echo "  image not pushed: measurements.json has image.reference null and is not publishable"
