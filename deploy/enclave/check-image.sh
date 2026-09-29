#!/bin/sh
# Static checks on a built reader image, run by CI and by build.sh before an
# EIF is made. Nothing here starts the reader: main.mjs is only parsed. The
# attachment workers (docs/mcp-enclave.md §16.6, §16.13 IMAGE) are imported
# and each is run once on a tiny job, unjailed, which needs no privilege.
#   deploy/enclave/check-image.sh [--jail] <image>
#
# --jail also runs the jail checks (§16.13 JAIL and CORPUS): a privileged
# container on an arm64 host with cgroup v2 stands in for the enclave, runs
# the entrypoint's own cgroup block, then deploy/enclave/jailcheck: the A0
# escape tests with /opt/media, media-jail's table, refusals, signals and
# parent death, and the whole worker corpus under media-jail. Twice: with the
# image's media-jail, and with a test build of the same source that takes the
# 4.14 blob kernel's fallback paths. It builds throwaway images on top of
# <image> (jailtest and the corpus added), never the image under test.
set -eu

jail=0
if [ "${1:-}" = --jail ]; then
  jail=1
  shift
fi
image=${1:?usage: check-image.sh [--jail] <image>}
here=$(cd "$(dirname "$0")" && pwd)

# shellcheck disable=SC2016 # the script runs inside the image, not here.
docker run --rm --network none --entrypoint /bin/sh "$image" -c '
set -eu
fail() { echo "check-image: $*" >&2; exit 1; }

# Measured environment: NODE_ENV and what the base image sets, nothing that
# configures the reader (docs/mcp-enclave.md §10.1).
env | grep -q "^NODE_ENV=production$" || fail "NODE_ENV is not production"
if env | grep -E "^(WAPPIE|WS|VIPS|MEDIA_JAIL)_" > /dev/null; then fail "reader configuration in the environment"; fi

[ ! -e /var/log/apk.log ] || fail "/var/log/apk.log is in the image"
[ -x /entrypoint.sh ] || fail "no /entrypoint.sh"
sh -n /entrypoint.sh || fail "entrypoint.sh does not parse under the image shell"
grep -q "^# Media jail (docs/mcp-enclave.md §16.6)" /entrypoint.sh || fail "entrypoint.sh has no media jail block"
command -v socat > /dev/null || fail "socat missing"
command -v ip > /dev/null || fail "ip missing"

# Outside an enclave there is no /dev/nsm: exit 2 proves the binary runs;
# bad arguments exit 3 before the device is touched.
rc=0; nsm-attest - - - > /dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "nsm-attest without /dev/nsm exited $rc, want 2"
rc=0; nsm-attest zz - - > /dev/null 2>&1 || rc=$?
[ "$rc" = 3 ] || fail "nsm-attest with a bad argument exited $rc, want 3"

# media-jail (§16.6): read-only, its table printed, bad invocations refused
# with 3 before anything is created, and no MEDIA_JAIL_EMULATE in this build.
mj=/usr/local/bin/media-jail
[ -x "$mj" ] || fail "no $mj"
[ "$(stat -c %a "$mj")" = 555 ] || fail "$mj is not mode 0555"
"$mj" --table > /tmp/table.json || fail "media-jail --table failed"
job="--slot light --id 0123456789abcdef --pids 64 --cpus 0 --wall-s 10 --tmp-mb 16"
for bad in "--worker nope --mem-mb 256" "--worker image --mem-mb 257" "--worker image --mem-mb 0"; do
  # shellcheck disable=SC2086 # the words are the arguments.
  rc=0; "$mj" $bad $job > /dev/null 2>&1 || rc=$?
  [ "$rc" = 3 ] || fail "media-jail $bad exited $rc, want 3"
done
rc=0; MEDIA_JAIL_EMULATE=no-pivot-root,kill-thread "$mj" --self-check > /tmp/self-check.json 2> /dev/null || rc=$?
[ "$rc" = 0 ] || fail "media-jail --self-check exited $rc"
grep -q "\"emulated\":\[\]" /tmp/self-check.json || fail "media-jail reads MEDIA_JAIL_EMULATE: a test build is in the image"

cd /app/packages/mcp-http/enclave
[ -f main.mjs ] || fail "enclave app (main.mjs) is missing"
[ -f package-lock.json ] || fail "enclave lockfile is missing"
node --check main.mjs || fail "main.mjs does not parse"
[ -f media/policy.mjs ] || fail "enclave/media/policy.mjs is missing"
# Every production dependency of the enclave package must import from here
# (catches a package whose runtime lives under a pruned src/), and so must the
# pure modules DEPLOY and the tests rely on. The reader gains no dependency
# for attachments: its parsers live under /opt/media alone (§16.5). The
# table media-jail prints is §16.8 WORKERS, which the reader checks at boot.
node --input-type=module -e "
  import { readFileSync } from \"node:fs\"
  import { isDeepStrictEqual } from \"node:util\"
  const deps = Object.keys(JSON.parse(readFileSync(\"package.json\", \"utf8\")).dependencies ?? {})
  if (deps.sort().join() !== \"@aws-sdk/client-kms,asn1js\") throw new Error(\"enclave dependencies changed: \" + deps.join(\" \"))
  for (const name of deps) await import(name)
  await import(\"./constants.mjs\")
  await import(\"./policy.mjs\")
  await import(\"@whatserver2/mcp\")
  const { WORKERS } = await import(\"./media/policy.mjs\")
  const { workers } = JSON.parse(readFileSync(\"/tmp/table.json\", \"utf8\"))
  const table = Object.fromEntries(Object.entries(workers).map(([id, w]) => [id, w.max]))
  if (!isDeepStrictEqual(table, JSON.parse(JSON.stringify(WORKERS)))) {
    throw new Error(\"media-jail --table is not WORKERS: \" + JSON.stringify(table) + \" vs \" + JSON.stringify(WORKERS))
  }
  console.log(\"imports ok: \" + (deps.join(\" \") || \"(no dependencies)\") + \"; media-jail table = WORKERS\")
" || fail "enclave imports or the worker table"
[ -z "$(find /app -type l)" ] || fail "symlink under /app"
[ -z "$(find /app -path "*/media/worker*")" ] || fail "a worker under /app: the reader tree must carry none"

# The workers (§16.13 IMAGE): Node new enough for pdf.js, no @napi-rs, a
# read-only root-owned tree without links, every file parsed, every
# dependency importing from /opt/media/worker as the workers import it.
major=$(node -p "process.versions.node.split(\".\")[0]"); minor=$(node -p "process.versions.node.split(\".\")[1]")
[ "$major" -gt 22 ] || { [ "$major" = 22 ] && [ "$minor" -ge 13 ]; } || fail "node $(node --version) is older than 22.13"
cd /opt/media/worker
[ -z "$(find /opt/media -name "@napi-rs")" ] || fail "@napi-rs is under /opt/media"
[ -z "$(find /opt/media -type l)" ] || fail "symlink under /opt/media"
[ -z "$(find /opt/media ! -user 0)" ] || fail "a file under /opt/media not owned by root"
[ -z "$(find /opt/media -perm /0222)" ] || fail "a writable file under /opt/media"
for f in image.mjs pdf.mjs office.mjs lib/*.mjs; do node --check "$f" || fail "$f does not parse"; done
[ ! -e test ] || fail "worker tests in the image"
node --input-type=module -e "
  import { readFileSync } from \"node:fs\"
  import { spawnSync } from \"node:child_process\"
  // The entry each worker loads (pdf.mjs uses pdf.js legacy build; its
  // modern build is pruned).
  const entry = { sharp: \"sharp\", \"pdfjs-dist\": \"pdfjs-dist/legacy/build/pdf.mjs\", xlsx: \"xlsx\" }
  const deps = Object.keys(JSON.parse(readFileSync(\"package.json\", \"utf8\")).dependencies)
  // pdf.js warns on import that it has no canvas, as the worker expects.
  const warn = console.warn
  console.warn = () => {}
  for (const d of deps) {
    if (!entry[d]) throw new Error(\"worker dependency without a known entry: \" + d)
    await import(entry[d])
  }
  console.warn = warn
  const sharp = (await import(\"sharp\")).default
  const XLSX = await import(\"xlsx\")

  // One tiny job per worker, run as media-jail runs it (the table argv and
  // environment) but without the jail: a photo, a PDF text page, a workbook.
  const table = JSON.parse(readFileSync(\"/tmp/table.json\", \"utf8\")).workers
  const env = { UV_USE_IO_URING: \"0\", PATH: \"/usr/local/bin:/usr/bin:/bin\", HOME: \"/tmp\", TMPDIR: \"/tmp\", OPENSSL_armcap: \"0\" }
  const job = (worker, header, input) => {
    const h = Buffer.from(JSON.stringify(header))
    const n = Buffer.alloc(4); n.writeUInt32BE(input.length)
    const hl = Buffer.alloc(4); hl.writeUInt32BE(h.length)
    const argv = table[worker].argv
    const r = spawnSync(argv[0], argv.slice(1), { input: Buffer.concat([hl, h, n, input]), env, maxBuffer: 1 << 26 })
    const frames = []
    for (let at = 0; at + 5 <= r.stdout.length; ) {
      const len = r.stdout.readUInt32BE(at)
      frames.push({ type: r.stdout[at + 4], payload: r.stdout.subarray(at + 5, at + 5 + len) })
      at += 5 + len
    }
    if (r.status !== 0 || frames.at(-1)?.type !== 9) throw new Error(worker + \" smoke job: exit \" + r.status + \", frames \" + frames.map((f) => f.type).join())
    return frames
  }
  const png = await sharp({ create: { width: 64, height: 48, channels: 3, background: \"#406080\" } }).png().toBuffer()
  const photo = job(\"image\", { v: 1, op: \"photo\", format: \"png\", limits: { pixels: 40000000, long_edge: 1568, image_bytes: 307200 } }, png)
  if (!photo.some((f) => f.type === 4 && f.payload[2] === 0xff && f.payload[3] === 0xd8)) throw new Error(\"image smoke job: no JPEG\")
  const stream = \"BT /F1 12 Tf 72 700 Td (hello from pdf.js) Tj ET\"
  const objs = [\"<< /Type /Catalog /Pages 2 0 R >>\", \"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\",
    \"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\",
    \"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\", \"<< /Length \" + stream.length + \" >>\\nstream\\n\" + stream + \"\\nendstream\"]
  let pdf = \"%PDF-1.4\\n\"; const offsets = []
  objs.forEach((o, i) => { offsets.push(pdf.length); pdf += (i + 1) + \" 0 obj\\n\" + o + \"\\nendobj\\n\" })
  const xref = pdf.length
  pdf += \"xref\\n0 6\\n0000000000 65535 f \\n\" + offsets.map((o) => String(o).padStart(10, \"0\") + \" 00000 n \\n\").join(\"\")
  pdf += \"trailer\\n<< /Size 6 /Root 1 0 R >>\\nstartxref\\n\" + xref + \"\\n%%EOF\\n\"
  const text = job(\"pdf\", { v: 1, op: \"text\", from: 1, count: 1, limits: { text_bytes: 4194304, image_pixels: 16000000 } }, Buffer.from(pdf, \"latin1\"))
  if (!text.some((f) => f.type === 2 && f.payload.toString().includes(\"hello from pdf.js\"))) throw new Error(\"pdf.js extracted no text\")
  const wb = XLSX.utils.book_new(); XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([[\"a\", 1], [\"b\", 2]]), \"S\")
  const sheet = job(\"office\", { v: 1, op: \"text\", allow: [\"office\", \"zip\"], limits: { text_bytes: 4194304, entries: 2000, inflated: 104857600, ratio: 100, listed: 200, sheets: 50, sheet_rows: 2000 } },
    XLSX.write(wb, { type: \"buffer\", bookType: \"xlsx\" }))
  if (!sheet.some((f) => f.type === 2 && f.payload.toString() === \"a,1\\nb,2\\n\")) throw new Error(\"office smoke job: no CSV\")
  console.log(\"workers ok: \" + deps.join(\" \") + \"; node \" + process.version)
" || fail "worker imports or smoke jobs"
echo "check-image: ok"
'

[ "$jail" = 1 ] || exit 0

# The jail checks (§16.13 JAIL, CORPUS), in a privileged container.
arch=$(docker image inspect --format '{{.Architecture}}' "$image")
[ "$arch" = arm64 ] || { echo "check-image: --jail needs an arm64 image (the enclave's), not $arch" >&2; exit 1; }
root=$(cd "$here/../.." && pwd)
rust_image=${RUST_IMAGE:-$(sed -n 's/^ARG RUST_IMAGE=//p' "$here/Dockerfile")}
tag=wappie-reader-jailcheck:$$
trap 'docker rmi -f "$tag" "$tag-4.14" > /dev/null 2>&1 || true' EXIT
for target in check check-4.14; do
  suffix=${target#check}
  docker build -q -f "$here/jailcheck/Dockerfile" --target "$target" --build-arg READER_IMAGE="$image" \
    --build-arg RUST_IMAGE="$rust_image" -t "$tag$suffix" "$root" > /dev/null
  echo "check-image --jail: $target"
  docker run --rm --privileged --cgroupns private --network none "$tag$suffix"
done
echo "check-image --jail: ok"
