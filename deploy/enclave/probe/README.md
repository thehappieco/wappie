# Probe enclave

A throwaway enclave that answers, on the enclave's own kernel, what nothing
off-Nitro can: the jail and the parsers on the Nitro blob's Linux 4.14, the
memory the enclave has left, and how long attachments take through vsock
(`docs/mcp-enclave.md` §16.6, §16.13). It is **never released**: `probe.sh`
builds a distinct image and EIF under `/opt/wappie-reader/probe/`, runs it in
`--debug-mode` on the parent, assembles the report the enclave streams to its
console, and throws the enclave away. The production reader's files are never
touched, but its supervisor is **stopped for the run** (the allocator has one
enclave slot), so each run is a production outage: a few minutes (the local
run below takes under two on one CPU, and the enclave boots a larger EIF
first), at most `REPORT_TIMEOUT` (35 minutes).

- **A0** (2026-09-28) answered the go/no-go with a probe image of its own:
  `RESULTS-2026-09-28.md`, `KERNEL-4.14.md`, and the history below.
- **A1** (this version) is the jail check before the release (§16.13 JAIL,
  "then the probe enclave"), and the enclave half of the performance gate
  (§16.13 GATE: the memory headroom and the 16 and 32 MiB documents).

## What the A1 probe is

The probe image is built **from the A1 reader image of the same commit**, in
three layers (`build-image.sh`):

1. the reader image exactly as `make enclave-image` builds it
   (`deploy/enclave/Dockerfile`): the production `media-jail` with its
   compiled-in table and seccomp profile, `/opt/media/worker` and its
   dependencies, Node, the entrypoint. Its KMS markers stay, so its own
   `main.mjs` would refuse to boot; the probe never starts it;
2. the jail check on top, exactly as `check-image.sh --jail` builds it
   (`deploy/enclave/jailcheck/Dockerfile`, target `check`): the A0 escape
   tests (`jailtest`), the §16.13 corpus, `jail-check.mjs`, and the reader's
   packages with their tests at `/opt/e2e`;
3. the probe (`Dockerfile.probe`): the runner (`probe-report.mjs`), its
   entrypoint, the reader stand-in (`reader-bench.mjs`) and the vsock
   throughput sink. The test tree is cut to what it runs: the SDK keeps its
   runtime dependencies only, and the worker package's tests import the
   image's own `/opt/media/worker/node_modules`. The enclave holds the whole
   root filesystem in memory, and nitro-cli wants four times the EIF: the
   probe's root filesystem is about 325 MB against the reader's 260 MB.

In the enclave, `entrypoint-probe.sh` does what production's entrypoint
does with production's own lines (loopback up, `/run/wappie`, and the media
jail block, taken from `/entrypoint.sh` at run time and traced), then runs
the runner, which measures on the real kernel:

- **the A0 kernel facts**: versions and CPU, `/proc/config.gz`, the cgroup
  layout the production block made, `media-jail --self-check` and `--table`,
  what the kernel has outside any jail, and the vsock throughput from the
  parent;
- **the jail check**, the same `jail-check.mjs` that `check-image.sh --jail`
  runs: the setup, the refusals, the A0 escape tests from `/opt/media`,
  `SIGTERM` and parent death, and every corpus file through the reader's own
  `runWorker`, each worker under the image's `media-jail` and seccomp
  profile, never a seccomp kill;
- **the reader end to end**, `enclave/test/media-e2e.test.mjs` with
  `MEDIA_E2E=jail`, as `check-image.sh --jail` runs it (loopback only);
- **the reader stand-in** (`reader-bench.mjs`): the production reader,
  `startEnclave` from `main.mjs`, booted in one Node with the test world's
  fake Go, KMS, NSM and ACME on loopback, and two media connections consented.
  It measures MemAvailable and its own RSS idle; then opens, end to end, the
  corpus files that reach furthest into their memcg (the 1 GB Flate stream at
  pdf's 384 MiB, the million-row sheet, a 35 MP PNG, a 12 MP JPEG, the scanned
  PDF), sampling MemAvailable every 50 ms, and reads the reader's own
  `mem_avail_min_mb`; then opens a scanned PDF and a docx of 16 MiB and of
  32 MiB (`CAP_BYTES.document`) whose ciphertext the **parent** serves over
  vsock (`vsock-serve.py`, port 9101) through a socat bridge like
  production's, timing each from the first `tools/call` to the answer, with
  `pending` followed as a host would, each job's time and memcg peak, and the
  repeat a ChatGPT client makes (answered from the result cache);
- **the kernel's reports** about all of it (SIGILL, seccomp kills, OOM) and
  what 4.14 lacks for §16.6.

What the stand-in is not: its Node also holds the fake Go (which buffers a
ciphertext whole before it answers) and the fixture, so its RSS is above the
production reader's; the parent serves the ciphertext from memory, so the
parent's Go, TLS and object store are not in the timings; and the probe's
own processes (the runner, about 50 MB) and test tree (`meta.probe_only_kb`)
are memory production does not spend. Each is in the report, to be taken off
by whoever reads the headroom. The inputs are built in short-lived children
writing to `/tmp`, never in the stand-in's own heap.

## Running it (on the parent)

```
sudo deploy/enclave/probe/probe.sh
```

Requires the arm64 parent (c7g.large), docker + nitro-cli 1.5.0, python3, the
production supervisor unit `wappie-reader-supervisor`, and the allocator
already reserving 1 vCPU / 1536 MiB. `probe.sh`:

1. builds the three images (`build-image.sh`, tag
   `wappie-reader-probe:<stamp>`) and the EIF under
   `/opt/wappie-reader/probe/<stamp>/`, and refuses to go on, **with
   production still up**, if the enclave's 1536 MiB is less than four times
   the EIF (nitro-cli's E26);
2. starts `vsock-serve.py` on vsock port **9101** (the documents);
3. **stops the production supervisor** (this terminates the production
   enclave), freeing the allocator slot;
4. runs the probe EIF `--debug-mode --cpu-count 1 --memory 1536 --enclave-cid 30`,
   saves `describe-enclaves` once (`describe-first.json`/`.err`) and captures
   the console (`console.log`);
5. streams 16 MiB then 32 MiB to the enclave over vsock port **9100**
   (`vsock-send.py`). None of 9100, 9101 or CID 30 collides with production's
   5443-5445 / 7000-7002 / 8000-8002 / 9000 and CID 16;
6. waits for the `===WAPPIE-A1-PROBE-END===` marker, up to `REPORT_TIMEOUT`
   (2,100 s) from the launch. The enclave counts as gone only when
   `describe-enclaves` succeeds and does not list it, twice in a row; a
   failing `describe-enclaves` is `unknown`, never `gone`. Every poll goes to
   `liveness.log`;
7. assembles the report from the streamed sections (`assemble-report.py`):
   `report.json` (complete with the END marker and the runner's `done`
   record, partial otherwise) and `report.jsonl`, keeping every finished
   section either way, and prints its one-line summary: `go` and its three
   parts (`jail_check`, `media_e2e`, `reader_bench`), and any failed check;
8. **always restarts the production supervisor** from its EXIT trap, even on
   failure or interrupt, and prints the report path, the EIF size, the
   installed blob's kernel config (`$NITRO_CLI_BLOBS/Image.config`) and the
   parent's log of the documents it served (`vsock-serve.log`).

HUP, INT and TERM make the script exit (bash would otherwise run the handler
and carry on), cleanup ignores further signals until production is back, and
production is started again only if the script had stopped it: a signal
during the image build leaves production running and never launches the probe.
SIGPIPE is ignored, because bash killed by it skips its EXIT trap: run as
`sudo probe.sh 2>&1 | tee run.log`, a dropped SSH session takes `tee` with it,
and the next write would otherwise end the script with production down. Now a
failed write returns `EPIPE` and the run goes on to cleanup, which starts
production before it prints anything. Every `nitro-cli describe-enclaves` and
`terminate-enclave` is bounded by `timeout 60`, so a hung one cannot hold the
restart either. `vsock-serve.py` exits by itself after the longest run.

## What the console shows

`entrypoint-probe.sh` writes to `/dev/console` explicitly and never `exec`s
Node, so the console explains the run even if Node dies:

- `===WAPPIE-A1-PROBE-BEGIN===`, and a `wappie-a1: probe entrypoint started`
  record in the kernel log itself (it dates the start in kernel time, and the
  runner reads kernel reports from there on);
- `A1 STEP <n> t=<uptime> <what>` before every step;
- a trivial `node -e` first (`A1 NODE {pid, version, arch, release, openssl,
  sha256}`), then the same with `OPENSSL_armcap=0`: on 4.14 the first draws
  one `Bad EL0 ... 0x66000000` report (OpenSSL's SVE probe) and the second
  none;
- `A1 PID <pid> <label>: <argv>` and `A1 EXIT <pid> <label>: exit N | signal N`
  around every process the entrypoint starts (the runner included);
- the last lines of the media jail block's trace;
- `A1 ALIVE t=<uptime>` every 10 s while the runner works;
- the runner's lines: `A1 RUN …` progress (every process is announced with its
  argv before it starts) and one `A1R <seq> <bytes> <json>` record per section,
  per jail check result and per stand-in result;
- every `/run/probe` file raw, between `A1 FILE <path> BEGIN/END` (this
  reprints `report.jsonl`, so a record a kernel message split in the stream is
  whole here);
- `===WAPPIE-A1-PROBE-END===`, then 5 s for the console to drain before the
  script exits and the init reboots the enclave.

## What the report answers (probe-report.mjs)

One record per section, streamed as soon as it is measured:

- `meta`: the reader version and capabilities of the image, Node, OpenSSL, V8
  and libuv, `os.release()`, the CPU part and `HWCAP_SVE`, the node binary's
  load address, memory at boot and after Node, and `probe_only_kb`, the
  probe's own trees;
- `kernel_config`: `/proc/config.gz` facts when the kernel exposes them;
- `cgroup`: the boot layout and root mount, the production block's trace, the
  controllers of `/run/cg2` and `media`, which optional files `media` has
  (`cgroup.kill`, `memory.peak`, `memory.oom.group`, `cpuset.cpus`), the
  `/proc` mount (hidepid) and `oom_score_adj`;
- `media_jail_self_check`: `--self-check` (with the seccomp kill action the
  kernel allows) and `--table`;
- `kernel_unjailed`: `io_uring_setup`, `userfaultfd`, `unshare(CLONE_NEWUSER)`,
  `clone3` and `pidfd_open` run as root with no seccomp (ENOSYS = absent);
- `vsock`: MB/s for the 16 MiB and 32 MiB streams from the parent;
- `jail_result`, one per check of `jail-check.mjs` (`{pass, name, detail}`:
  each escape with the jail's own account, each corpus file with its outcome,
  time and memcg peak), then `jail_check`: `go`, the counts, what failed, the
  root switch and kill method the kernel took, and the largest memcg peaks;
- `media_e2e`: `go`, the TAP counts and tail;
- `bench`, one per stand-in result (`phase`: `begin`, `inputs`, `boot`,
  `idle`, `heavy` per file, `heavy_summary` with `mem_avail_min_mb`, the
  quarter of MemTotal and the reader's own health figures, `document` per
  file with `ms`, `fits_chatgpt`, `transport`, the header's summary and every
  job, and `end`), then `reader_bench`: `go`, the documents' times, and the
  runner's own RSS;
- `kernel_log`: from `/dev/kmsg` after the entrypoint's mark, every `Bad EL0`
  report with its pid, comm and pc, traced to the process that raised it
  (whether they all sit on OpenSSL's SVE probe; workers run with
  `OPENSSL_armcap=0`), seccomp kills (audit type 1326: syscall number and
  process; `worker_seccomp_kills` must be empty, the escape tests' own are
  jailtest's), OOM lines;
- `a1_kernel`: what §16.6 wanted and this kernel lacks, measured, with the
  fallback and the root switch and kill method in use;
- `done`, with `go` and its parts; `spawn`/`exit` records for every process
  the runner starts; `fatal` for an uncaught exception or unhandled rejection
  (the run goes on).

Every child the runner starts has a timeout (the jail check 10 minutes, the
end-to-end test 5, the stand-in 15), and each of their results was streamed
before it, so a hang costs its own section only.

## Files

| File | Runs | Purpose |
|---|---|---|
| `build-image.sh` | parent, CI host | Builds the reader image, the jail check on it, and the probe on that. |
| `Dockerfile.probe` | build | The probe layer: the runner, the entrypoint, the stand-in, the throughput sink; the test tree cut down. |
| `entrypoint-probe.sh` | enclave CMD | Production's loopback, `/run/wappie` and media jail block, boot snapshots, the trivial nodes, then the runner as a child; the self-explaining console above. |
| `probe-report.mjs` | enclave | Measures every section and streams it. |
| `reader-bench.mjs` | enclave | The reader stand-in: idle memory, the heaviest jobs, the documents over vsock. Copied next to the reader's tests as `probe-bench.mjs`. |
| `tests/jailtest.c` | jailed | One static binary; a sub-command per escape (also `jailcheck`'s). |
| `tests/vsock-sink.c` | enclave | Times the parent's vsock streams. |
| `probe.sh` | parent | The orchestration above. |
| `vsock-send.py` | parent | Streams 16 and 32 MiB to the enclave over vsock 9100. |
| `vsock-serve.py` | parent | Takes and serves the stand-in's documents over vsock 9101. |
| `assemble-report.py` | parent | Builds `report.json`/`report.jsonl` from the console; repairs a record a kernel line split. |
| `test_assemble_report.py`, `test_vsock_serve.py` | CI | Unit tests for the assembler and the object server. |
| `KERNEL-4.14.md` | — | The kernel 4.14 amendments to §16.6 (A0). |
| `RESULTS-2026-09-28.md` | — | The A0 run's answers. |

## Local validation (what was checked off-Nitro)

On an arm64 host with Docker (Docker Desktop, kernel 6.12, cgroup v2), the
probe image from `build-image.sh`, in a privileged container that stands in
for the enclave, limited to one CPU:

```
docker run --rm --privileged --cgroupns private --cpus 1 \
  -e PROBE_CONSOLE=- -e PROBE_VSOCK_TIMEOUT_MS=2000 -e PROBE_OBJECTS=loopback \
  wappie-reader-probe:local > console.log
python3 deploy/enclave/probe/assemble-report.py console.log .
```

The report is complete in about 95 s (the jail check 32 s, the end-to-end
test 15 s, the stand-in 42 s), `go` with all three parts: 114 of 114 jail
checks, the end-to-end test passing, the four documents opened (the PDFs in
about 2 s, the docx files in under 1 s, each repeat from the cache). The
kernel's own seccomp reports are the escape tests' (comm `jailtest`) only.

The vsock path too: Docker Desktop's VM has AF_VSOCK loopback (CID 1), so a
second privileged container stood in for the parent, running
`vsock-serve.py 9101` and `vsock-send.py 1 9100`, and the probe ran with
`-e PROBE_PARENT_CID=1` and no `PROBE_OBJECTS`: the throughput sink got both
streams, and the four documents went up to the stand-in parent and came back
through the socat bridge (`transport: vsock`), complete again.

What the local runs cannot show is the Nitro kernel itself (4.14, its v1
cgroup layout, `pivot_root` or its fallback, the real kill methods, the real
SIGILLs), 1536 MiB of memory with a 325 MB root filesystem in it, and the
parent's vsock; those are what `probe.sh` is for. The 4.14 fallbacks are
exercised off-Nitro by `check-image.sh --jail`'s `check-4.14` target, with a
test build of `media-jail`; the probe runs only the image's binary.

## History: A0 (2026-09-28)

The A0 probe had its own image (the prototype `media-jail --profile … --
<program>`, its own sharp and pdf.js stack and corpus) and answered the
go/no-go: `RESULTS-2026-09-28.md`. Its first Nitro run left only kernel lines
on the console, and what that run taught is kept here:

- **The enclave kernel is Linux 4.14** (`4.14.256-209.484.amzn2.aarch64`, the
  nitro-cli blob): `KERNEL-4.14.md` lists what it lacks, and media-jail
  detects each feature and falls back.
- **The `Bad EL0 synchronous exception ... code 0x66000000` reports are
  OpenSSL, and harmless.** ESR class 0x19 is an SVE access trap: Graviton3 has
  SVE, 4.14 predates kernel SVE support, and OpenSSL's CPU-feature probe
  (`_armv8_sve_probe`, offset `0x213ee48` in the pinned node binary) catches
  the SIGILL to learn there is no SVE. Every node start takes it once;
  `OPENSSL_armcap=0` (the workers' environment) skips it.
- **One cgroup write naming a controller the kernel lacks fails as a whole**:
  `'+memory +pids +cpuset'` left memory and pids off on 4.14. The production
  block enables each controller with its own write.
- **The console must explain the run on its own**, so every section is
  streamed as it is measured, the entrypoint prints numbered steps, a
  heartbeat, every process's pid and end, and the raw files at the end.
- **Liveness was misjudged**: `nitro-cli describe-enclaves 2>/dev/null | grep -q`
  under `pipefail` read a live enclave as gone whenever nitro-cli exited
  non-zero (it fails when it cannot reach any one enclave process's socket,
  which a production enclave stopped a moment earlier can cause), and the
  EXIT trap then terminated the probe. Now "gone" needs a successful
  `describe-enclaves` that does not list the probe, twice in a row, and
  every poll is logged.
