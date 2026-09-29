# A0 probe enclave

The throwaway probe that answers the media go/no-go (`docs/mcp-enclave.md` §16.6,
§4 JAIL) before any reader release is built. It is **never released**: `probe.sh`
builds a distinct image and EIF under `/opt/wappie-reader/probe/`, runs it in
`--debug-mode` on the parent, assembles the report the enclave streams to its
console, and throws the enclave away. The production reader's files are never
touched, but its supervisor is **stopped for the run** (the allocator has one
enclave slot), so each run is a production outage of a few minutes.

Nothing here changes a released reader. In particular the §16.6 cgroup surgery
(unmount the v1 memory/pids/cpuset hierarchies, mount cgroup2 at `/run/cg2`,
enable the controllers) lives in `entrypoint-probe.sh`, **not** in the
production `deploy/enclave/entrypoint.sh`; A1 moves the reviewed version there.

**A1.** The reviewed block is now in `deploy/enclave/entrypoint.sh`, and
`media-jail` takes only its compiled-in workers (`--worker image|pdf|office`,
no `--profile … -- <program>`), which `probe-report.mjs` still uses: this
directory records the A0 run as it was. The A1 jail checks, the A0 escape
tests with `/opt/media` included, are `deploy/enclave/jailcheck`, which
`check-image.sh --jail` runs in a privileged container; before the release,
the probe enclave runs them on the real kernel through a runner moved there.

## The first Nitro run (2026-09-28)

c7g.large parent, nitro-cli 1.5.0, enclave 1 vCPU / 1536 MiB, `--debug-mode`.
The console held only kernel lines, and `probe.sh` said "probe enclave exited
before the report". What that run shows, and what this version changes:

- **The enclave kernel is Linux 4.14** (`4.14.256-209.484.amzn2.aarch64`, the
  nitro-cli blob). Much of §16.6 is newer; `KERNEL-4.14.md` lists what is
  missing, and media-jail now detects each feature and falls back (its README).
- **The two `Bad EL0 synchronous exception ... code 0x66000000` reports are
  OpenSSL, and harmless.** ESR class 0x19 is an SVE access trap: Graviton3
  (Neoverse V1) has SVE, the 4.14 kernel predates SVE support (4.15), so the
  instruction traps and the kernel, not knowing the class, sends SIGILL. The pc
  is `_armv8_sve_probe` (`eor z0.d, z0.d, z0.d`, offset `0x213ee48` in the
  pinned node binary: Node 22.23.3, OpenSSL 3.5.8), and the return address is
  in OpenSSL's `arm_probe_for`, right after its `blr x0` under `sigsetjmp`:
  OpenSSL's CPU-feature probe, which catches the SIGILL to learn there is no
  SVE. On musl OpenSSL cannot ask `getauxval`, so it probes like this at every
  node start. Both reports (PIDs 570 and 617) sit at the same load-relative
  offsets, and PID 570, the runner, went on to start PID 617, so it survived
  its SIGILL. The production reader's node takes the same trap at every start;
  its console is simply not readable outside debug mode.
- **The cgroup setup could not have worked.** `'+memory +pids +cpuset'` was one
  write to `cgroup.subtree_control`; 4.14's cgroup2 has no cpuset (5.0), and one
  unknown controller fails the whole write, so memory and pids stayed off and
  every media-jail run failed at `memory.max` within milliseconds. That fits the
  runner reaching `gen-corpus.mjs` (the second node, PID 617) 0.9 s after it
  started. Controllers are now enabled one per write.
- **Silence after 1.2 s was expected**, and says nothing about when the enclave
  died: the runner printed its one JSON object only at the very end.
- **Most likely the probe was still running when `probe.sh` tore it down.** An
  enclave whose command exits leaves lines on the console — the Nitro init
  prints "child exited with error"/"by signal" and reboots, and the kernel
  prints "reboot: Restarting system" — and an OOM kill or a panic prints too;
  none of that is there. `probe.sh` judged liveness with
  `nitro-cli describe-enclaves 2>/dev/null | grep -q` under `pipefail`, which
  reads a live enclave as gone whenever nitro-cli exits non-zero — it prints
  the enclaves it reached and then fails if it could not reach any one enclave
  process's socket ("Failed connections: N", sent to /dev/null here), which a
  production enclave process stopped a moment earlier could cause — and,
  rarely, when nitro-cli dies of EPIPE writing its last line after `grep -q`
  has matched and quit. Its EXIT trap then terminated the enclave. Against a stubbed nitro-cli that exits 1 with the enclave listed,
  the old `probe.sh` prints exactly "probe enclave exited before the report".

The next run proves it either way: `liveness.log` records every poll's verdict
(`up`, `gone`, `unknown(rc=…: stderr)`), the entrypoint prints `A0 ALIVE` every
10 s, every section is on the console as soon as it is measured, the runner's
exit code or signal is printed, and the init's own exit lines would show a
self-inflicted end.

## Running it (on the parent)

```
sudo deploy/enclave/probe/probe.sh
```

Requires the arm64 parent (c7g.large), docker + nitro-cli 1.5.0, python3, the
production supervisor unit `wappie-reader-supervisor`, and the allocator already
reserving 1 vCPU / 1536 MiB. `probe.sh`:

1. builds the probe image and EIF under `/opt/wappie-reader/probe/<stamp>/`;
2. **stops the production supervisor** (this terminates the production enclave),
   freeing the allocator slot;
3. runs the probe EIF `--debug-mode --cpu-count 1 --memory 1536 --enclave-cid 30`,
   saves `describe-enclaves` once (`describe-first.json`/`.err`) and captures the
   console (`console.log`);
4. streams 16 MiB then 32 MiB to the enclave over vsock port **9100** (none of
   these collide with production's 5443-5445 / 7000-7002 / 8000-8002 / 9000);
5. waits for the `===WAPPIE-A0-PROBE-END===` marker, up to 480 s from the
   launch. The enclave counts as gone only when `describe-enclaves` succeeds and
   does not list it, twice in a row; a failing `describe-enclaves` is
   `unknown`, never `gone`. Every poll goes to `liveness.log`;
6. assembles the report from the streamed sections (`assemble-report.py`):
   `report.json` (complete with the END marker and the runner's `done` record,
   partial otherwise) and `report.jsonl`, keeping every finished section either
   way;
7. **always restarts the production supervisor** from its EXIT trap, even on
   failure or interrupt, and prints the report path and its one-line summary,
   the EIF size and the installed blob's kernel config
   (`$NITRO_CLI_BLOBS/Image.config`).

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
restart either.

## What the console shows

`entrypoint-probe.sh` writes to `/dev/console` explicitly and never `exec`s
Node, so the console explains the run even if Node dies:

- `===WAPPIE-A0-PROBE-BEGIN===`, and a `wappie-a0: probe entrypoint started`
  record in the kernel log itself (it dates the start in kernel time, and the
  runner reads kernel reports from there on);
- `A0 STEP <n> t=<uptime> <what>` before every step;
- a trivial `node -e` first (`A0 NODE {pid, version, arch, release, openssl,
  sha256}`), then the same with `OPENSSL_armcap=0`, which makes OpenSSL skip its
  probes: on 4.14 the first should draw exactly one `Bad EL0 ... 0x66000000`
  report for its pid and the second none, which settles where the SIGILL comes
  from;
- `A0 PID <pid> <label>: <argv>` and `A0 EXIT <pid> <label>: exit N | signal N`
  around every process the entrypoint starts (the runner included);
- the cgroup setup log, one line per controller, and the hidepid result;
- `A0 ALIVE t=<uptime>` every 10 s while the runner works;
- the runner's lines: `A0 RUN …` progress (every process is announced with its
  argv before it starts) and one `A0R <seq> <bytes> <json>` record per section;
- every `/run/probe` file raw, between `A0 FILE <path> BEGIN/END` (this reprints
  `report.jsonl`, so a record a kernel message split in the stream is whole
  here);
- `===WAPPIE-A0-PROBE-END===`, then 5 s for the console to drain before the
  script exits and the init reboots the enclave.

## What the report answers (probe-report.mjs)

One record per section, streamed as soon as it is measured:

- `meta`: Node, OpenSSL, V8 and libuv versions, `os.release()`, the CPU part and
  `HWCAP_SVE` (false on Graviton3 means the kernel lacks SVE), the node
  binary's load address, memory at boot and after Node;
- `kernel_config`: `/proc/config.gz` facts when the kernel exposes them;
- `cgroup`: the boot layout, the boot mount of `/`, the setup log, the media
  node's controllers and which optional files it has (`cgroup.kill`,
  `memory.peak`, `memory.oom.group`, `cpuset.cpus`), and hidepid;
- `media_jail_self_check`, including the seccomp kill action the kernel allows;
- `kernel_unjailed`: `io_uring_setup`, `userfaultfd`, `unshare(CLONE_NEWUSER)`,
  `clone3` and `pidfd_open` run as root with no seccomp (ENOSYS = absent);
- one `jail_test` record per escape, each with the jail's own account
  (`child_pid`, `root_switch`, `caps`, `cpu_pin`, `oom_group`, `seccomp_kill`):
  `/dev/nsm` open (ENOENT), `socket(AF_VSOCK)`, `socket(AF_INET)` and `connect`
  (seccomp kill), `socket(AF_UNIX)` (allowed, shows the filter is precise),
  `io_uring_setup` and `clone3` (ENOSYS shim), `userfaultfd`,
  `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWNS)` and `chroot` (seccomp kill),
  `/run/wappie`, `/run/cg2`, `/sys`, `/etc/hosts` and `/dev/nsm` absent,
  `privs` (every capability set empty, NoNewPrivs 1, Seccomp 2, the CPU mask),
  `mountinfo` (the jail's whole mount table; nothing under `/sys`, `/run`,
  `/etc`), a memory hog (killed by the memcg), cross-job `/proc` (invisible),
  the external kill (the main Node's path: `cgroup.kill`, or on 4.14 SIGKILL of
  the job's PID-namespace init), and the wall timeout; then a `jail` summary
  with `go`;
- `corpus`, `image_job`, `pdf_job`: the A1 stack — a generated 12 MP JPEG
  through **sharp** and a 50-page PDF through **pdfjs-dist** (no
  `@napi-rs/canvas`, §16 F2), jailed, with `memory.peak` or, without it, the
  sampled `memory.current` and `ru_maxrss`, and the wall time;
- `vsock`: MB/s for the 16 MiB and 32 MiB streams;
- `kernel_log`: from `/dev/kmsg` after the entrypoint's mark, every `Bad EL0`
  report with its pid, comm and pc, traced to the process that raised it (the
  runner, an entrypoint process, a runner spawn, a jailed job's PID 1), whether
  node SIGILLs recur and whether they all sit on OpenSSL's SVE probe (the
  runner's own maps to an exact offset in the node binary); seccomp kills
  (audit type 1326: syscall number and process); OOM lines;
- `a1_kernel`: what §16.6 wanted and this kernel lacks, measured, with the
  fallback in use (the facts for "stay on the blob kernel or build our own");
- `done`; `spawn`/`exit` records for every process the runner starts; `fatal`
  for an uncaught exception or unhandled rejection (the run goes on).

A kill or a denial only counts once the test printed its own `START` line (a
SIGSYS during startup is a profile gap, not the denial under test), and an
errno denial must carry the expected errno. Every jailed record keeps
media-jail's own stderr (`stderr_tail`), so a setup failure on the real kernel
explains itself. The runner gives each jailed job a watchdog 10 s past its wall;
a job that outlives it is killed and recorded as `hung`.

## Files

| File | Runs | Purpose |
|---|---|---|
| `Dockerfile.probe` | build | The probe image: `media-jail`, the C tests, the sharp/pdfjs worker stack, the runner. Same pinned base digests as `deploy/enclave/Dockerfile`. |
| `entrypoint-probe.sh` | enclave CMD | The §16.6 cgroup surgery, boot snapshots, the trivial nodes, then the runner as a child; the self-explaining console above. |
| `probe-report.mjs` | enclave | Measures every section and streams it. |
| `tests/jailtest.c` | jailed | One static binary; a sub-command per escape. |
| `tests/vsock-sink.c` | enclave | Times the parent's vsock streams. |
| `worker/{gen-corpus,image-probe,pdf-probe}.mjs` | enclave / jailed | Generate the corpus; the jailed sharp and pdfjs workers. |
| `worker/package.json` + lock | build | sharp 0.35.5, pdfjs-dist 6.3.289 (pinned); `@napi-rs/canvas` pruned after `npm ci`. |
| `probe.sh` | parent | The orchestration above. |
| `vsock-send.py` | parent | Streams 16 and 32 MiB to the enclave over vsock 9100. |
| `assemble-report.py` | parent | Builds `report.json`/`report.jsonl` from the console; repairs a record a kernel line split. |
| `test_assemble_report.py` | CI | Unit tests for the assembler. |
| `KERNEL-4.14.md` | — | The "Kernel 4.14 amendments" to append to the design. |

## Local validation (what was checked off-Nitro)

On an arm64 host with Docker (Docker Desktop, kernel 6.12, cgroup v2), in a
privileged container that stands in for the enclave
(`docker run --privileged -e PROBE_CONSOLE=- -e PROBE_VSOCK_TIMEOUT_MS=2000`):

- `media-jail` builds `--locked`, its unit tests pass, `--self-check` runs;
- natively (`pivot_root`, cpuset, `cgroup.kill`, `memory.oom.group`,
  `memory.peak`, `KILL_PROCESS`), the report is complete and every jail test
  passes (`jail.go == true`), with the jailed sharp (12 MP, peak ~49 MB) and
  pdfjs (50 pages, peak ~40 MB) workers succeeding;
- with `PROBE_EMULATE_OLD_KERNEL=1` — cpuset left off cgroup2 by the entrypoint,
  and media-jail told `no-cgroup-kill,no-oom-group,no-peak,no-pivot-root,kill-thread`
  — every job ran `move+chroot`, `affinity`, `oom_group: media-jail`,
  `kill_thread`, the wall timeout and the external kill went through the
  PID-namespace init, and the report is again complete with `jail.go == true`,
  the same jail mount table and `caps: cleared`;
- `Bad EL0` lines written into `/dev/kmsg` in the 4.14 format for the runner's
  and the trivial node's pids were traced to them, the runner's to offset
  `0x213ee48` (`openssl_sve_probe: true`); in a container the kernel's own pids
  are the host's, so real kernel reports there show `source: unknown`;
- `probe.sh` against a stubbed nitro-cli: a full run (complete, exit 0), an
  enclave that ends mid-run (two `gone` polls, a partial report with every
  record streamed so far, exit 1), and a `describe-enclaves` that exits 1 with
  the enclave listed (`unknown`, run completes); production restarted each
  time. Also with its output piped into a reader that goes away while
  production is down (`| head -n 4`, and `| tee` with SIGHUP sent to the whole
  pipeline, as an SSH drop does): the script before the SIGPIPE fix left
  production stopped both times, and now restarts it;
- `media-jail` directly, `MEDIA_JAIL_EMULATE=no-swap-max`: the job is refused
  (exit 3) while `/proc/swaps` lists the VM's swap file, and runs with
  `swap_max: absent-no-swap` with an empty list bound over `/proc/swaps`. A
  write to a missing cgroupfs file fails with `EACCES` on 6.12, which is why
  the file is detected by its presence.

Only the Nitro enclave boot (the 4.14 kernel, its cgroup layout, `/dev/nsm`,
the real SIGILLs) and the AF_VSOCK transfer need the actual hardware; those run
when `probe.sh` is executed on the parent.
