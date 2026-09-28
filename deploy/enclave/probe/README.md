# A0 probe enclave

The throwaway probe that answers the media go/no-go (`docs/mcp-enclave.md` §16.6,
§4 JAIL) before any reader release is built. It is **never released**: `probe.sh`
builds a distinct image and EIF under `/opt/wappie-reader/probe/`, runs it in
`--debug-mode` on the spare parent, captures one JSON report, and throws the
enclave away — the production reader, its EIF and its supervisor are untouched.

Nothing here changes a released reader. In particular the §16.6 cgroup surgery
(unmount the v1 memory/pids/cpuset hierarchies, mount cgroup2 at `/run/cg2`,
enable the controllers) lives in `entrypoint-probe.sh`, **not** in the
production `deploy/enclave/entrypoint.sh`; A1 moves the reviewed version there.

## Running it (on the parent)

```
sudo deploy/enclave/probe/probe.sh
```

Requires the arm64 parent (c7g.large), docker + nitro-cli 1.5.0, the production
supervisor unit `wappie-reader-supervisor`, and the allocator already reserving
1 vCPU / 1536 MiB. `probe.sh`:

1. builds the probe image and EIF under `/opt/wappie-reader/probe/<stamp>/`;
2. **stops the production supervisor** (this terminates the production enclave),
   freeing the allocator slot;
3. runs the probe EIF `--debug-mode --cpu-count 1 --memory 1536 --enclave-cid 30`
   and captures its console;
4. streams 16 MiB then 32 MiB to the enclave over vsock port **9100** (none of
   these collide with production's 5443-5445 / 7000-7002 / 8000-8002 / 9000);
5. extracts the report between the `===WAPPIE-A0-PROBE-BEGIN/END===` markers;
6. **always restarts the production supervisor** in a trap, even on failure or
   interrupt, and prints the report path and the EIF size.

## What the report answers (probe-report.mjs)

One JSON object with raw evidence for each §4 JAIL / §16 open point:

- kernel version and `/proc/config.gz` facts (`CONFIG_IO_URING`, `CONFIG_USER_NS`,
  `CONFIG_SECCOMP_FILTER`, `CONFIG_CGROUPS`, `CONFIG_MEMCG`, …);
- the boot cgroup layout (`/proc/self/mountinfo`, `/proc/cgroups`) and whether
  the v1→v2 switch and controller enable worked;
- `/dev/nsm` mode and owner;
- `media-jail --self-check`;
- a jailed test per escape (`jailtest`), each classified pass/fail:
  `/dev/nsm` open (ENOENT), `socket(AF_VSOCK)` and `socket(AF_INET)` (seccomp
  kill), `socket(AF_UNIX)` (allowed, shows the filter is precise),
  `io_uring_setup` (ENOSYS shim), `userfaultfd` and `unshare(CLONE_NEWUSER)`
  (seccomp kill), cross-job `/proc` (invisible in a fresh PID namespace), a
  memory hog (killed by the memcg while the parent survives), and the wall
  timeout (cgroup.kill);
- memory headroom (`MemTotal`/`MemAvailable` at boot, after Node, and the min
  sampled while a jailed worker runs) plus per-job `memory.peak` and wall time
  for the A1 stack — a generated 12 MP JPEG through **sharp** and a generated
  50-page PDF through **pdfjs-dist** (proving pdf.js extracts text without
  `@napi-rs/canvas`, §16 F2), with the corpus generated in-enclave from nothing;
- vsock throughput (MB/s) for the 16 MiB and 32 MiB streams;
- the EIF size (printed by `probe.sh`).

## Files

| File | Runs | Purpose |
|---|---|---|
| `Dockerfile.probe` | build | The probe image: `media-jail`, the C tests, the sharp/pdfjs worker stack, the runner. Same pinned base digests as `deploy/enclave/Dockerfile`. |
| `entrypoint-probe.sh` | enclave PID 1 | The §16.6 cgroup surgery + boot snapshots, then `exec node probe-report.mjs`. |
| `probe-report.mjs` | enclave | Orchestrates every section and prints the one JSON report. |
| `tests/jailtest.c` | jailed | One static binary; a sub-command per escape. |
| `tests/vsock-sink.c` | enclave | Times the parent's vsock streams. |
| `worker/{gen-corpus,image-probe,pdf-probe}.mjs` | enclave / jailed | Generate the corpus; the jailed sharp and pdfjs workers. |
| `worker/package.json` + lock | build | sharp 0.35.5, pdfjs-dist 6.3.289 (pinned); `@napi-rs/canvas` pruned after `npm ci`. |
| `probe.sh` | parent | The orchestration above. |
| `vsock-send.py` | parent | Streams 16 and 32 MiB to the enclave over vsock 9100. |

## Local validation (what was checked off-Nitro)

On an arm64 host with Docker (a real cgroup-v2 kernel), everything except the
Nitro boot and the vsock transfer was validated in a privileged container that
stands in for the enclave:

- `media-jail` builds `--locked`, its unit tests pass, `--self-check` runs;
- every `jailtest` behaves as required (seccomp kills VSOCK/INET/userfaultfd/
  userns with SIGSYS, `io_uring_setup`→ENOSYS, `AF_UNIX` allowed, cross-job
  `/proc` invisible, OOM at the memcg cap with the parent surviving, wall
  timeout via cgroup.kill, `/dev/nsm` absent);
- the whole probe image builds and `probe-report.mjs` produces a complete
  report with `jail.go == true` and the jailed sharp (12 MP) and pdfjs (50-page)
  workers succeeding with real `memory.peak` and wall times.

Only the Nitro enclave boot (PCRs, `/dev/nsm`, the real Nitro kernel's cgroup
layout) and the AF_VSOCK transfer need the actual hardware; those run when
`probe.sh` is executed on the parent.
