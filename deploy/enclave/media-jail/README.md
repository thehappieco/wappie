# media-jail

The sandbox launcher for the attested reader's media parsers
(`docs/mcp-enclave.md` §16.6). A static aarch64 musl binary, built in the same
`rust:1-alpine` stage as `nsm-attest` and measured into PCR0.

**Status: A1.** The reader's Node runs every attachment parser through it
(§16.11), from `/usr/local/bin/media-jail` in the image (`deploy/enclave/Dockerfile`,
mode 0555, built with no cargo features). A2's heavy slot and its ffmpeg and
whisper profiles are deferred and absent.

## Invocation

```
media-jail --worker <image|pdf|office> --slot light --id <16 hex> \
           --mem-mb N --pids N --cpus LIST --wall-s N --tmp-mb N
media-jail --self-check
media-jail --table
```

There is no free-form program. `--worker` names a row of the compiled-in table
(`src/workers.rs`), which fixes the exact argv (`/usr/local/bin/node` with the
row's flags and `/opt/media/worker/<id>.mjs`), the seccomp profile and the
ceilings:

| `--worker` | Node flags | ceilings (mem MiB, wall s, pids, /tmp MiB) |
|---|---|---|
| `image` | `--max-old-space-size=128 --disallow-code-generation-from-strings` | 256, 10, 64, 16 |
| `pdf` | `--max-old-space-size=256 --disallow-code-generation-from-strings` | 384, 20, 64, 16 |
| `office` | `--max-old-space-size=256 --disallow-code-generation-from-strings --no-addons` | 384, 15, 64, 16 |

Every flag is required and every value must be positive and at most the row's
ceiling: there is no default that could drop a bound silently. An unknown
worker, `--slot heavy`, an `--id` that is not 16 lowercase hex characters, a
flag given twice or any value above the row exits `3` before anything is
created. `--table` prints the table as JSON (`{"workers":{"<id>":{"argv":[…],
"profile":"node-worker","max":{"mem_mb":…,"wall_s":…,"pids":…,"tmp_mb":…}}}}`);
the reader checks its `max` against §16.8's `WORKERS` at boot, and
`check-image.sh` at build. `--self-check` prints one JSON object of what the
kernel supports and runs nothing.

Exit codes (§16.6): `0` and `2` the worker's (done, refused); `1` and `4`-`123`
the worker's own non-zero exit; `3` a bad invocation or a setup error before
the fork; `124` wall timeout; `125` a killed job that could not be reaped;
`127` a child setup error after the fork; `137` OOM kill; `143` stopped by
SIGTERM, SIGINT or SIGHUP (how the reader stops a job), or the reader gone
before the job started; `128+n` the worker died of signal n (`159` a seccomp
kill). The worker is PID 1 of its PID namespace, which ignores a SIGABRT it
sends itself, so V8's `abort()` (the heap limit) ends in musl's deliberate
crash: `139`, where the same worker outside the jail exits `134`.
`--self-check` and `--table` exit `0`; `--self-check` exits `1` when a row's
profile does not assemble.

**Dying together.** media-jail asks the kernel for SIGTERM when the process
that started it (the reader's Node) dies (`PR_SET_PDEATHSIG`), and its child
asks for SIGKILL when media-jail dies, right after the uid drop that would
clear the request. The child's last write to the facts pipe fails if
media-jail is already gone, so the child dies before the exec: no job outlives
the process that wanted it.

## Kernel features: detected, with a fallback each

The installed Nitro blob kernel is **Linux 4.14** (`4.14.256-209.484.amzn2`,
nitro-cli 1.5.0; first probe run, 2026-09-28), older than much of what §16.6
assumed. media-jail never infers a feature from the version: it looks for the
interface file or asks the kernel, so the same binary runs on the blob and on a
newer kernel of our own. Every fallback keeps the §16.6 property:

| §16.6 wanted | Since | Without it (4.14) |
|---|---|---|
| `cpuset.cpus` on cgroup2 | 5.0 | the child pins itself with `sched_setaffinity` before the exec; `sched_setaffinity` is reserved, never allowlisted, so the worker cannot widen it (`cpu_pin: affinity`) |
| `cgroup.kill` | 5.14 | SIGKILL of the child, PID 1 of the job's PID namespace: the kernel kills every process in the namespace, and no job process can leave it (`kill_method: pid1`) |
| `memory.oom.group` | 4.19 | media-jail watches `memory.events` and, on the first `oom_kill`, kills the job the same way (`oom_group: media-jail`) |
| `memory.peak` | 5.19 | `memory.current` sampled every 50 ms, plus the worker's `ru_maxrss` from `wait4` |
| `pivot_root` of the current root | — | when the kernel answers `EINVAL` (the root is the initramfs itself, or not a mount root), the switch_root pattern: detach every other mount of the private namespace, `MS_MOVE` the new root over `/`, `chroot`, `chdir /` (`root_switch: move+chroot`) |
| `SECCOMP_RET_KILL_PROCESS` | 4.14 | `KILL_THREAD` (detected with `SECCOMP_GET_ACTION_AVAIL`, same release); 4.14 has it |
| `close_range` | 5.9 | the fds are listed from the jail's `/proc/self/fd` and closed one by one |

The move+chroot root is final only because the worker holds no capability and
the allowlist never grants a way out: the child empties the bounding, ambient
and inheritable sets while still root, `setresuid` clears permitted and
effective, and `verify_no_capabilities` checks all five sets before the exec
(`caps: cleared`, or the job does not start). `chroot`, `mount`, `umount2`,
`pivot_root`, `unshare`, `setns` and namespace-creating `clone` are never
allowlisted, the kernel refuses a user namespace to a chrooted process, and the
worker has no fd or cwd outside its root. The Nitro init binds `/rootfs` onto
itself, moves it over `/` and chroots, so `pivot_root` is expected to work in
the enclave; the status line says which path ran.

`io_uring_*` (5.1) and `clone3` (5.3) do not exist on 4.14; the seccomp shim
matches them by number anyway, so they answer `ENOSYS` on every kernel. No
filter flag is used (seccompiler installs each filter with `seccomp(2)`
`SECCOMP_SET_MODE_FILTER` and flags 0, Linux 3.17).

**Test builds only: `MEDIA_JAIL_EMULATE`.** A binary built with
`--features emulate-old-kernel` reads `MEDIA_JAIL_EMULATE` (comma-separated
`no-cgroup-kill`, `no-oom-group`, `no-peak`, `no-swap-max`, `no-cpuset`,
`no-pivot-root`, `kill-thread`) and treats those features as missing, so the
4.14 paths run on a newer test kernel (`no-swap-max` is not a 4.14 gap: the
blob has swap accounting). A token can only take a feature away; the status
line and `--self-check` list what was emulated. The image's binary is built
without the feature and never reads the variable (`check-image.sh` checks
that); `check-image.sh --jail` runs the whole jail check a second time with a
test build and every 4.14 token (`src/emulate.rs`).

## What it does (src/jail.rs)

1. Compiles the seccomp filters for the profile (fails early on a bad profile).
2. Creates a cgroup v2 leaf `/run/cg2/media/<slot>-<id>` with `memory.max`,
   `memory.swap.max=0` and `pids.max`, plus `memory.oom.group=1` and
   `cpuset.cpus` where the kernel has them (removed again if any write fails).
   A kernel without swap accounting has no `memory.swap.max`; that is accepted
   only when `/proc/swaps` lists no device. Like the other optional files it is
   detected by its presence (cgroupfs answers a write to a missing file with
   `EACCES`, so the write's error cannot tell). `memory.max` and `pids.max` are
   never optional.
3. Unshares a PID namespace and forks; the child is PID 1 of it. The parent
   stays in the host mount namespace so it can drive cgroupfs by path.
4. Moves the child into the leaf, then releases it (a sync pipe), so every page
   the worker touches is charged to the memcg.
5. The child unshares mount/net/ipc/uts for itself, makes propagation private,
   builds a minimal root on a tmpfs, `pivot_root`s into it (or, when the kernel
   refuses, moves it over `/` and chroots, see above) and detaches the old
   root. The root holds only the profile's compiled-in binds (`profile.rs`;
   for `node-worker`: `/lib`, `/usr/lib`, `/usr/local/bin/node` and the worker
   tree `/opt/media`), a size-capped tmpfs
   `/tmp`, a `/dev` with only `null`, `zero` and `urandom`, and a fresh
   `/proc`. The binds are non-recursive, so a submount never enters the jail,
   and read-only, nosuid, nodev; the root and `/dev` are then remounted
   read-only too, leaving `/tmp` the only writable place. No `/dev/nsm`,
   `/run/wappie`, `/run/cg2`, `/sys`, `/etc` or the rest of `/usr/local/bin`
   (media-jail itself, `nsm-attest` and `socat`) is reachable.
6. Sets `oom_score_adj=1000` and the slot `nice`, pins the CPUs when the leaf
   has no cpuset, applies RLIMITs (NOFILE 64, FSIZE = tmp, CORE 0; RLIMIT_AS
   deliberately unset for Node, §16.6 step 4), empties the bounding, ambient and
   inheritable capability sets, drops to the light slot's uid/gid 65533, asks
   for SIGKILL if media-jail dies, and verifies root cannot be regained and
   every capability set is empty.
7. Sets `PR_SET_NO_NEW_PRIVS`, closes every fd above 2 and points fd 2 at
   `/dev/null` (§16.6 step 7), installs the seccomp allowlist, and `execve`s
   the worker's row with exactly the §16.6 environment (`UV_USE_IO_URING=0`,
   `PATH`, `HOME=/tmp`, `TMPDIR=/tmp`, `OPENSSL_armcap=0`; no `VIPS_*`, so a
   worker configures libvips in code). A close-on-exec copy of the real stderr
   carries the child's own last errors (for example a failed `execve`) until
   the exec.

The parent waits, enforcing the wall timeout and acting on a stop signal, then
reads `memory.events` / `memory.peak` and prints a one-line JSON status on
**stderr**. The reader spawns media-jail with stderr ignored, so no per-job
figure leaves the process (§16.10); the probe and the jail check read it. The
worker's own stderr is `/dev/null`, so that line cannot be forged or garbled by
the worker.
The timeout writes `cgroup.kill` where it exists; if it does not (before Linux
5.14) or the child is still there 2 s later, media-jail SIGKILLs the child,
which is PID 1 of the job's PID namespace, so the kernel kills every other
process in it. The status says which (`kill_method`: `cgroup.kill`,
`cgroup.kill+pid1` or `pid1`) and whether the child was reaped; media-jail never
blocks on a job that will not die. While the job runs, `memory.current` is
sampled every 50 ms (`memory_current_max_bytes`) for kernels without
`memory.peak` (5.19), and without `memory.oom.group` the first `oom_kill` in
`memory.events` ends the job.

Besides the outcome, the status line carries how the jail was built: the
child's host pid (`child_pid`, the pid kernel messages name), `root_switch`
(`pivot_root` or `move+chroot`, reported by the child over a close-on-exec
pipe just before the exec), `caps` (`cleared`), `cpu_pin`, `oom_group`,
`seccomp_kill`, which optional `cgroup` files were used, `ru_maxrss_kb` and
`emulated`. media-jail keeps itself out of the job cgroup so a
`cgroup.kill` cannot take it down; the reader never touches cgroupfs and stops
a job with SIGTERM to media-jail (§16.6 "Killing a job").

## Seccomp (src/seccomp.rs, profiles/*.txt)

Two stacked cBPF filters, evaluated together (most restrictive action wins):

- **ALLOW** — every profile syscall plus the code-owned argument-filtered calls
  (`socket`/`socketpair` only `AF_UNIX`; `clone` only without a `CLONE_NEW*`
  flag; `ioctl` only a tiny request set that excludes the NSM ioctl; `prctl`
  only name/VMA) → `Allow`, everything else → `KILL_PROCESS` (`KILL_THREAD` on
  a kernel before 4.14). `io_uring_*` and
  `clone3` are allowed unconditionally here only so the shim decides them;
  clone3's flags sit behind a pointer, so it cannot be argument-filtered.
- **SHIM** — `io_uring_setup`/`enter`/`register` and `clone3` → `ENOSYS`, so
  libuv and glibc fall back rather than being killed.

A `profiles/*.txt` file is a plain allowlist of the syscalls one workload needs;
it may never list a reserved name (the argument-filtered, ENOSYS or
always-denied calls, and `chroot` and `sched_setaffinity`, which the 4.14
fallbacks rely on), so a profile edit can only widen the plain set. A1 ships
`node-worker`, used by every row of the table; `ffmpeg` and `whisper` are A2,
deferred. `node-worker.txt` is exactly what the three workers made over the
whole §16.13 corpus, traced inside the jail
(`deploy/enclave/jailcheck/trace-profile.sh <image>`, which prints the traced
set against the file), plus a reviewed reserve with the reason for each entry.
A missing syscall is a seccomp kill (`159`), never a bypass, and
`check-image.sh --jail` fails on one.

## Building and testing

```
# in a rust:1-alpine (aarch64) stage — how the Dockerfile builds it
cargo build --locked --release            # → target/release/media-jail (static)
cargo test  --locked                      # pure-Rust: args, table, profiles, seccomp compile
cargo test  --locked --features emulate-old-kernel

# the whole jail, on an arm64 host with Docker (privileged, cgroup v2):
deploy/enclave/check-image.sh --jail <reader image>
```

`check-image.sh --jail` (`deploy/enclave/jailcheck`) runs the entrypoint's own
cgroup block in a privileged container, then the A0 probe's escape tests from
a stand-in `/opt/media` (its driver execs `jailtest` as the worker), the A1
checks (the table, refusals, SIGTERM, a dying reader), every corpus file
through the real workers as the reader's own `runWorker` runs and reads them,
and the reader's end-to-end test (`open_attachment` over `/mcp` to the jailed
workers, `enclave/test/media-e2e.test.mjs`); then all of it again with a test
build and every 4.14 token. The A0 probe (`deploy/enclave/probe`) still drives the A0
command line (`--profile … -- <program>`), which this binary no longer
accepts: before the probe enclave runs the A1 jail checks on the real kernel,
its runner moves to `deploy/enclave/jailcheck`.

`cargo test` needs the aarch64 Linux target (the syscall numbers and seccompiler
are Linux-only), so it runs in the same stage the Dockerfile uses, not on the
build host.
