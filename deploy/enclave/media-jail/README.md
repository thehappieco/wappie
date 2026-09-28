# media-jail

The sandbox launcher for the attested reader's media parsers
(`docs/mcp-enclave.md` §16.6). A static aarch64 musl binary, built in the same
`rust:1-alpine` stage as `nsm-attest` and measured into PCR0.

**Status: A0 prototype.** This is the groundwork the go/no-go probe
(`deploy/enclave/probe`) runs against a real Nitro kernel. It is enough to prove
the jail works; the A1 production wiring (the compiled-in argv table, the worker
protocol, native ffmpeg/whisper profiles, the pipeline slots) is built on top of
it and is not here yet. `media-jail` is **never part of a released reader** until
A1 adds it to `deploy/enclave/Dockerfile` — see §16.6 and the A0 task notes.

## Invocation

```
media-jail --profile <name> --slot <heavy|light> --mem-mb N --pids N \
           --cpus LIST --wall-s N [--id STR] [--tmp-mb N] -- <program> [args…]
media-jail --self-check
```

Every limit is required for a run: there is no permissive default that could
drop a bound silently. `--self-check` prints one JSON object of what the kernel
supports and runs nothing.

Exit codes: the worker's own on a clean exit; `124` wall timeout; `137` OOM
kill; `128+signal` on any other signal (a seccomp kill is `159` = 128+SIGSYS);
`3` a bad invocation or a setup error before the worker starts; `127` a child
setup error after the fork. `--self-check` exits `0` when the seccomp assembler
works.

## What it does (src/jail.rs)

1. Compiles the seccomp filters for the profile (fails early on a bad profile).
2. Creates a cgroup v2 leaf `/run/cg2/media/<slot>-<id>` with `memory.max`,
   `memory.swap.max=0`, `memory.oom.group=1`, `pids.max` and `cpuset.cpus`.
3. Unshares a PID namespace and forks; the child is PID 1 of it. The parent
   stays in the host mount namespace so it can drive cgroupfs by path.
4. Moves the child into the leaf, then releases it (a sync pipe), so every page
   the worker touches is charged to the memcg.
5. The child unshares mount/net/ipc/uts for itself, makes propagation private,
   builds a minimal read-only root (read-only binds of `/lib`, `/usr`, `/bin`,
   `/sbin`, `/opt`; a size-capped tmpfs `/tmp`; a minimal `/dev`; a fresh
   `/proc`), `pivot_root`s into it and detaches the old root. No `/dev/nsm`,
   `/run/wappie`, `/run/cg2`, `/sys` or `/etc` is reachable.
6. Sets `oom_score_adj=1000` and the slot `nice`, applies RLIMITs (NOFILE 64,
   FSIZE = tmp, CORE 0; RLIMIT_AS deliberately unset for Node, §16.6 step 4),
   drops to the slot uid/gid (65532 heavy, 65533 light) and verifies root cannot
   be regained.
7. Sets `PR_SET_NO_NEW_PRIVS`, installs the seccomp allowlist, and `execve`s the
   program with a controlled environment (`UV_USE_IO_URING=0`).

The parent waits, enforcing the wall timeout with `cgroup.kill`, then reads
`memory.events` / `memory.peak` and prints a one-line JSON status on **stderr**
(so it never mixes with worker stdout). It keeps itself out of the job cgroup so
a `cgroup.kill` cannot take it down — the one deviation from annex §16.6 step 1,
which had the main Node hold the timeout; the A0 task gives `media-jail` the
wall enforcement.

## Seccomp (src/seccomp.rs, profiles/*.txt)

Two stacked cBPF filters, evaluated together (most restrictive action wins):

- **ALLOW** — every profile syscall plus the code-owned argument-filtered calls
  (`socket`/`socketpair` only `AF_UNIX`; `clone`/`clone3` only without a
  `CLONE_NEW*` flag; `ioctl` only a tiny request set that excludes the NSM
  ioctl; `prctl` only name/VMA) → `Allow`, everything else → `KILL_PROCESS`.
- **SHIM** — `io_uring_setup`/`enter`/`register` and `clone3` → `ENOSYS`, so
  libuv and glibc fall back rather than being killed.

A `profiles/*.txt` file is a plain allowlist of the syscalls one workload needs;
it may never list a reserved name (the argument-filtered, ENOSYS or
always-denied calls), so a profile edit can only widen the plain set. A0 ships
`node-worker`; `ffmpeg` and `whisper` are A2. The shipped profiles are generated
by `strace -f` over the §4 corpus and reviewed — the committed `node-worker.txt`
is a reviewed starting point that the probe refines against real Node + sharp +
pdfjs.

## Building and testing

```
# in a rust:1-alpine (aarch64) stage — how the Dockerfile builds it
cargo build --locked --release            # → target/release/media-jail (static)
cargo test  --locked                      # pure-Rust: args, profiles, seccomp compile

# smoke on any arm64 host with Docker (a cgroup-v2 kernel):
docker run --rm --privileged media-jail --self-check
```

`cargo test` needs the aarch64 Linux target (the syscall numbers and seccompiler
are Linux-only), so it runs in the same stage the Dockerfile uses, not on the
build host.
