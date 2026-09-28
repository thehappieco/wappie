### Kernel 4.14 amendments

To append to `docs/mcp-enclave.md` §16 (amends §16.6, updates §16.14). Source:
the first A0 probe run on the pilot parent, 2026-09-28, and the code in
`deploy/enclave/media-jail` and `deploy/enclave/probe` that answers it.

**Fact.** The enclave kernel is the nitro-cli 1.5.0 blob, **Linux
4.14.256-209.484.amzn2.aarch64** (built 2022-01-11; the upstream 4.14 series
reached end of life in January 2024). The Nitro init mounts every enabled
controller as its own cgroup v1 hierarchy at `/sys/fs/cgroup/<name>`, and enters
the root by binding `/rootfs` onto itself, moving it over `/` and chrooting.
The CPU is Graviton3 (Neoverse V1), which has SVE; 4.14 predates kernel SVE
support.

**§16.6, entrypoint.** Enable each controller with its own write, at the root
and at `media`, after waiting (up to ~3 s) for it to appear in
`cgroup.controllers`: an unmounted v1 hierarchy is released asynchronously,
and one write naming a controller the kernel's cgroup2 lacks fails as a whole
(`'+memory +pids +cpuset'` left memory and pids off on 4.14, which has no
cgroup2 cpuset). Remount `/proc` with `nosuid,nodev,noexec,hidepid=2`:
`hidepid=invisible` is only 5.8's name for mode 2, and 4.14 refuses the name.

**§16.6, boot check.** `media/cgroup.subtree_control` must contain `memory` and
`pids`; `cpuset` is used where present, not required.

**§16.6, media-jail.** Features are detected, never inferred from the version,
and each missing one has a fallback with the same guarantee:

- step 1: `memory.max` and `pids.max` are required; `memory.oom.group=1` and
  `cpuset.cpus` are written where the leaf has them. Without cpuset the child
  pins itself with `sched_setaffinity`, which is added to the always-absent
  syscalls.
- step 3: `pivot_root`; if the kernel answers `EINVAL` (a root that is the
  initramfs itself or not a mount root), detach every other mount of the
  private namespace, `MS_MOVE` the new root over `/`, `chroot`, `chdir /`.
  `chroot` is added to the always-absent syscalls. The Nitro init's bind mount
  makes `pivot_root` the expected path in the enclave; the status line says
  which ran.
- step 5: before the uid drop, empty the bounding, ambient and inheritable
  capability sets; after it, verify all five sets are empty or refuse to run
  the job. This, NO_NEW_PRIVS and the allowlist are what make the chroot
  fallback final.
- step 6: the default action is `SECCOMP_RET_KILL_PROCESS` where
  `SECCOMP_GET_ACTION_AVAIL` confirms it (both 4.14), else `KILL_THREAD`.
  Filters are installed with flags 0 (`seccomp(2)`, 3.17). `io_uring_*` and
  `clone3` do not exist on 4.14 and still get the ENOSYS shim, by number.
- step 7: close the fds with `close_range` (5.9), else from `/proc/self/fd`.

**§16.6, killing a job.** `cgroup.kill` where present (5.14); otherwise SIGKILL
of the job's PID-namespace init (media-jail's child), which the kernel turns
into the death of every process in the namespace, and no job process can leave
it. Without `memory.oom.group` (4.19), media-jail ends the job the same way on
the first `oom_kill` in `memory.events` (present since 4.13). The job's memory
figure is `memory.peak` (5.19), else `memory.current` sampled every 50 ms plus
the worker's `ru_maxrss`.

**§16.6, kernel requirements.** Required and present on the blob:
`CONFIG_MEMCG`, `CONFIG_CGROUP_PIDS`, `CONFIG_SECCOMP_FILTER`, `CONFIG_PID_NS`,
`CONFIG_NET_NS`. `CONFIG_CPUSETS` is no longer required (v1 only on 4.14).
Recorded: `CONFIG_USER_NS=y`, `CONFIG_USERFAULTFD=y` (both denied by the
allowlist; a chrooted process cannot create a user namespace either), no
io_uring.

**Node on the blob.** Every node start takes one SIGILL, printed by the kernel
as `Bad EL0 synchronous exception ... code 0x66000000 -- UNRECOGNIZED EC`: OpenSSL
3.5.8 (bundled in Node 22.23.3, musl, so no `getauxval`) probes for SVE by
executing `eor z0.d, z0.d, z0.d` under a SIGILL handler, and 4.14 traps the
instruction (ESR class 0x19) and sends SIGILL. OpenSSL catches it; it is
harmless and costs nothing but the console line. `OPENSSL_armcap` set in the
environment skips the probe.

**§16.14 updates.** Kernel: 4.14, above. `CONFIG_IO_URING`: the syscalls do not
exist (5.1). The v1 layout: one hierarchy per controller (the init source);
whether unmounting memory and pids frees them for cgroup2 is the next probe
run's `cgroup.setup_log`. Node in the pinned digest: 22.23.3 (≥ 22.13 for
pdf.js).

**Facts for A1's decision: stay on the blob kernel, or build our own.**

| §16.6 wanted | Needs | On 4.14 | What the fallback costs |
|---|---|---|---|
| cgroup2 cpuset | 5.0 | absent | nothing for one job per slot: the mask is inherited and cannot be widened; the kernel no longer enforces it against the job's own `sched_setaffinity`, the allowlist does |
| `cgroup.kill` | 5.14 | absent | nothing: killing the PID-namespace init is equally total |
| `memory.oom.group` | 4.19 | absent | up to one 50 ms poll between the first OOM kill and the rest of the job |
| `memory.peak` | 5.19 | absent | measurement only: spikes shorter than 50 ms are missed by `memory.current` sampling (`ru_maxrss` bounds the worker's RSS) |
| `hidepid=invisible` | 5.8 | as `hidepid=2` | nothing (same mode) |
| `pivot_root` | — | expected to work | if not: the move+chroot root, final only with the capability and allowlist rules above |
| `SECCOMP_RET_KILL_PROCESS` | 4.14 | present | — |
| `pidfd_open` | 5.3 | absent | the main Node kills by pid; the PID namespace bounds a job |
| `close_range` | 5.9 | absent | nothing (fd walk) |
| io_uring, clone3 | 5.1, 5.3 | absent | nothing (shim kept for newer kernels) |
| kernel SVE | 4.15 | absent | Graviton3's SVE unused (libvips/highway run NEON); one handled SIGILL per node start |
| kernel maintenance | — | 4.14 LTS ended January 2024; blob built 2022-01-11 | security fixes depend on AWS shipping a new blob |

A kernel of our own would restore every row but costs building, measuring
(PCR0) and maintaining it; the blob keeps AWS's kernel and needs only the
fallbacks above, all of which run on newer kernels unchanged.
