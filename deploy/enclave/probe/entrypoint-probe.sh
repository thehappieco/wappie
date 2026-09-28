#!/bin/sh
# The CMD of the A0 PROBE enclave (deploy/enclave/probe), started by the Nitro
# init. This is the §16.6 entrypoint change — unmount the v1 memory/pids/cpuset
# hierarchies, mount cgroup2 at /run/cg2 and enable the controllers — kept HERE,
# in the throwaway probe image, and NOT in the production
# deploy/enclave/entrypoint.sh. A1 moves the reviewed version into production;
# A0 must not change the released reader.
#
# The probe has no network, no KMS, no reader: it prepares the cgroups,
# snapshots the boot-time kernel state, then runs the probe runner, whose report
# goes to the enclave console (readable because probe.sh runs the enclave with
# --debug-mode).
#
# The console must explain the run even if Node dies: the first Nitro run
# (2026-09-28) showed only kernel lines. So everything goes to /dev/console
# explicitly, every step prints a numbered marker before it runs, a trivial
# node runs first, the runner is a CHILD (never exec'd) so its exit code or
# signal is printed, the raw /run/probe files are printed, and the END marker is
# followed by a pause so the console drains before this script exits (the init
# then reboots the enclave).
#
# Environment (local smoke test only; unset in the enclave):
#   PROBE_CONSOLE=-               keep stdout instead of /dev/console
#   PROBE_EMULATE_OLD_KERNEL=1    behave as on the 4.14 blob on a newer kernel:
#                                 no cpuset on cgroup2 (the runner tells
#                                 media-jail the rest)
set -u

console=${PROBE_CONSOLE:-/dev/console}
if [ "$console" != - ]; then
  if { : > "$console"; } 2> /dev/null; then
    exec > "$console" 2>&1
  else
    echo "A0 console $console is not writable; staying on stdout"
  fi
fi
emulate=${PROBE_EMULATE_OLD_KERNEL:-0}

up() { cut -d' ' -f1 /proc/uptime 2> /dev/null; }
n=0
step() {
  n=$((n + 1))
  echo "A0 STEP $n t=$(up) $*"
}

# Run a command in the background so its pid can be printed (a kernel report
# about it, such as a SIGILL, names that pid), wait for it, and print how it
# ended: "exit N" or "signal N". Recorded in /run/probe/processes for the
# runner, which matches kernel lines to processes.
run_logged() {
  label=$1
  shift
  "$@" &
  pid=$!
  echo "A0 PID $pid $label: $*"
  wait "$pid"
  rc=$?
  if [ "$rc" -gt 128 ]; then how="signal $((rc - 128))"; else how="exit $rc"; fi
  echo "A0 EXIT $pid $label: $how"
  echo "$label pid=$pid rc=$rc" >> /run/probe/processes
  return "$rc"
}

# A controller an unmounted v1 hierarchy held comes back to cgroup2 only once
# the kernel has released that hierarchy, which is asynchronous: wait up to
# ~3 s for it to be offered. Each controller is enabled with its own write, at
# the root and at /run/cg2/media, because one write naming a controller the
# kernel's cgroup2 lacks (cpuset before 5.0) fails as a whole: on the first
# Nitro run '+memory +pids +cpuset' left memory and pids off too.
enable_controller() {
  c=$1
  tries=0
  while ! grep -qw "$c" /run/cg2/cgroup.controllers 2> /dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 15 ]; then
      echo "controller $c: not offered by cgroup2 (cgroup.controllers: $(cat /run/cg2/cgroup.controllers))"
      return 1
    fi
    sleep 0.2
  done
  if ! err=$( { echo "+$c" > /run/cg2/cgroup.subtree_control; } 2>&1 ); then
    echo "controller $c: root enable FAILED ($err)"
    return 1
  fi
  if ! err=$( { echo "+$c" > /run/cg2/media/cgroup.subtree_control; } 2>&1 ); then
    echo "controller $c: media enable FAILED ($err)"
    return 1
  fi
  echo "controller $c: enabled (waited $tries x 0.2 s)"
}

cgroup_setup() {
  for c in memory pids cpuset; do
    if grep -q " /sys/fs/cgroup/$c cgroup " /proc/mounts; then
      if umount "/sys/fs/cgroup/$c"; then
        echo "v1 $c: unmounted"
      else
        echo "v1 $c: unmount FAILED"
      fi
    else
      echo "v1 $c: not a v1 mount"
    fi
  done

  mkdir -p /run/cg2
  if grep -q " /run/cg2 cgroup2 " /proc/mounts; then
    echo "cgroup2: already mounted at /run/cg2"
  elif mount -t cgroup2 cgroup2 /run/cg2; then
    echo "cgroup2: mounted at /run/cg2"
  else
    echo "cgroup2: mount FAILED"
    return 1
  fi

  # cgroup2 forbids enabling controllers in a cgroup that still holds processes
  # (the "no internal processes" rule) unless it is the true root. In the
  # enclave /run/cg2 IS the true root, so this normally is not needed; the init
  # leaf move makes the probe work under a delegated (nested) cgroup too, and is
  # harmless in the enclave.
  mkdir -p /run/cg2/probe-init /run/cg2/media
  echo $$ > /run/cg2/probe-init/cgroup.procs || echo "init move: FAILED"

  # memory and pids are required; cpuset is used where the kernel has it on
  # cgroup2 (5.0+), else media-jail pins jobs with sched_setaffinity.
  wanted="memory pids cpuset"
  [ "$emulate" = 1 ] && wanted="memory pids"
  for c in $wanted; do
    enable_controller "$c"
  done
  echo "root subtree_control: [$(cat /run/cg2/cgroup.subtree_control)]"
  echo "media subtree_control: [$(cat /run/cg2/media/cgroup.subtree_control)]"
}

node_trivial='const fs=require("fs"),os=require("os");fs.writeSync(1,"A0 NODE "+JSON.stringify({pid:process.pid,version:process.version,arch:process.arch,release:os.release(),openssl:process.versions.openssl,armcap:process.env.OPENSSL_armcap||null,sha256:require("crypto").createHash("sha256").update("a0").digest("hex").slice(0,16)})+"\n")'

echo '===WAPPIE-A0-PROBE-BEGIN==='
# A mark in the kernel log itself: the runner reads the kernel's reports about
# this run (SIGILLs, seccomp kills, OOM) from /dev/kmsg after it, and on the
# console it dates the start in kernel time.
echo "wappie-a0: probe entrypoint started" > /dev/kmsg 2> /dev/null
step "entrypoint: pid $$, kernel $(uname -r), emulate-old-kernel=$emulate"
mkdir -p /run/probe
# The reader's secrets directory, created as production's entrypoint does, so
# the jail's `paths` test (it must be absent inside the jail) means something.
mkdir -p /run/wappie
chmod 0700 /run/wappie

step "boot snapshots to /run/probe, before any cgroup surgery"
uname -a > /run/probe/uname 2>&1
cat /proc/meminfo > /run/probe/boot-meminfo 2>&1
cat /proc/self/mountinfo > /run/probe/boot-mountinfo 2>&1
cat /proc/cgroups > /run/probe/boot-cgroups 2>&1
cat /proc/filesystems > /run/probe/boot-filesystems 2>&1
cat /proc/cmdline > /run/probe/cmdline 2>&1
grep '^Features' /proc/cpuinfo | head -n 1 > /run/probe/cpu-features
# /dev/nsm mode and owner, raw, for the report (§16.6 S1).
if [ -e /dev/nsm ]; then
  ls -ln /dev/nsm > /run/probe/dev-nsm 2>&1
else
  echo "absent" > /run/probe/dev-nsm
fi

step "node, trivially: expect one kernel 'Bad EL0 ... code 0x66000000' line for this pid on a pre-SVE kernel (OpenSSL's SVE probe, caught by OpenSSL)"
run_logged node-trivial node -e "$node_trivial"
step "node again with OPENSSL_armcap=0 (OpenSSL skips its probes): expect NO kernel line for this pid"
run_logged node-trivial-armcap0 env OPENSSL_armcap=0 node -e "$node_trivial"

step "cgroup: v1 memory/pids/cpuset out, cgroup2 at /run/cg2, controllers one at a time"
cgroup_setup > /run/probe/cgroup-setup 2>&1
cat /run/probe/cgroup-setup

# So a jailed job cannot read the runner's /proc entries even before it gets
# its own PID namespace (§16.6). hidepid=2 is the same mode 5.8 named
# "invisible", and every kernel takes the number, while 4.14 refuses the name
# (the first run's console: "proc: unrecognized mount option"). The flags the
# init mounted /proc with are restated, because a remount resets them, and the
# source is named, because busybox mount cannot always find /proc in
# /proc/mounts by itself.
step "hidepid=2 on /proc"
if mount -o remount,nosuid,nodev,noexec,hidepid=2 proc /proc; then
  hidepid=2
else
  hidepid=none
fi
echo "hidepid=$hidepid ($(grep ' /proc proc ' /proc/mounts))" > /run/probe/hidepid
cat /run/probe/hidepid

step "heartbeat every 10 s while the runner works"
(while :; do sleep 10; echo "A0 ALIVE t=$(up)"; done) &
beat=$!

step "runner: node /probe/probe-report.mjs, as a child"
run_logged runner node /probe/probe-report.mjs
kill "$beat" 2> /dev/null

step "raw /run/probe files"
for f in /run/probe/*; do
  [ -f "$f" ] || continue
  echo "A0 FILE $f BEGIN"
  cat "$f"
  echo "A0 FILE $f END"
done

step "end"
echo '===WAPPIE-A0-PROBE-END==='
# Let the console drain before this script (the init's only child) exits and
# the init reboots the enclave.
sleep 5
exit 0
