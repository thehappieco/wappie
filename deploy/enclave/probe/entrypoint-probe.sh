#!/bin/sh
# The entrypoint of the A1 PROBE enclave (deploy/enclave/probe), started by
# the Nitro init. The image is the A1 reader image with the jail check on top
# (Dockerfile.probe); this script prepares the enclave the way the production
# entrypoint does and then runs the probe runner, whose report goes to the
# enclave console (readable because probe.sh runs the enclave with
# --debug-mode). It never starts the reader's own Node: probe-report.mjs runs
# a stand-in (reader-bench.mjs).
#
# What production does, it does with production's own lines: loopback up,
# /run/wappie, and the media jail block (the cgroup2 surgery, hidepid=2 and
# oom_score_adj -1000), which is taken from /entrypoint.sh at run time as
# jailcheck/run.sh takes it, so what is measured is what ships. Its trace
# goes to /run/probe/cgroup-setup.
#
# The console must explain the run even if Node dies (the A0 lesson): so
# everything goes to /dev/console explicitly, every step prints a numbered
# marker before it runs, a trivial node runs first, the runner is a CHILD
# (never exec'd) so its exit code or signal is printed, the raw /run/probe
# files are printed, and the END marker is followed by a pause so the console
# drains before this script exits (the init then reboots the enclave).
#
# Environment (a local smoke run only; unset in the enclave):
#   PROBE_CONSOLE=-            keep stdout instead of /dev/console
#   PROBE_VSOCK_TIMEOUT_MS=N   how long the throughput sink waits for the parent
#   PROBE_OBJECTS=loopback     the reader stand-in serves its documents itself
#   PROBE_PARENT_CID=N         the parent's vsock CID (3; 1 for vsock loopback)
set -u

console=${PROBE_CONSOLE:-/dev/console}
if [ "$console" != - ]; then
  if { : > "$console"; } 2> /dev/null; then
    exec > "$console" 2>&1
  else
    echo "A1 console $console is not writable; staying on stdout"
  fi
fi

up() { cut -d' ' -f1 /proc/uptime 2> /dev/null; }
n=0
step() {
  n=$((n + 1))
  echo "A1 STEP $n t=$(up) $*"
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
  echo "A1 PID $pid $label: $*"
  wait "$pid"
  rc=$?
  if [ "$rc" -gt 128 ]; then how="signal $((rc - 128))"; else how="exit $rc"; fi
  echo "A1 EXIT $pid $label: $how"
  echo "$label pid=$pid rc=$rc" >> /run/probe/processes
  return "$rc"
}

node_trivial='const fs=require("fs"),os=require("os");fs.writeSync(1,"A1 NODE "+JSON.stringify({pid:process.pid,version:process.version,arch:process.arch,release:os.release(),openssl:process.versions.openssl,armcap:process.env.OPENSSL_armcap||null,sha256:require("crypto").createHash("sha256").update("a1").digest("hex").slice(0,16)})+"\n")'

echo '===WAPPIE-A1-PROBE-BEGIN==='
# A mark in the kernel log itself: the runner reads the kernel's reports about
# this run (SIGILLs, seccomp kills, OOM) from /dev/kmsg after it, and on the
# console it dates the start in kernel time.
echo "wappie-a1: probe entrypoint started" > /dev/kmsg 2> /dev/null
step "entrypoint: pid $$, kernel $(uname -r)"
mkdir -p /run/probe

step "loopback up, as the production entrypoint brings it up"
ip addr add 127.0.0.1/8 dev lo 2> /dev/null || true
ip link set dev lo up || echo "A1 loopback: ip link set dev lo up FAILED"
# The reader's secrets directory, as production's entrypoint makes it before
# the media jail block, so the escape tests' `paths` check means something.
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

step "the production media jail block, from /entrypoint.sh, traced to /run/probe/cgroup-setup"
sed -n '/^# Media jail (docs\/mcp-enclave.md §16.6)/,/^echo -1000 > \/proc\/self\/oom_score_adj/p' /entrypoint.sh > /run/probe/media-block.sh
if grep -q '^echo -1000 > /proc/self/oom_score_adj' /run/probe/media-block.sh; then
  # In the enclave /run/cg2 is the true root, where controllers can be enabled
  # while it holds processes. A privileged container's cgroup namespace root
  # (the local smoke run) is not, so this shell leaves it first, as
  # jailcheck/run.sh does.
  if grep -q ' /sys/fs/cgroup cgroup2 ' /proc/mounts; then
    mkdir -p /sys/fs/cgroup/probe-init
    echo $$ > /sys/fs/cgroup/probe-init/cgroup.procs || echo "A1 cgroup: could not leave the namespace root"
  fi
  # Sourced, not run: oom_score_adj -1000 is this shell's, and the runner and
  # every Node it starts inherit it, as the reader's Node does in production.
  exec 3>&2 2> /run/probe/cgroup-setup
  set -x
  # shellcheck disable=SC1091 # extracted from the image at run time.
  . /run/probe/media-block.sh
  set +x
  exec 2>&3 3>&-
  {
    echo "cgroup.controllers: [$(cat /run/cg2/cgroup.controllers 2>&1)]"
    echo "root subtree_control: [$(cat /run/cg2/cgroup.subtree_control 2>&1)]"
    echo "media subtree_control: [$(cat /run/cg2/media/cgroup.subtree_control 2>&1)]"
    echo "proc: $(grep ' /proc proc ' /proc/mounts)"
    echo "oom_score_adj: $(cat /proc/self/oom_score_adj)"
  } >> /run/probe/cgroup-setup 2>&1
else
  echo "A1 no media jail block in /entrypoint.sh" | tee /run/probe/cgroup-setup
fi
tail -n 5 /run/probe/cgroup-setup

step "heartbeat every 10 s while the runner works"
(while :; do sleep 10; echo "A1 ALIVE t=$(up)"; done) &
beat=$!

step "runner: node /probe/probe-report.mjs, as a child"
run_logged runner node /probe/probe-report.mjs
kill "$beat" 2> /dev/null

step "raw /run/probe files"
for f in /run/probe/*; do
  [ -f "$f" ] || continue
  echo "A1 FILE $f BEGIN"
  cat "$f"
  echo "A1 FILE $f END"
done

step "end"
echo '===WAPPIE-A1-PROBE-END==='
# Let the console drain before this script (the init's only child) exits and
# the init reboots the enclave.
sleep 5
exit 0
