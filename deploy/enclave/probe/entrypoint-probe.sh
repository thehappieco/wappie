#!/bin/sh
# PID 1 of the A0 PROBE enclave (deploy/enclave/probe). This is the §16.6
# entrypoint change — unmount the v1 memory/pids/cpuset hierarchies, mount
# cgroup2 at /run/cg2 and enable the controllers — kept HERE, in the throwaway
# probe image, and NOT in the production deploy/enclave/entrypoint.sh. A1 moves
# the reviewed version into production; A0 must not change the released reader.
#
# The probe has no network, no KMS, no reader: it prepares the cgroups, snapshots
# the boot-time kernel state for the report, then runs the probe runner, whose
# JSON goes to the enclave console (readable because probe.sh runs the enclave
# with --debug-mode).
set -u

mkdir -p /run/probe
# The reader's secrets directory, created as production's entrypoint does, so
# the jail's `paths` test (it must be absent inside the jail) means something.
mkdir -p /run/wappie
chmod 0700 /run/wappie

# 1. Snapshot the boot layout BEFORE any cgroup surgery, so the report can show
#    what the Nitro init actually mounted (§16.6 open point: v1 vs v2).
uname -a > /run/probe/uname 2>/dev/null || true
cat /proc/meminfo > /run/probe/boot-meminfo 2>/dev/null || true
cat /proc/self/mountinfo > /run/probe/boot-mountinfo 2>/dev/null || true
cat /proc/cgroups > /run/probe/boot-cgroups 2>/dev/null || true
cat /proc/filesystems > /run/probe/boot-filesystems 2>/dev/null || true
# /dev/nsm mode and owner, raw, for the report (§16.6 S1).
if [ -e /dev/nsm ]; then
  ls -ln /dev/nsm > /run/probe/dev-nsm 2>/dev/null || true
else
  echo "absent" > /run/probe/dev-nsm
fi

# 2. The §16.6 cgroup block. Each controller lives in one hierarchy only, so
#    memory, pids and cpuset must leave any v1 mount before a cgroup2 mount can
#    own them. Record every step's outcome for the report.
{
  for c in memory pids cpuset; do
    if grep -q " /sys/fs/cgroup/$c cgroup " /proc/mounts 2>/dev/null; then
      if umount "/sys/fs/cgroup/$c" 2>/dev/null; then
        echo "v1 $c: unmounted"
      else
        echo "v1 $c: unmount FAILED"
      fi
    else
      echo "v1 $c: not a v1 mount"
    fi
  done

  mkdir -p /run/cg2
  if grep -q " /run/cg2 cgroup2 " /proc/mounts 2>/dev/null; then
    echo "cgroup2: already mounted at /run/cg2"
  elif mount -t cgroup2 cgroup2 /run/cg2 2>/dev/null; then
    echo "cgroup2: mounted at /run/cg2"
  else
    echo "cgroup2: mount FAILED"
  fi

  # cgroup2 forbids enabling controllers in a cgroup that still holds processes
  # (the "no internal processes" rule) unless it is the true root. In the
  # enclave /run/cg2 IS the true root, so this normally is not needed; the init
  # leaf move makes the probe work under a delegated (nested) cgroup too, and is
  # harmless in the enclave.
  mkdir -p /run/cg2/probe-init
  echo $$ > /run/cg2/probe-init/cgroup.procs 2>/dev/null || echo "init move: FAILED"

  if echo '+memory +pids +cpuset' > /run/cg2/cgroup.subtree_control 2>/dev/null; then
    echo "root subtree_control: [$(cat /run/cg2/cgroup.subtree_control 2>/dev/null)]"
  else
    echo "root subtree_control: WRITE FAILED"
  fi
  mkdir -p /run/cg2/media
  if echo '+memory +pids +cpuset' > /run/cg2/media/cgroup.subtree_control 2>/dev/null; then
    echo "media subtree_control: [$(cat /run/cg2/media/cgroup.subtree_control 2>/dev/null)]"
  else
    echo "media subtree_control: WRITE FAILED"
  fi
} > /run/probe/cgroup-setup 2>&1

# 3. hidepid, so a jailed job cannot read the parent Node's /proc entries even
#    before it gets its own PID namespace (§16.6).
mount -o remount,hidepid=invisible /proc 2>/dev/null || true

# 4. The probe runner. Its stdout is the enclave console; probe.sh captures it
#    between the report markers.
exec node /probe/probe-report.mjs
