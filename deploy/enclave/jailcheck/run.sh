#!/bin/sh
# PID 1 of the jail check (check-image.sh --jail): a privileged container
# standing in for the enclave. It runs the production entrypoint's own media
# jail block, taken from /entrypoint.sh, so what is checked is what ships,
# then jail-check.mjs.
set -eu

# cgroup2 lets a cgroup enable controllers for its children only while it
# holds no process, except at the true root. The enclave's /run/cg2 is the
# true root; a container's is not, so this shell leaves it first.
mkdir -p /sys/fs/cgroup/jailcheck
echo $$ > /sys/fs/cgroup/jailcheck/cgroup.procs

sed -n '/^# Media jail (docs\/mcp-enclave.md §16.6)/,/^echo -1000 > \/proc\/self\/oom_score_adj/p' /entrypoint.sh > /tmp/media-block.sh
grep -q '^echo -1000 > /proc/self/oom_score_adj' /tmp/media-block.sh || { echo "jailcheck: no media jail block in /entrypoint.sh" >&2; exit 1; }
# shellcheck disable=SC1091 # extracted from the image at run time.
. /tmp/media-block.sh
# As the entrypoint makes it: the escape tests check it is out of reach.
mkdir -p /run/wappie
chmod 0700 /run/wappie

# `trace`: the syscalls the workers make (trace-profile.sh), not the checks.
if [ "${1:-}" = trace ]; then exec node /opt/jailcheck/trace.mjs; fi
exec node /opt/jailcheck/jail-check.mjs
