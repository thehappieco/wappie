#!/bin/sh
# The entrypoint of the CLOCK PROBE enclave (deploy/enclave/clockprobe),
# started by the Nitro init. NEVER in the release image. The image is the
# reader image of the same commit with the probe's files on top
# (Dockerfile.clockprobe), so chronyd, its configuration, nsm-timefeed and
# /usr/local/sbin/wappie-clock-start are the release bytes. It never starts
# the reader's Node (in debug mode KMS refuses the zero PCRs, so main.mjs
# could not boot): clockprobe-run.mjs runs the scenarios, injects each fault,
# then calls the same wappie-clock-start the release entrypoint calls.
#
# Before anything else it takes one NSM sample, so S8 can compare the
# enclave's clock at boot with NSM time before any chronyd touches it.
#
# Then what production does that the clock needs: loopback up, KMS's name on
# 127.0.0.2 and the socat bridge to vsock 8000 (both checked against
# /entrypoint.sh at build time by Dockerfile.clockprobe), and
# oom_score_adj -1000, which wappie-clock-start's loops inherit as they do in
# production.
#
# The console explains the run even if Node dies (the A0 lesson): everything
# goes to /dev/console, each step prints a marker, the runner is a child and
# its end is printed, /run/clockprobe/report.jsonl is printed again whole, and
# the END marker is followed by a pause so the console drains.
#
# Environment (a local smoke run only; unset in the enclave):
#   PROBE_CONSOLE=-            keep stdout instead of /dev/console
#   CLOCKPROBE_RUN, CLOCKPROBE_SCENARIOS  see clockprobe-run.mjs
set -u

console=${PROBE_CONSOLE:-/dev/console}
if [ "$console" != - ]; then
  if { : > "$console"; } 2> /dev/null; then
    exec > "$console" 2>&1
  else
    echo "CP console $console is not writable; staying on stdout"
  fi
fi

mkdir -p /run/clockprobe
# First: the enclave's clock against NSM time, before anything sets it.
/opt/clockprobe/bin/nsm-p0 sample > /run/clockprobe/boot-sample.json 2> /dev/null
cut -d' ' -f1 /proc/uptime > /run/clockprobe/boot-uptime 2> /dev/null

up() { cut -d' ' -f1 /proc/uptime 2> /dev/null; }
n=0
step() {
  n=$((n + 1))
  echo "CP STEP $n t=$(up) $*"
}

echo '===WAPPIE-CLOCKPROBE-BEGIN==='
step "entrypoint: pid $$, kernel $(uname -r), boot sample $(cat /run/clockprobe/boot-sample.json 2> /dev/null)"

step "loopback up, KMS on 127.0.0.2 through vsock 8000, oom_score_adj -1000"
ip addr add 127.0.0.1/8 dev lo 2> /dev/null || true
ip link set dev lo up || echo "CP loopback: ip link set dev lo up FAILED"
echo '127.0.0.2 kms.eu-west-1.amazonaws.com' >> /etc/hosts
(while :; do
  socat TCP-LISTEN:443,bind=127.0.0.2,reuseaddr,fork VSOCK-CONNECT:3:8000 > /dev/null 2>&1 < /dev/null || true
  sleep 1
done) &
echo -1000 > /proc/self/oom_score_adj || true

step "heartbeat every 60 s while the runner works"
(while :; do sleep 60; echo "CP ALIVE t=$(up)"; done) &
beat=$!

step "runner: node /clockprobe/clockprobe-run.mjs, as a child"
node /clockprobe/clockprobe-run.mjs &
pid=$!
echo "CP PID $pid runner"
wait "$pid"
rc=$?
if [ "$rc" -gt 128 ]; then echo "CP EXIT $pid runner: signal $((rc - 128))"; else echo "CP EXIT $pid runner: exit $rc"; fi
kill "$beat" 2> /dev/null

step "the report again, whole"
echo "CP FILE /run/clockprobe/report.jsonl BEGIN"
cat /run/clockprobe/report.jsonl 2> /dev/null
echo "CP FILE /run/clockprobe/report.jsonl END"

step "end"
echo '===WAPPIE-CLOCKPROBE-END==='
sleep 5
exit 0
