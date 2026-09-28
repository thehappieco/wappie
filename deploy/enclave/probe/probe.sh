#!/bin/bash
# Runs the A0 go/no-go probe ON THE PARENT (deploy/enclave/probe). It builds the
# throwaway probe image and EIF, STOPS the production reader (which terminates
# the production enclave), boots the probe enclave in --debug-mode so its console
# is readable, captures the one JSON report, terminates the probe, and ALWAYS
# restarts the production reader. Production files are never overwritten: the EIF
# and logs go under /opt/wappie-reader/probe/.
#
#   sudo deploy/enclave/probe/probe.sh
#
# Requirements (task A0): arm64 parent (c7g.large), docker + nitro-cli 1.5.0, the
# production supervisor unit wappie-reader-supervisor, and the allocator already
# reserving 1 vCPU / 1536 MiB (commercial/deploy/enclave/allocator.yaml). Run as
# root: it stops/starts a systemd unit and runs enclaves.
set -uo pipefail

NAME=wappie-reader-probe
PROD_UNIT=wappie-reader-supervisor
CID=30                 # not production's 16
VSOCK_PORT=9100        # not 5443-5445/7000-7002/8000-8002/9000
RUN_CPUS=1
RUN_MEM=1536           # production enclave sizing, to measure real headroom
# Seconds to wait for the report end marker. A clean run takes a minute or two;
# this bounds the worst case, where every jailed test hangs until the runner's
# watchdog (the job's wall + 10 s) and the vsock sender never arrives.
REPORT_TIMEOUT=480

# nitro-cli's profile script is not sourced by plain shells/SSM (spike Day 1).
export NITRO_CLI_ARTIFACTS=${NITRO_CLI_ARTIFACTS:-/var/lib/nitro_enclaves/artifacts}
export NITRO_CLI_BLOBS=${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs/}

root=$(cd "$(dirname "$0")/../../.." && pwd)
die() { echo "probe.sh: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (it stops/starts $PROD_UNIT and runs enclaves)"
[ "$(uname -m)" = aarch64 ] || die "run on the arm64 parent; this host is $(uname -m)"
command -v docker > /dev/null || die "docker is not installed"
command -v nitro-cli > /dev/null || die "nitro-cli is not installed"
command -v python3 > /dev/null || die "python3 is needed for the vsock sender"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
base=/opt/wappie-reader/probe
out=$base/$stamp
mkdir -p "$out" || die "cannot create $out"
console=$out/console.log
report=$out/report.json
: > "$console"

console_pid=""
sender_pid=""
production_stopped=0
production_restored=0

# Start production again, but only if this script stopped it, and only once.
# The flag is set after the attempt, so an interrupted attempt is retried.
restore_production() {
  [ "$production_stopped" = 1 ] || return 0
  [ "$production_restored" = 0 ] || return 0
  echo "probe.sh: restarting production ($PROD_UNIT)"
  systemctl start "$PROD_UNIT" 2> /dev/null || echo "probe.sh: WARNING could not start $PROD_UNIT; start it by hand" >&2
  production_restored=1
}

# Runs once, from the EXIT trap only. A signal handler in bash returns and the
# script carries on, so HUP/INT/TERM just exit (which runs this); and a second
# signal must not cut this short before production is back.
cleanup() {
  trap '' HUP INT TERM
  [ -z "$sender_pid" ] || kill "$sender_pid" 2> /dev/null || true
  [ -z "$console_pid" ] || kill "$console_pid" 2> /dev/null || true
  nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
  restore_production
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# --- build the throwaway image and EIF (never overwriting production) ---
tag=$NAME:$stamp
echo "probe.sh: building $tag"
docker build -f "$root/deploy/enclave/probe/Dockerfile.probe" -t "$tag" "$root" \
  || die "docker build failed"
eif=$out/probe.eif
echo "probe.sh: building EIF $eif"
nitro-cli build-enclave --docker-uri "$tag" --output-file "$eif" > "$out/build-enclave.json" \
  || die "nitro-cli build-enclave failed"
eif_size=$(stat -c %s "$eif")

# The installed blob's kernel config, the static answer to §16.14 (e.g.
# CONFIG_IO_URING) when the enclave kernel has no /proc/config.gz.
blob_config=$out/blob-kernel-config.txt
if [ -f "$NITRO_CLI_BLOBS/Image.config" ]; then
  cp "$NITRO_CLI_BLOBS/Image.config" "$out/Image.config"
  grep -E '^(# )?CONFIG_(IO_URING|USER_NS|SECCOMP_FILTER|CGROUPS|MEMCG|MEMCG_SWAP|SWAP|CGROUP_PIDS|CPUSETS|PID_NS|NET_NS|USERFAULTFD|SECURITY_YAMA|IKCONFIG_PROC)[ =]' \
    "$out/Image.config" > "$blob_config" || true
else
  echo "absent: $NITRO_CLI_BLOBS/Image.config" > "$blob_config"
fi

# --- free the enclave slot: stop production (this terminates its enclave) ---
echo "probe.sh: stopping production ($PROD_UNIT) — the production enclave goes down now"
# Set before the stop, so an interrupt during it still restarts production.
production_stopped=1
systemctl stop "$PROD_UNIT" 2> /dev/null || echo "probe.sh: $PROD_UNIT was not running"
# Also clear any leftover enclave under our probe name.
nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
sleep 2

# --- run the probe enclave in debug mode (console readable, PCRs all zero) ---
echo "probe.sh: launching probe enclave (cid $CID, $RUN_CPUS vcpu, $RUN_MEM MiB, debug)"
nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$eif" \
  --cpu-count "$RUN_CPUS" --memory "$RUN_MEM" --enclave-cid "$CID" --debug-mode \
  > "$out/run-enclave.json" || die "nitro-cli run-enclave failed"

# Capture the console to a file, and start the vsock sender (it retries until
# the enclave's sink is listening, late in the run).
nitro-cli console --enclave-name "$NAME" >> "$console" 2>&1 &
console_pid=$!
python3 "$root/deploy/enclave/probe/vsock-send.py" "$CID" "$VSOCK_PORT" > "$out/vsock-send.log" 2>&1 &
sender_pid=$!

# --- wait for the report end marker, or time out ---
echo "probe.sh: waiting up to ${REPORT_TIMEOUT}s for the report"
deadline=$(( $(date +%s) + REPORT_TIMEOUT ))
got=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q '===WAPPIE-A0-PROBE-END===' "$console" 2> /dev/null; then got=1; break; fi
  if ! nitro-cli describe-enclaves 2> /dev/null | grep -q "\"$NAME\""; then
    echo "probe.sh: probe enclave exited before the report" >&2
    break
  fi
  sleep 2
done

# Extract the report JSON between the markers.
awk '/===WAPPIE-A0-PROBE-BEGIN===/{f=1;next} /===WAPPIE-A0-PROBE-END===/{f=0} f' "$console" > "$report"

echo "-----------------------------------------------------------------"
echo "probe EIF size : $eif_size bytes ($out/probe.eif)"
echo "console log    : $console"
echo "blob config    : $blob_config"
if [ "$got" = 1 ] && [ -s "$report" ]; then
  echo "report         : $report"
else
  echo "report         : INCOMPLETE (no end marker); see $console"
fi
echo "-----------------------------------------------------------------"
# cleanup (trap) terminates the probe enclave and restarts production.
[ "$got" = 1 ]
