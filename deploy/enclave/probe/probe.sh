#!/bin/bash
# Runs the A1 probe ON THE PARENT (deploy/enclave/probe): the jail check on the
# enclave's own kernel before the release (docs/mcp-enclave.md §16.13). It
# builds the throwaway probe image (build-image.sh: this commit's reader image,
# the jail check on top, the probe) and its EIF, checks the EIF fits the
# enclave, STOPS the production reader (which terminates the production
# enclave), boots the probe enclave in --debug-mode so its console is
# readable, serves the documents the enclave asks for over vsock
# (vsock-serve.py), assembles the report from the sections the enclave streams
# to its console (assemble-report.py), terminates the probe, and ALWAYS
# restarts the production reader. Production files are never overwritten: the
# EIF and logs go under /opt/wappie-reader/probe/.
#
#   sudo deploy/enclave/probe/probe.sh
#
# Requirements: arm64 parent (c7g.large), docker + nitro-cli 1.5.0, python3,
# the production supervisor unit wappie-reader-supervisor, and the allocator
# already reserving 1 vCPU / 1536 MiB (commercial/deploy/enclave/allocator.yaml).
# Run as root: it stops/starts a systemd unit and runs enclaves. Production is
# down for a few minutes; REPORT_TIMEOUT bounds it.
set -uo pipefail

NAME=wappie-reader-probe
PROD_UNIT=wappie-reader-supervisor
CID=30                 # not production's 16
VSOCK_PORT=9100        # throughput; not 5443-5445/7000-7002/8000-8002/9000
OBJECTS_PORT=9101      # the documents the reader stand-in opens; not production's either
RUN_CPUS=1
RUN_MEM=1536           # production enclave sizing, to measure real headroom
# Seconds to wait for the report end marker, from the launch. A clean run takes
# a few minutes on one vCPU; this bounds the worst case, where each of the
# runner's children (the jail check, the end-to-end test, the reader
# stand-in) runs into its own timeout (10, 5 and 15 minutes) and the vsock
# sender never arrives.
REPORT_TIMEOUT=2100
# Seconds any one nitro-cli describe/terminate may take while production is
# down, so a hung nitro-cli can neither stretch the wait nor hold the restart.
NITRO_TIMEOUT=60

# nitro-cli's profile script is not sourced by plain shells/SSM (spike Day 1).
export NITRO_CLI_ARTIFACTS=${NITRO_CLI_ARTIFACTS:-/var/lib/nitro_enclaves/artifacts}
export NITRO_CLI_BLOBS=${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs/}

root=$(cd "$(dirname "$0")/../../.." && pwd)
die() { echo "probe.sh: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (it stops/starts $PROD_UNIT and runs enclaves)"
[ "$(uname -m)" = aarch64 ] || die "run on the arm64 parent; this host is $(uname -m)"
command -v docker > /dev/null || die "docker is not installed"
command -v nitro-cli > /dev/null || die "nitro-cli is not installed"
command -v python3 > /dev/null || die "python3 is needed for the vsock sender and the report"
command -v timeout > /dev/null || die "timeout (coreutils) is needed to bound nitro-cli"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
base=/opt/wappie-reader/probe
out=$base/$stamp
mkdir -p "$out" || die "cannot create $out"
console=$out/console.log
liveness=$out/liveness.log
: > "$console"

console_pid=""
sender_pid=""
serve_pid=""
production_stopped=0
production_restored=0

# Start production again, but only if this script stopped it, and only once.
# The flag is set after the attempt, so an interrupted attempt is retried. The
# start comes before any output, so a write that fails cannot stand in its way.
restore_production() {
  [ "$production_stopped" = 1 ] || return 0
  [ "$production_restored" = 0 ] || return 0
  if systemctl start "$PROD_UNIT" 2> /dev/null; then
    echo "probe.sh: restarted production ($PROD_UNIT)"
  else
    echo "probe.sh: WARNING could not start $PROD_UNIT; start it by hand" >&2
  fi
  production_restored=1
}

# Runs once, from the EXIT trap only. A signal handler in bash returns and the
# script carries on, so HUP/INT/TERM just exit (which runs this); and a second
# signal must not cut this short before production is back.
cleanup() {
  trap '' HUP INT TERM PIPE
  [ -z "$sender_pid" ] || kill "$sender_pid" 2> /dev/null || true
  [ -z "$serve_pid" ] || kill "$serve_pid" 2> /dev/null || true
  [ -z "$console_pid" ] || kill "$console_pid" 2> /dev/null || true
  timeout "$NITRO_TIMEOUT" nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
  restore_production
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# A closed stdout must never skip cleanup. Bash dies of SIGPIPE without running
# its EXIT trap, e.g. under `probe.sh 2>&1 | tee run.log` when the SSH session
# drops and takes tee with it. Ignored, a failed write returns EPIPE and the
# script carries on to cleanup. (Not `exit 141`: an exit inside the EXIT trap
# would cut cleanup short.)
trap '' PIPE

# --- build the throwaway image and EIF (never overwriting production) ---
tag=$NAME:$stamp
echo "probe.sh: building $tag"
sh "$root/deploy/enclave/probe/build-image.sh" "$tag" || die "the probe image did not build"
eif=$out/probe.eif
echo "probe.sh: building EIF $eif"
nitro-cli build-enclave --docker-uri "$tag" --output-file "$eif" > "$out/build-enclave.json" \
  || die "nitro-cli build-enclave failed"
eif_size=$(stat -c %s "$eif")
# nitro-cli refuses an enclave with less than four times its EIF's size in
# memory (E26); the probe carries the jail check's test tree on top of the
# reader, so this is checked here, while production is still up.
eif_mib=$(( (eif_size + 1048575) / 1048576 ))
[ $(( eif_mib * 4 )) -le "$RUN_MEM" ] \
  || die "the EIF is $eif_mib MiB; nitro-cli wants $(( eif_mib * 4 )) MiB for it, more than the $RUN_MEM MiB the enclave has"

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

# The parent end of the documents the reader stand-in opens, up before the
# enclave boots. It exits by itself after the longest run.
python3 "$root/deploy/enclave/probe/vsock-serve.py" "$OBJECTS_PORT" $(( REPORT_TIMEOUT + 300 )) > "$out/vsock-serve.log" 2>&1 &
serve_pid=$!

# --- free the enclave slot: stop production (this terminates its enclave) ---
echo "probe.sh: stopping production ($PROD_UNIT) — the production enclave goes down now"
# Set before the stop, so an interrupt during it still restarts production.
production_stopped=1
systemctl stop "$PROD_UNIT" 2> /dev/null || echo "probe.sh: $PROD_UNIT was not running"
# Also clear any leftover enclave under our probe name.
timeout "$NITRO_TIMEOUT" nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
sleep 2

# --- run the probe enclave in debug mode (console readable, PCRs all zero) ---
echo "probe.sh: launching probe enclave (cid $CID, $RUN_CPUS vcpu, $RUN_MEM MiB, debug)"
nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$eif" \
  --cpu-count "$RUN_CPUS" --memory "$RUN_MEM" --enclave-cid "$CID" --debug-mode \
  > "$out/run-enclave.json" || die "nitro-cli run-enclave failed"

launched=$(date +%s)
timeout "$NITRO_TIMEOUT" nitro-cli describe-enclaves > "$out/describe-first.json" 2> "$out/describe-first.err"

# Capture the console to a file, and start the vsock sender (it retries until
# the enclave's sink is listening, late in the run).
nitro-cli console --enclave-name "$NAME" >> "$console" 2>&1 &
console_pid=$!
python3 "$root/deploy/enclave/probe/vsock-send.py" "$CID" "$VSOCK_PORT" > "$out/vsock-send.log" 2>&1 &
sender_pid=$!

# Whether the probe enclave is up, judged from describe-enclaves' OUTPUT. The
# first run checked `describe-enclaves 2>/dev/null | grep -q` under pipefail,
# which also reads "gone" whenever nitro-cli exits non-zero (a failed
# connection to another enclave process is enough) or dies of EPIPE after
# grep -q matched and quit, with the reason discarded; its cleanup then
# terminated the probe it had just called gone. Now: "up" when the output
# lists the enclave, "gone" only when nitro-cli succeeded and did not list it,
# "unknown" otherwise (a timed-out poll is rc=124), and every poll is logged
# with its stderr.
enclave_state() {
  local desc rc
  desc=$(timeout "$NITRO_TIMEOUT" nitro-cli describe-enclaves 2> "$out/describe.err")
  rc=$?
  if [[ $desc == *"\"$NAME\""* ]]; then
    echo up
  elif [ "$rc" = 0 ]; then
    echo gone
  else
    echo "unknown(rc=$rc: $(tr '\n' ' ' < "$out/describe.err" | cut -c1-200))"
  fi
}

# --- wait for the end marker, the enclave's end, or the timeout ---
echo "probe.sh: waiting up to ${REPORT_TIMEOUT}s for the report"
deadline=$(( launched + REPORT_TIMEOUT ))
got=0
gone=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q '===WAPPIE-A1-PROBE-END===' "$console" 2> /dev/null; then got=1; break; fi
  state=$(enclave_state)
  echo "+$(( $(date +%s) - launched ))s $state" >> "$liveness"
  if [ "$state" = gone ]; then gone=$((gone + 1)); else gone=0; fi
  # Twice in a row, so one odd answer cannot end the run.
  if [ "$gone" -ge 2 ]; then
    grep -q '===WAPPIE-A1-PROBE-END===' "$console" 2> /dev/null && got=1
    [ "$got" = 1 ] || echo "probe.sh: probe enclave ended before the END marker (+$(( $(date +%s) - launched ))s; see $liveness)" >&2
    break
  fi
  sleep 2
done
[ "$got" = 1 ] || [ "$gone" -ge 2 ] || echo "probe.sh: no END marker within ${REPORT_TIMEOUT}s" >&2

# Assemble the report from the streamed sections: complete with the END
# marker, partial otherwise, and every finished section is kept either way.
python3 "$root/deploy/enclave/probe/assemble-report.py" "$console" "$out" > "$out/assemble.txt" 2>&1
assembled=$?

echo "-----------------------------------------------------------------"
echo "probe EIF size : $eif_size bytes ($out/probe.eif)"
echo "console log    : $console"
echo "liveness log   : $liveness"
echo "documents      : $out/vsock-serve.log"
echo "blob config    : $blob_config"
echo "report         : $out/report.json ($(cat "$out/assemble.txt"))"
echo "-----------------------------------------------------------------"
# cleanup (trap) terminates the probe enclave and restarts production.
[ "$got" = 1 ] && [ "$assembled" = 0 ]
