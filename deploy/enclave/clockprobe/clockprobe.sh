#!/bin/bash
# Runs the reader clock probe ON A PARENT (deploy/enclave/clockprobe; README.md).
# It builds the throwaway probe image (build-image.sh: this commit's reader
# image with the probe on top) and its EIF, then for each run named on the
# command line boots the probe enclave in --debug-mode, serves it the parent
# control server (control.py on vsock 9103), captures its console, assembles
# the report (assemble.py), and terminates it. Nothing of production is
# overwritten: the EIF, logs and reports go under /opt/wappie-reader/clockprobe/.
#
#   sudo deploy/enclave/clockprobe/clockprobe.sh [main] [s8] [s9boot]
#
# Runs (all three by default, in this order):
#   main    P0, S1-S7 and the in-run part of S9          about 2.5 h
#   s8      the parent's clock +120 s at launch and while running (S8)
#   s9boot  KMS (vsock 8000) blocked from the enclave's boot (S9)
#
# The plan runs the probe on a separate c7g.large (decision D2). On the
# production parent (where wappie-reader-supervisor exists) it refuses unless
# CLOCKPROBE_ALLOW_PRODUCTION_PARENT=1, which needs the owner's explicit yes
# (a 3-hour production outage), and even then it refuses s8 and s9boot,
# which move the parent's clock and stop its KMS proxy.
#
# Environment:
#   CLOCKPROBE_EIF=<path>         reuse an EIF built by an earlier run
#   CLOCKPROBE_SCENARIOS=S1,S5    run only these scenarios of `main`
#   CLOCKPROBE_S5_S=1800          seconds S5 watches after its +3 s
#   CLOCKPROBE_S6_S=3600          seconds S6 runs with the fake drift
#   CLOCKPROBE_KMS_UNIT=<unit>    the unit that runs the KMS vsock-proxy on
#                                 vsock 8000 (found by itself otherwise)
#   CLOCKPROBE_CHRONY_UNIT=chronyd  the parent's own chronyd unit
#   CLOCKPROBE_ALLOW_PRODUCTION_PARENT=1  see above
#
# Requirements: arm64 parent (c7g.large), docker, nitro-cli 1.5.0, python3,
# the allocator reserving at least 1 vCPU / 1536 MiB, and a vsock-proxy for
# kms.eu-west-1.amazonaws.com on vsock 8000 (README.md). Run as root.
set -uo pipefail

NAME=wappie-clockprobe
PROD_UNIT=wappie-reader-supervisor
CID=30                 # not production's 16
CONTROL_PORT=9103      # not 5443-5445/7000-7002/8000-8007/9000, nor the A1 probe's 9100/9101
RUN_CPUS=1
RUN_MEM=1536           # production enclave sizing
NITRO_TIMEOUT=60

export NITRO_CLI_ARTIFACTS=${NITRO_CLI_ARTIFACTS:-/var/lib/nitro_enclaves/artifacts}
export NITRO_CLI_BLOBS=${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs/}

here=$(cd "$(dirname "$0")" && pwd)
die() { echo "clockprobe.sh: $*" >&2; exit 1; }
# Seconds since boot: the deadlines must not move when s8 steps the clock.
now() { cut -d. -f1 /proc/uptime; }

runs=("$@")
[ "${#runs[@]}" -gt 0 ] || runs=(main s8 s9boot)
for r in "${runs[@]}"; do
  case "$r" in main | s8 | s9boot) ;; *) die "unknown run '$r' (main, s8, s9boot)" ;; esac
done

[ "$(id -u)" = 0 ] || die "run as root (it runs enclaves, stops units and moves the parent's clock)"
[ "$(uname -m)" = aarch64 ] || die "run on the arm64 parent; this host is $(uname -m)"
for c in docker nitro-cli python3 timeout systemctl; do
  command -v "$c" > /dev/null || die "$c is not installed"
done

production=0
if systemctl cat "$PROD_UNIT" > /dev/null 2>&1; then
  production=1
  [ "${CLOCKPROBE_ALLOW_PRODUCTION_PARENT:-0}" = 1 ] \
    || die "this is the production parent ($PROD_UNIT exists). The plan runs the probe on a separate instance (D2); set CLOCKPROBE_ALLOW_PRODUCTION_PARENT=1 only with the owner's explicit yes"
  for r in "${runs[@]}"; do
    [ "$r" = main ] || die "run '$r' moves the parent's clock or its KMS proxy: never on the production parent"
  done
fi

# The KMS vsock-proxy on vsock 8000: production's wappie-vsock-kms, or the
# stock nitro-enclaves-vsock-proxy on a fresh parent.
kms_unit=${CLOCKPROBE_KMS_UNIT:-}
if [ -z "$kms_unit" ]; then
  for u in wappie-vsock-kms nitro-enclaves-vsock-proxy; do
    if systemctl is-active --quiet "$u"; then kms_unit=$u; break; fi
  done
fi
[ -n "$kms_unit" ] || echo "clockprobe.sh: WARNING no active KMS vsock-proxy unit; the KMS checks (ready, S4's proof, S9) will fail" >&2
kms_was_active=0
[ -n "$kms_unit" ] && systemctl is-active --quiet "$kms_unit" && kms_was_active=1
chrony_unit=${CLOCKPROBE_CHRONY_UNIT:-chronyd}
chrony_was_active=0
systemctl is-active --quiet "$chrony_unit" && chrony_was_active=1

stamp=$(date -u +%Y%m%dT%H%M%SZ)
base=/opt/wappie-reader/clockprobe
out=$base/$stamp
mkdir -p "$out" || die "cannot create $out"
echo "clockprobe.sh: results under $out"

console_pid=""
control_pid=""
production_stopped=0
production_restored=0

# shellcheck disable=SC2329 # called from cleanup, the EXIT trap
restore_production() {
  [ "$production_stopped" = 1 ] || return 0
  [ "$production_restored" = 0 ] || return 0
  if systemctl start "$PROD_UNIT" 2> /dev/null; then
    echo "clockprobe.sh: restarted production ($PROD_UNIT)"
  else
    echo "clockprobe.sh: WARNING could not start $PROD_UNIT; start it by hand" >&2
  fi
  production_restored=1
}

stop_control() {
  if [ -n "$control_pid" ]; then
    # control.py puts back what it changed (KMS unit, the parent's clock) as it exits.
    kill -TERM "$control_pid" 2> /dev/null || true
    for _ in $(seq 1 30); do kill -0 "$control_pid" 2> /dev/null || break; sleep 1; done
    kill -KILL "$control_pid" 2> /dev/null || true
    control_pid=""
  fi
}

# Runs once, from the EXIT trap: the probe enclave down, control.py stopped,
# then the KMS unit, the parent's chronyd and production as they were, even
# if control.py was killed before it could.
# shellcheck disable=SC2329 # the EXIT trap
cleanup() {
  trap '' HUP INT TERM PIPE
  [ -z "$console_pid" ] || kill "$console_pid" 2> /dev/null || true
  timeout "$NITRO_TIMEOUT" nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
  stop_control
  if [ "$kms_was_active" = 1 ] && ! systemctl is-active --quiet "$kms_unit"; then
    systemctl start "$kms_unit" 2> /dev/null || echo "clockprobe.sh: WARNING could not start $kms_unit" >&2
  fi
  if [ "$chrony_was_active" = 1 ] && ! systemctl is-active --quiet "$chrony_unit"; then
    systemctl start "$chrony_unit" 2> /dev/null && sleep 5 && chronyc -a makestep > /dev/null 2>&1
  fi
  restore_production
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# See probe.sh: a closed stdout must not end the script before cleanup.
trap '' PIPE

# --- the image and EIF (never overwriting production) ---
if [ -n "${CLOCKPROBE_EIF:-}" ]; then
  eif=$CLOCKPROBE_EIF
  [ -f "$eif" ] || die "CLOCKPROBE_EIF=$eif does not exist"
  echo "clockprobe.sh: reusing $eif"
else
  tag=$NAME:$stamp
  echo "clockprobe.sh: building $tag"
  sh "$here/build-image.sh" "$tag" || die "the probe image did not build"
  eif=$out/clockprobe.eif
  nitro-cli build-enclave --docker-uri "$tag" --output-file "$eif" > "$out/build-enclave.json" \
    || die "nitro-cli build-enclave failed"
fi
eif_mib=$(( ($(stat -c %s "$eif") + 1048575) / 1048576 ))
[ $(( eif_mib * 4 )) -le "$RUN_MEM" ] \
  || die "the EIF is $eif_mib MiB; nitro-cli wants $(( eif_mib * 4 )) MiB, more than the $RUN_MEM MiB the enclave gets"

enclave_state() {
  local desc rc
  desc=$(timeout "$NITRO_TIMEOUT" nitro-cli describe-enclaves 2> "$1/describe.err")
  rc=$?
  if [[ $desc == *"\"$NAME\""* ]]; then
    echo up
  elif [ "$rc" = 0 ]; then
    echo gone
  else
    echo "unknown(rc=$rc)"
  fi
}

# One probe enclave: control.py for this run, launch, wait for the END
# marker (or the enclave's end, or the timeout), terminate, assemble.
one_run() {
  local run=$1 timeout_s=$2 dir=$out/$1
  shift 2
  mkdir -p "$dir"
  local console=$dir/console.log
  : > "$console"

  # On the production parent the probe never blocks KMS or moves the clock:
  # the S9 parts of `main` then report "not run".
  local extra=()
  if [ "$production" = 0 ]; then
    extra+=(--allow-parent-clock)
    [ -z "$kms_unit" ] || extra+=(--kms-unit "$kms_unit" --allow-kms-block)
  fi
  rm -f "$dir/control.ready"
  python3 "$here/control.py" --run "$run" --log "$dir/control.log" --port "$CONTROL_PORT" --cid "$CID" \
    --chrony-unit "$chrony_unit" --s5-s "${CLOCKPROBE_S5_S:-1800}" --s6-s "${CLOCKPROBE_S6_S:-3600}" \
    --scenarios "${CLOCKPROBE_SCENARIOS:-}" --lifetime $(( timeout_s + 600 )) --ready-file "$dir/control.ready" \
    "${extra[@]}" "$@" > "$dir/control.out" 2>&1 &
  control_pid=$!
  for _ in $(seq 1 30); do [ -f "$dir/control.ready" ] && break; kill -0 "$control_pid" 2> /dev/null || break; sleep 1; done
  [ -f "$dir/control.ready" ] || { cat "$dir/control.out" "$dir/control.log" >&2 2> /dev/null; die "control.py did not start for $run"; }

  if [ "$production" = 1 ] && [ "$production_stopped" = 0 ]; then
    echo "clockprobe.sh: stopping production ($PROD_UNIT) — the production enclave goes down now"
    production_stopped=1
    systemctl stop "$PROD_UNIT" 2> /dev/null || echo "clockprobe.sh: $PROD_UNIT was not running"
  fi
  timeout "$NITRO_TIMEOUT" nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
  sleep 2

  echo "clockprobe.sh: $run: launching the probe enclave (cid $CID, $RUN_CPUS vcpu, $RUN_MEM MiB, debug), up to ${timeout_s}s"
  nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$eif" \
    --cpu-count "$RUN_CPUS" --memory "$RUN_MEM" --enclave-cid "$CID" --debug-mode \
    > "$dir/run-enclave.json" || { stop_control; echo "clockprobe.sh: $run: nitro-cli run-enclave failed" >&2; return 1; }
  local launched
  launched=$(now)
  nitro-cli console --enclave-name "$NAME" >> "$console" 2>&1 &
  console_pid=$!

  local got=0 gone=0 state
  while [ "$(now)" -lt $(( launched + timeout_s )) ]; do
    if grep -q '===WAPPIE-CLOCKPROBE-END===' "$console" 2> /dev/null; then got=1; break; fi
    state=$(enclave_state "$dir")
    echo "+$(( $(now) - launched ))s $state" >> "$dir/liveness.log"
    if [ "$state" = gone ]; then gone=$((gone + 1)); else gone=0; fi
    if [ "$gone" -ge 2 ]; then
      grep -q '===WAPPIE-CLOCKPROBE-END===' "$console" 2> /dev/null && got=1
      break
    fi
    sleep 10
  done
  [ "$got" = 1 ] || echo "clockprobe.sh: $run: no END marker (+$(( $(now) - launched ))s; see $dir/liveness.log)" >&2
  sleep 6
  kill "$console_pid" 2> /dev/null || true
  console_pid=""
  timeout "$NITRO_TIMEOUT" nitro-cli terminate-enclave --enclave-name "$NAME" > /dev/null 2>&1 || true
  stop_control
  python3 "$here/assemble.py" "$console" "$dir" | tee "$dir/assemble.txt"
}

for r in "${runs[@]}"; do
  case "$r" in
    main) one_run main $(( 3600 + ${CLOCKPROBE_S5_S:-1800} + ${CLOCKPROBE_S6_S:-3600} + 1800 )) ;;
    s8) one_run s8 2400 --shift-at-start 120 ;;
    s9boot) one_run s9boot 1200 --block-at-start refuse ;;
  esac
done

echo "-----------------------------------------------------------------"
python3 "$here/assemble.py" --summary "$out"
summary=$?
echo "results        : $out/results.json"
echo "per run        : $out/<run>/report.json, console.log, control.log"
echo "-----------------------------------------------------------------"
exit "$summary"
