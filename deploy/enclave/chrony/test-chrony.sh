#!/bin/sh
# Runs the reader image's own chronyd and configuration against nsm-timefeed's
# own cycle with a fake NSM (nsm-attest/examples/fake-feed.rs), and checks
# what only a live chronyd can show (docs/mcp-enclave.md, Clock):
# - the sign: a feed saying "the true time is 8 s ahead" makes chronyd report
#   the clock 8 s slow, not fast (a wrong sign would double the error);
# - the 40-byte sample: chronyd selects the NSM source at all;
# - boot.conf: the first update is let through and steps (one attempt only),
#   a later correction under 5 s slews, a later one over 5 s makes chronyd
#   exit, and nsm-timefeed then reports chronyd_gone;
# - run.conf: no step, and a first correction over 5 s exits at once;
# - nsm-timefeed's boot gate: a first sample 700 s off is never fed.
#
#   deploy/enclave/chrony/test-chrony.sh <image>
#
# <image> is a built reader image (make enclave-image). chronyd runs with -x,
# so it never touches the clock: it keeps its correction to itself, and a
# step it would make shows as "Could not step system clock". That also means
# this cannot show how far or how fast the real clock moves; the clock probe
# on a Nitro host does (deploy/enclave/clockprobe). Needs Docker and network
# access to build the fake feed (cargo fetches the locked crates). The five
# cases run side by side and take about six minutes: chronyd needs three
# polls of 32 s for its first update, and after the true time jumps it waits
# for the old samples to age out of its filter before it acts.
set -eu

image=${1:?usage: test-chrony.sh <image>}
here=$(cd "$(dirname "$0")" && pwd)
rust_image=${RUST_IMAGE:-$(sed -n 's/^ARG RUST_IMAGE=//p' "$here/../Dockerfile")}
work=$(mktemp -d)
names=""
cleanup() {
  for n in $names; do docker rm -f "$n" > /dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT

# The fake feed, built from the committed lock in the pinned Rust image.
docker run --rm -v "$here/../nsm-attest:/nsm:ro" -v "$work:/out" -w /nsm -e CARGO_TARGET_DIR=/tmp/target "$rust_image" \
  sh -c 'apk add --no-cache musl-dev > /dev/null && cargo build --quiet --locked --release --example fake-feed \
    && cp /tmp/target/release/examples/fake-feed /out/fake-feed'

# One case, inside the image: case_name conf offset_ms [new_offset_ms].
# It prints its findings and exits non-zero on the first that is wrong.
cat > "$work/case.sh" <<'EOF'
set -eu
name=$1 conf=$2 offset=$3 jump=${4:-}
fail() { echo "test-chrony $name: $*" >&2; dump; exit 1; }
dump() {
  echo "--- $name: chronyd log"; cat /tmp/chronyd.log 2> /dev/null || true
  echo "--- $name: tracking"; grep -v "^ \|^=" /tmp/log/tracking.log 2> /dev/null || true
  echo "--- $name: feed"; tail -5 /tmp/feed.log 2> /dev/null || true; cat /tmp/feed/state.json 2> /dev/null || true
}
# Seconds since the case started.
started=$(date +%s)
elapsed() { echo $(( $(date +%s) - started )); }
# wait_for SECONDS COMMAND...: polls COMMAND every second.
wait_for() {
  limit=$1; shift
  until "$@"; do
    [ "$(elapsed)" -lt "$limit" ] || return 1
    sleep 1
  done
}
alive() { kill -0 "$chronyd" 2> /dev/null; }
gone() { ! alive; }
logged() { grep -q "$1" /tmp/chronyd.log 2> /dev/null; }
# Matching lines in chronyd's log, 0 before the log exists.
count() { if [ -f /tmp/chronyd.log ]; then grep -c "$1" /tmp/chronyd.log || true; else echo 0; fi; }
corrections_at_least() { [ "$(count "System clock wrong by")" -ge "$1" ]; }
# Clock updates in the tracking log after the start line (whose source is 0.0.0.0).
updates() { if [ -f /tmp/log/tracking.log ]; then grep -c " NSM " /tmp/log/tracking.log || true; else echo 0; fi; }
has_updates() { [ "$(updates)" -ge "$1" ]; }
updated_or_gone() { has_updates 1 || gone; }
# The Nth update's offset (chronyd's sign: local minus true time).
offset_of() { grep " NSM " /tmp/log/tracking.log | sed -n "$1p" | awk "{print \$7}"; }
# Whether |value - want| <= tolerance.
near() { awk -v v="$1" -v w="$2" -v t="$3" "BEGIN { d = v - w; if (d < 0) d = -d; exit !(d <= t) }"; }
# The last "System clock wrong by X seconds" value: positive means the clock is slow.
wrong_by() { grep "System clock wrong by" /tmp/chronyd.log | tail -1 | sed "s/.*wrong by \([-0-9.]*\) seconds.*/\1/"; }
# The size of the correction maxchange refused, from its exit line.
refused() { sed -n "s/.*Adjustment of \([-0-9.]*\) seconds exceeds the allowed maximum of 5.000 seconds (exiting).*/\1/p" /tmp/chronyd.log | tail -1; }
state() { sed -n "s/.*\"state\":\"\([a-z_]*\)\".*/\1/p" /tmp/feed/state.json 2> /dev/null; }
state_is() { [ "$(state)" = "$1" ]; }

mkdir -p /run/chrony /tmp/feed /tmp/log
chmod 0700 /run/chrony
# The image's configuration, plus logs for this test only.
printf "include /etc/chrony/%s\nlogdir /tmp/log\nlog tracking\n" "$conf" > /tmp/test.conf
echo "$offset" > /tmp/offset_ms
chronyd -x -n -f /tmp/test.conf -l /tmp/chronyd.log > /dev/null 2>&1 &
chronyd=$!
/t/fake-feed /run/chrony/nsm.sock /tmp/feed /tmp/offset_ms > /tmp/feed.log 2>&1 &

case $name in
boot-gate)
  wait_for 30 state_is boot_refused || fail "nsm-timefeed did not refuse a first sample 700 s off (state $(state))"
  sleep 100
  alive || fail "chronyd exited"
  ! logged "Selected source" || fail "chronyd selected the NSM source: the refused feed reached it"
  echo "test-chrony $name: ok (boot_refused, nothing fed to chronyd in $(elapsed) s)"
  exit 0
  ;;
esac

# The first update: at most three polls of 32 s, plus some slack.
wait_for 150 updated_or_gone || true
case $name in
run-big)
  wait_for 150 gone || fail "chronyd did not exit"
  rc=0; wait "$chronyd" || rc=$?
  [ "$rc" = 1 ] || fail "chronyd exited $rc, want 1"
  near "$(refused)" 8 0.01 || fail "no maxchange exit for 8 s (refused \"$(refused)\")"
  ! logged "System clock wrong by" || fail "chronyd corrected the clock before it exited"
  [ "$(updates)" = 0 ] || fail "chronyd updated the clock"
  echo "test-chrony $name: ok (run.conf exits on a first correction of 8 s, after $(elapsed) s)"
  exit 0
  ;;
esac
has_updates 1 || fail "no clock update in $(elapsed) s"
alive || fail "chronyd exited at its first update"
want=$(awk -v o="$offset" "BEGIN { print o / 1000 }")
# The sign, twice: chronyd says the clock is slow by the feed's offset, and
# its tracking offset (local minus true) is the negation.
near "$(wrong_by)" "$want" 0.01 || fail "chronyd says the clock is wrong by $(wrong_by) s, want +$want s: the offset's sign or the sample layout is wrong"
near "$(offset_of 1)" "-$want" 0.01 || fail "first tracking offset $(offset_of 1), want -$want"
case $conf in
boot.conf) [ "$(count "Could not step system clock")" = 1 ] || fail "boot.conf: the first update did not try to step" ;;
run.conf) [ "$(count "Could not step system clock")" = 0 ] || fail "run.conf tried to step the clock" ;;
esac
state_is ok || fail "nsm-timefeed state $(state) with chronyd running, want ok"
if [ -z "$jump" ]; then
  # Then it tracks: the next update's offset is small.
  wait_for 230 has_updates 2 || fail "no second clock update"
  near "$(offset_of 2)" 0 0.01 || fail "second tracking offset $(offset_of 2), want about 0"
  alive || fail "chronyd exited"
  echo "test-chrony $name: ok (sign +$want s, $conf, tracking after $(elapsed) s)"
  exit 0
fi
# The true time jumps. nsm-timefeed takes the new level after 3 samples that
# agree; chronyd acts once the old samples have left its filter.
echo "$jump" > /tmp/offset_ms
step=$(awk -v a="$offset" -v b="$jump" "BEGIN { print (b - a) / 1000 }")
case $name in
boot-slew)
  wait_for 540 corrections_at_least 2 || fail "no correction for the $step s jump"
  # The size is chronyd's regression over samples from both sides of the
  # jump, so only roughly the jump: what matters is that it is over the 0.5 s
  # step threshold and under maxchange's 5 s.
  near "$(wrong_by)" "$step" 1 || fail "chronyd corrected $(wrong_by) s for a $step s jump"
  alive || fail "chronyd exited on a $step s correction (maxchange is 5 s)"
  [ "$(count "Could not step system clock")" = 1 ] || fail "boot.conf tried a second step (makestep 0.5 1 allows one)"
  echo "test-chrony $name: ok (a later $step s correction slews, no second step, after $(elapsed) s)"
  ;;
boot-big)
  wait_for 540 gone || fail "chronyd did not exit on a $step s correction"
  rc=0; wait "$chronyd" || rc=$?
  [ "$rc" = 1 ] || fail "chronyd exited $rc, want 1"
  near "$(refused)" "$step" 1 || fail "no maxchange exit for about $step s (refused \"$(refused)\")"
  [ "$(count "Could not step system clock")" = 1 ] || fail "boot.conf tried a second step"
  # nsm-timefeed notices: its sends fail, and after its 30 s grace it says so.
  limit=$(( $(elapsed) + 60 ))
  wait_for "$limit" state_is chronyd_gone || fail "nsm-timefeed state $(state) after chronyd exited, want chronyd_gone"
  echo "test-chrony $name: ok (a later $step s correction exits, then chronyd_gone, after $(elapsed) s)"
  ;;
esac
EOF

# name:conf:offset_ms[:new_offset_ms]
cases="boot-slew:boot.conf:8000:11000 boot-big:boot.conf:8000:19000 run-small:run.conf:3000 run-big:run.conf:8000 boot-gate:boot.conf:700000"
running=""
for c in $cases; do
  IFS=: read -r name conf offset jump <<EOF2
$c
EOF2
  container=wappie-chrony-test-$$-$name
  names="$names $container"
  # No network and no extra capability: chronyd -x needs neither.
  docker run --rm --name "$container" --network none -v "$work:/t:ro" --entrypoint /bin/sh "$image" \
    /t/case.sh "$name" "$conf" "$offset" "$jump" > "$work/$name.out" 2>&1 &
  running="$running $name:$!"
done
failed=0
for r in $running; do
  rc=0; wait "${r#*:}" || rc=$?
  cat "$work/${r%%:*}.out"
  [ "$rc" = 0 ] || failed=1
done
[ "$failed" = 0 ] || { echo "test-chrony: FAILED" >&2; exit 1; }
echo "test-chrony: ok"
