# Clock probe enclave

A throwaway enclave that tests the reader 0.6.1 clock on the enclave's own
kernel, which nothing off-Nitro can do. The clock is `chronyd` steered by
`nsm-timefeed`, checked by `clock.mjs` against KMS Date ranges, behind the
503 `clock_unknown` gate.

The probe is **never released**:

- `clockprobe.sh` builds its own image with a distinct tag and its own EIF
  under `/opt/wappie-reader/clockprobe/`.
- It runs that EIF in `--debug-mode`. Debug mode zeroes the PCRs, so the probe
  can never use the reader's KMS keys.
- It assembles the report from the enclave console, then throws the enclave
  away.

This directory follows `deploy/enclave/probe/` (the A1 probe). It implements
section 5 of the reader 0.6.1 plan: P0, and scenarios S1–S9.

## What the probe image is

`build-image.sh` builds two images:

1. **The reader image**, exactly as `make enclave-image` builds it
   (`deploy/enclave/Dockerfile`). The probe therefore tests the release bytes
   of:
   - `chronyd`;
   - `/etc/chrony/{common,boot,run}.conf`;
   - `/usr/local/bin/nsm-timefeed`;
   - `/usr/local/sbin/wappie-clock-start`;
   - the reader's `clock.mjs` and `health.mjs`.
2. **The probe layer** (`Dockerfile.clockprobe`), which adds:
   - `/opt/clockprobe/bin/nsm-p0`: the measuring tool (`nsm-p0.rs`). It is
     built as an example of the nsm-attest crate, from the crate's own
     `Cargo.lock`, so it decodes documents with nsm-timefeed's own code.
   - `/opt/clockprobe/fake/nsm-timefeed`: nsm-timefeed built with the
     probe-only `fake-drift` feature. S6 is the only scenario that uses it.
   - `/clockprobe/`: the entrypoint, the runner (`clockprobe-run.mjs` and
     `evaluate.mjs`) and the KMS sampler (`kms-sampler.mjs`).

The build fails if any of these is untrue:

- the release `nsm-timefeed` contains `WAPPIE_FAKE_DRIFT`;
- `/entrypoint.sh` no longer calls `wappie-clock-start`;
- `/entrypoint.sh` no longer maps KMS to 127.0.0.2 or bridges it to vsock 8000.

**This directory is not a release input.**

- `deploy/enclave/Dockerfile` copies nothing from it.
- `scripts/check-reader-inputs.sh` does not list it.
- `deploy/enclave/test_build.py` checks both.

Changing anything here does not move PCR0.

## How a run works

A run is one boot of the probe enclave. In the enclave:

1. `entrypoint-clockprobe.sh` takes one NSM sample before anything sets the
   clock. S8 uses this boot sample.
2. It sets up what the clock needs, the way production does:
   - loopback;
   - `kms.eu-west-1.amazonaws.com` on 127.0.0.2, bridged to vsock 8000;
   - `oom_score_adj -1000`.
3. It starts the runner as a child.
4. The runner asks the parent's control server which run this is
   (`hello`, vsock 9103), then runs that run's scenarios.

Every scenario starts from a fresh clock. The runner:

- kills the last scenario's `chronyd`, `nsm-timefeed`, samplers and watcher
  (each started in its own process group);
- removes `/run/chrony` and `/run/wappie-clock`;
- puts the kernel's frequency and tick back to their boot values;
- sets `CLOCK_REALTIME` to NSM time (`nsm-p0 align`);
- starts `nsm-p0 watch`, which records REALTIME, MONOTONIC_RAW and
  MONOTONIC every second, and an NSM sample every 30 s.

It then:

1. injects its fault;
2. calls `/usr/local/sbin/wappie-clock-start`, as the release entrypoint does;
3. starts `kms-sampler.mjs`, which runs the reader's own `clock.mjs`;
4. reads `/run/wappie-clock/state.json`, chronyd's command line and the
   helper's pid every 2 s.

**Why a KMS sampler.** In debug mode KMS refuses every call, so `main.mjs`
never boots. Every KMS answer still carries a Date header. The sampler does
what the reader does with those answers, using the reader's own code:

- `health.mjs` `clockSkew` makes the request, through the same name and
  bridge;
- `clock.mjs` turns the answers into ranges and proofs, and gives `ready()`
  and `ok()`.

In `ready` mode it calls `clock.ready()` exactly as `main.mjs` step 2b does.
On a timeout it exits 78 with `clock_unknown`.

**The parent's control server** (`control.py`) runs as root on the parent and
answers only the probe's CID (30). It accepts a fixed list of requests:

| Request | What it does |
|---|---|
| `kms block refuse` | Stops the KMS vsock-proxy unit. |
| `kms block hold` | Stops the unit, then holds vsock 8000 open without answering. |
| `kms unblock` | Undoes either block. |
| `parent shift <s>` | Stops the parent's chronyd and steps the parent's clock. |
| `parent restore` | Puts the parent's clock back. |
| `time` | Returns the parent's clocks: real, true (real minus the measured shift), and the shift. |

Everything it changed is put back when it exits. `clockprobe.sh`'s EXIT trap
does the same again, in case control.py was killed first.

## Runs and scenarios

| Run | Scenarios | Time |
|---|---|---|
| `main` | P0, S1, S2, S3, S4 (+ S9 part), S9 (in-run), S7, S5, S6 | about 2.5 h (S5 30 min, S6 60 min) |
| `s8` | S8 (the parent's clock is +120 s from before the launch) | about 15 min |
| `s9boot` | S9-boot (KMS refused from before the launch) | about 6 min |

Each scenario gives a machine-readable verdict.

- Each check is `{name, pass, value, want}`.
- `pass` is `true`, `false` or `null` (not run).
- A scenario's `pass` is `false` if any of its checks failed, and `null` if
  none of them ran.

| # | Injection | Checks (all must pass) |
|---|---|---|
| **P0** | none | `cap_sys_time_pid1`, `cap_sys_time_entrypoint`, `cap_sys_time_chronyd` (CAP_SYS_TIME, bit 25 of CapEff); `clock_settime_works`, `adjtimex_write_works` (a zero step and the frequency it already has); `nsm_good_alone`, `nsm_good_under_load` (≥ 99% of 1000 requests decode, alone and while `nsm-attest` runs 10 times a second); `rtt_p99_alone_ms`, `rtt_p99_load_ms` (under half of `RTT_HARD_CAP`, 250 ms); `nsm_attest_under_load_ok`; `concurrent_opens` (two `/dev/nsm` descriptors at once, and two threads at once); `from_binary_decodes`; `timestamp_resolution_1ms`; `cpu_percent` (nsm-timefeed plus chronyd ≤ 5% of the one vCPU, over 120 s). P0 also records the clocksource, adjtimex, `clock_getres`, the boot sample, and an `obs.constants` block for each "settled by P0" constant. `obs.fallback_needed` is true when CAP_SYS_TIME, `clock_settime` or `adjtimex` fails: that is the plan's trigger for the Rust `--discipline` fallback. |
| **S1** | +90 s before chronyd starts | `one_step` (exactly one step after the injection); `step_size` (−90 000 ms ± 2000); `helper_ok_synced`; `synced_within_s` (≤ 180; the plan expects about 90, and the value is recorded); `nsm_skew_ms_steady` (\|skew\| < 50 ms over the 60 s after ready); `ready_passes` (`clock.ready()` with KMS agreement); `helper_steps_field` (= 1); `no_cap_or_refusal`; `chronyd_boot_conf_alive` |
| **S2** | −90 s before chronyd starts | as S1, stepping forward |
| **S3** | +700 s before chronyd starts | `boot_refused`; `refused_within_60_s`; `no_step`; `clock_stays_ahead_ms` (system − NSM stays 700 000 ± 2000); `clock_mjs_not_ok` (the code is `boot_refused` and never ok); `nothing_fed` |
| **S4** | +90 s after sync | `synced_before`; `ready_before`; `cap_exceeded_within_60_s`; `cap_sticky`; `no_step_back` (the clock stays 90 s ahead); `clock_mjs_not_ok`; `kms_proof_fast` (the sampler proves about +90 s). Whether chronyd exited on `maxchange` is recorded, not required (see Deviations). |
| **S5** | +3 s after sync, watched for `CLOCKPROBE_S5_S` (1800 s) | `no_step`; `chronyd_no_exit`; `no_cap_breach`; `hour_bucket_records_3s` (`corr_hour_ms` between 2800 and 5000); `slew_rate_ppm` (≤ 110 + 5 over any 10 minutes); `slewing_back` (`nsm_skew_ms` falls by at least half of 50 ppm of the run) |
| **S6** | fake-drift nsm-timefeed (NSM time +200 ppm), for `CLOCKPROBE_S6_S` (3600 s) | `fake_feed_running`; `synced_first`; `rate_ppm` (≤ 110 + 5 over any 10 minutes); `kernel_freq_bounded` (\|adjtimex freq\| ≤ 111 ppm); `offset_grows` (≥ 50 ppm after the first 15 minutes); `no_cap_breach`; `gate_closes_past_5s` (the sampler's code becomes `unc_high` once \|skew\| > 5 s: **null** if the run is too short to get there, with the estimated time in `value`) |
| **S7** | kill nsm-timefeed; kill chronyd and write its pidfile with a live pid | `helper_restarts` (≤ 15 s); `ledger_survives` (the same baseline); `boot_file_kept`; `helper_ok_again`; `stale_pidfile_written`; `chronyd_restarts_run_conf` (≤ 45 s); `recovers` (ok, synced, \|skew\| < 50 ms); `no_second_step` |
| **S8** (run `s8`) | the parent's clock +120 s with its chronyd stopped, before the launch, then restore, +120 s and restore again while the enclave runs | `parent_shifted_at_launch`; `boot_time_unaffected` (\|system − NSM\| at the entrypoint < 60 s); `nsm_follows_true_time` (\|NSM − the parent's true time\| < 2 s); `nsm_ignores_parent_clock` (NSM − the parent's clock = −120 s ± 2); `ready_while_parent_off`; one `run_phase_*` check for each change while running (no step, helper ok, ≤ 2 bad cycles, \|skew\| < 50 ms, NSM equal to true time) |
| **S9** (run `main`) | vsock 8000 refused, then held, for 120 s each with the clock good; then held for 11 minutes with S4's proof set | `refuse_no_proof.*` and `hold_no_proof.*` (no range, no proof set, the gate stays open, ranges resume after the block); `held_keeps_proof.*` (no range, and the proof stays `fast` for the whole 11 minutes, past the 10-minute window) |
| **S9-boot** (run `s9boot`) | vsock 8000 refused from before the launch | `parent_blocked_from_boot`; `ready_times_out` (`clock_unknown`); `waited_full_timeout` (≥ 175 s); `exits_78`; `no_proof_no_range`; `helper_fine` (ok and synced: the wait is KMS's alone) |

Every run also ends with a `drift` record. It is the slope of NSM time against
MONOTONIC_RAW for each scenario, from the watcher's NSM samples. It gives the
oscillator's true error in ppm for this instance, not production's: the 24 h
production soak (plan R12) measures that.

## Where it runs

The plan (decision D2) runs the probe on a **separate c7g.large**. That
instance avoids a 3-hour production outage, and it is the only place the
probe can act as a hostile parent (S8, S9). Launching it touches AWS, so it
needs the owner's explicit yes. The commands below assume that yes has been
given and the instance exists.

The fallback, with its own explicit yes, is the production parent for about
3 hours, `main` only.

- `clockprobe.sh` refuses the production parent (where
  `wappie-reader-supervisor` exists) unless
  `CLOCKPROBE_ALLOW_PRODUCTION_PARENT=1` is set.
- Even then it refuses `s8` and `s9boot`, and never blocks KMS or moves the
  clock there. The S9 parts of `main` then report `null`.
- It stops production for the run and always starts it again, as `probe.sh`
  does.

## Operator commands (on the parent, through SSM)

You run these, not an agent. The region is eu-west-1. `<probe-instance-id>`
is the separate c7g.large. `<sha>` is the head commit of the core PR that
carries the clock (plan R2: "Run the probe on the PR head before merging").

### 0. Open a session

```
aws sts get-caller-identity
aws ssm start-session --target <probe-instance-id> --region eu-west-1
sudo -i
```

### 1. Prepare the instance (once)

Use Amazon Linux 2023 arm64, with enclaves enabled at launch.

```
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git python3
sed -i 's/^memory_mib:.*/memory_mib: 1536/; s/^cpu_count:.*/cpu_count: 1/' /etc/nitro_enclaves/allocator.yaml
systemctl enable --now nitro-enclaves-allocator docker
# The stock proxy: vsock 8000 to kms.<region>.amazonaws.com, which is eu-west-1 here.
systemctl enable --now nitro-enclaves-vsock-proxy
systemctl is-active nitro-enclaves-allocator docker nitro-enclaves-vsock-proxy chronyd
git clone -q https://github.com/thehappieco/wappie.git /opt/wappie-clockprobe-src
```

If the allocator fails to reserve its memory, reboot once and check again.

### 2. Check out the PR head

```
cd /opt/wappie-clockprobe-src
git fetch -q origin <sha> || git fetch -q origin "pull/<PR number>/head"
git checkout -q --detach <sha>
git log -1 --format='%H %s'
```

### 3. P0 alone, first (about 10 minutes)

P0 settles the constants marked "settled by P0" before anything else runs.
That is the plan's order (section 5).

```
cd /opt/wappie-clockprobe-src
CLOCKPROBE_SCENARIOS=P0 deploy/enclave/clockprobe/clockprobe.sh main 2>&1 | tee /root/clockprobe-p0.log
```

The last lines print `P0: PASS` or `P0: FAIL [...]` and the paths.

- Read `obs.constants` and `obs.fallback_needed` in
  `/opt/wappie-reader/clockprobe/<stamp>/main/report.json`.
- If `fallback_needed` is true, stop here: the plan's fallback applies.
- The EIF in that directory can be reused below with `CLOCKPROBE_EIF=…`.

### 4. Everything (about 3 hours)

Run it under systemd, so that a dropped SSM session does not end it:

```
cd /opt/wappie-clockprobe-src
systemd-run --unit wappie-clockprobe --collect \
  --setenv=CLOCKPROBE_EIF=/opt/wappie-reader/clockprobe/<P0 stamp>/clockprobe.eif \
  /opt/wappie-clockprobe-src/deploy/enclave/clockprobe/clockprobe.sh main s8 s9boot
```

Leave out `--setenv=CLOCKPROBE_EIF=…` to build a fresh EIF.

To follow it, in the same or a later session:

```
journalctl -u wappie-clockprobe -f
ls -t /opt/wappie-reader/clockprobe/ | head -1
tail -f /opt/wappie-reader/clockprobe/<stamp>/main/console.log | grep --line-buffered '^CP '
```

To stop it early: `systemctl stop wappie-clockprobe`. The EXIT trap terminates
the enclave and puts back the KMS unit and the parent's chronyd.

To run one run, or some scenarios of `main`, again:

```
deploy/enclave/clockprobe/clockprobe.sh s8
CLOCKPROBE_SCENARIOS=S4,S9 deploy/enclave/clockprobe/clockprobe.sh main
CLOCKPROBE_S6_S=600 CLOCKPROBE_SCENARIOS=S6 deploy/enclave/clockprobe/clockprobe.sh main
```

### 5. Collect the results

```
cat /opt/wappie-reader/clockprobe/<stamp>/results.json
python3 /opt/wappie-clockprobe-src/deploy/enclave/clockprobe/assemble.py --summary /opt/wappie-reader/clockprobe/<stamp>
```

The summary prints one line per scenario, `S1: PASS` or `S1: FAIL [check, …]`.
It exits 1 if any scenario failed. `results.json` holds every check with its
value. Each run's directory also holds:

- `report.json` (every record);
- `console.log`;
- `control.log` (what the parent did, and when);
- `liveness.log`.

Copy `results.json` and the `report.json` files off the instance, then record
the outcome in `deploy/enclave/clockprobe/RESULTS-<date>.md`, as the A1 probe
did.

### 6. Afterwards

```
systemctl is-active chronyd nitro-enclaves-vsock-proxy   # both active again
nitro-cli describe-enclaves                              # []
```

Stopping or terminating the probe instance is the owner's call (D2).

### Fallback: the production parent, `main` only

Only with the owner's explicit yes for a production outage of about 3 hours.
The command is the same, with the flag set:

```
cd <a fresh core checkout at <sha>>
CLOCKPROBE_ALLOW_PRODUCTION_PARENT=1 deploy/enclave/clockprobe/clockprobe.sh main 2>&1 | tee /root/clockprobe-main.log
```

## Local validation (what was checked off-Nitro)

On an arm64 Mac with Docker:

- `build-image.sh` builds both images.
- The probe image runs unprivileged with `-e PROBE_CONSOLE=-`. Without
  `/dev/nsm`, P0 records the capabilities, the clocksource and adjtimex, and
  fails `clock_settime` and `adjtimex` with EPERM. Every other scenario
  reports "not run". The console then assembles into a complete report.
- `nsm-p0` builds with `cargo clippy -D warnings` clean in the pinned Rust
  image. It exits 2 without `/dev/nsm` and 3 on bad arguments.
- `kms-sampler.mjs` ran against the worktree's `clock.mjs`, with a fake
  state file and a fake Date server:
  - `ready` passed after two agreeing ranges;
  - with the Date 90 s ahead it set the proof `slow` after two ranges, with
    `clock_sources_disagree`.
- The unit tests:
  - `python3 -m unittest discover -s deploy/enclave/clockprobe -p 'test_*.py'`
    covers control.py against a fake system, and assemble.py;
  - `node --test deploy/enclave/clockprobe/evaluate.test.mjs` covers the step,
    rate and drift arithmetic.

None of this sets a clock. A privileged local container would set the Docker
VM's clock, so the scenarios themselves only run in an enclave.

## Deviations from the plan's section 5

- **Faults are injected with `clock_settime`** (`nsm-p0 shift`), not
  busybox `date -s`. `date -s` takes whole seconds only, so a "+3 s" could be
  anywhere from +2 to +3 s. It is the same system call.
- **The runner injects, not the entrypoint.** Several scenarios run in one
  boot, so `clockprobe-run.mjs` injects each fault and then calls the release
  `wappie-clock-start`. The entrypoint only takes the boot sample.
- **S4 does not require `chronyd_gone`.** nsm-timefeed checks the ledger
  before it feeds. The cycle that sees the +90 s trips `cap_exceeded` and
  feeds nothing, so chronyd may never see the jump and may never exit on
  `maxchange`. What the plan relies on is checked: the cap trips and stays,
  there is no step back, the gate stays shut and KMS proves the offset.
  chronyd's exit is recorded as `chronyd_exited`.
- **S6 cannot reach the 5 s gate in an hour.** At 200 ppm injected and at most
  110 ppm corrected, the offset grows by about 90 ppm, so 5 s takes about
  15 hours. The default hour checks the caps and the growth rate.
  `gate_closes_past_5s` is `null` unless `CLOCKPROBE_S6_S` is long enough;
  its `value` gives the estimated time. The `unc_high` rule itself is covered
  by `clock.test.mjs`.
- **Truncated or rounded timestamps cannot be told apart in the enclave.**
  They differ by a constant 0.5 ms, which looks the same as a clock offset.
  P0 settles the resolution (1 ms), and `TS_ROUNDING_NS` stays 0.5 ms. Being
  wrong costs 0.5 ms against a 500 ms `synced` threshold.

## Files

| File | Runs | Purpose |
|---|---|---|
| `build-image.sh` | parent, local | Builds the reader image and the probe on top. |
| `Dockerfile.clockprobe` | build | The probe layer: nsm-p0, the fake-drift nsm-timefeed, the runner and sampler, and the build-time checks. |
| `nsm-p0.rs` | enclave | Measures (P0), aligns and steps the clock, and watches the clocks. |
| `entrypoint-clockprobe.sh` | enclave | The boot sample, loopback, the KMS bridge, then the runner as a child. |
| `clockprobe-run.mjs` | enclave | The scenarios and their checks. |
| `evaluate.mjs` | enclave | The arithmetic: steps, rates, drift, CPU, verdicts. |
| `kms-sampler.mjs` | enclave | The reader's `clock.mjs` fed with KMS Date ranges. |
| `clockprobe.sh` | parent | The orchestration above. |
| `control.py` | parent | The hostile parent, on vsock 9103. |
| `assemble.py` | parent | `report.json` from a console, and `results.json` across runs. |
| `test_clockprobe.py`, `evaluate.test.mjs` | CI | Unit tests. |

None of the ports collides with production or the A1 probe. The probe uses
CID 30 and vsock 9103. Production uses 5443–5445, 7000–7002, 8000–8007, 9000
and CID 16; the A1 probe uses 9100 and 9101.
