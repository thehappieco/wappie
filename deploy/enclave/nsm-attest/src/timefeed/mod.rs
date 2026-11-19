// nsm-timefeed: feeds the Nitro Secure Module's time to chronyd and writes
// what it sees to a state file the reader reads (docs/mcp-enclave.md, Clock).
//
// Every cycle it asks the NSM for a few attestation documents, keeps the one
// with the smallest round trip, checks it, and works out
//   offset = NSM time - system time   (positive: the system clock is behind)
// at the midpoint of the request. A good sample is sent to chronyd's SOCK
// reference clock, and the result of the cycle goes to <state_dir>/state.json.
//
// The modules:
// - sample: the clocks, one attempt, the round-trip and consistency rules;
// - cose: decoding and checking one attestation document;
// - sock: the 40-byte sample chronyd's SOCK driver reads;
// - boot: the boot gate (the first good sample of this enclave boot);
// - ledger: the watchdog over how much the system clock has been corrected;
// - state: one cycle from start to end, and the state file.
//
// Signs used throughout: offset_ns is NSM minus system; nsm_skew_ms in the
// state file is system minus NSM (its negation), the sign the reader's other
// skew fields use.

pub mod boot;
pub mod cose;
pub mod ledger;
pub mod sample;
pub mod sock;
pub mod state;

use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub const NS_PER_MS: i64 = 1_000_000;
pub const NS_PER_S: i64 = 1_000 * NS_PER_MS;
pub const HOUR_NS: i64 = 3_600 * NS_PER_S;

/// One cycle every 4 s: at chronyd's `poll 5 filter 8` that is 8 samples per
/// poll. Settled by P0 (the CPU cost of a cycle on one vCPU).
pub const CYCLE_NS: i64 = 4 * NS_PER_S;

/// Attestations per cycle, back to back; the one with the smallest round trip
/// is used. Settled by P0 (the CPU cost of a cycle on one vCPU).
pub const BEST_OF: usize = 3;

/// The round-trip keep rule: a cycle's best sample is kept only if its round
/// trip is at most RTT_FACTOR times the smallest of the last RTT_WINDOW
/// cycles' best round trips, and never over RTT_HARD_CAP_NS. rtt/2 then goes
/// into the reader's uncertainty. Settled by P0 (NSM ioctl latency alone and
/// under concurrent nsm-attest load).
pub const RTT_FACTOR: i64 = 2;
/// Settled by P0 (NSM ioctl latency under load).
pub const RTT_HARD_CAP_NS: i64 = 500 * NS_PER_MS;
/// 15 cycles is 60 s, well inside STALE_NS: under a sustained load the
/// minimum rises with it before the feed goes stale. Settled by P0.
pub const RTT_WINDOW: usize = 15;

/// The NSM timestamp is in whole milliseconds; it is taken to be truncated,
/// so half a millisecond is added to centre it. Settled by P0 (timestamp
/// resolution and rounding).
pub const TS_ROUNDING_NS: i64 = NS_PER_MS / 2;

/// A sample is thrown away if REALTIME and MONOTONIC_RAW disagree by more than
/// this over the request: the clock was stepped while the NSM answered.
pub const STEP_TOLERANCE_NS: i64 = 2 * NS_PER_MS;

/// Boot gate: the first good sample of an enclave boot may be off by at most
/// 10 minutes. Beyond that the feed never feeds chronyd this boot.
pub const BOOT_MAX_NS: i64 = 600 * NS_PER_S;

/// Ledger caps on |change in (REALTIME - MONOTONIC_RAW)|.
pub const HOUR_CAP_NS: i64 = 5 * NS_PER_S;
pub const DAY_CAP_NS: i64 = 10 * NS_PER_S;
/// The ledger starts once a good sample is this close to NSM time, so the
/// boot step stays out of its budget.
pub const BASELINE_MAX_OFFSET_NS: i64 = NS_PER_S;
/// A change in REALTIME - MONOTONIC_RAW larger than this between two cycles
/// counts as a clock step (the `steps` field).
pub const CLOCK_STEP_NS: i64 = 100 * NS_PER_MS;

/// No good sample for this long: state nsm_stale.
pub const STALE_NS: i64 = 120 * NS_PER_S;

/// Consistency of NSM time between samples: |dNSM - dMONOTONIC_RAW| may be at
/// most 1 s + 200 ppm of the time between them. A new level is accepted once
/// NEW_LEVEL_SAMPLES samples in a row agree with each other.
pub const CONSISTENT_BASE_NS: i64 = NS_PER_S;
pub const CONSISTENT_PPM: i64 = 200;
pub const NEW_LEVEL_SAMPLES: usize = 3;

/// `synced`: every good sample within 500 ms of NSM time for at least two
/// chrony polls (poll 5 is 32 s).
pub const SYNC_MAX_OFFSET_NS: i64 = 500 * NS_PER_MS;
pub const SYNC_SPAN_NS: i64 = 64 * NS_PER_S;

/// A failing send to chronyd turns into chronyd_gone once nothing has been
/// delivered for this long (the grace also covers chronyd's start).
pub const CHRONYD_GRACE_NS: i64 = 30 * NS_PER_S;

/// Cycles in a row in which every attempt failed at the NSM or its document
/// failed a check: state nsm_error.
pub const NSM_ERROR_CYCLES: u32 = 3;

/// NSM timestamps must lie strictly between these (milliseconds since the
/// epoch). The floor is fixed in the source, 2026-11-01T00:00:00Z, so the
/// binary does not change with every commit.
pub const DATE_FLOOR_MS: u64 = 1_793_491_200_000;
/// 2100-01-01T00:00:00Z.
pub const DATE_CEIL_MS: u64 = 4_102_444_800_000;

/// Seconds allowed for one NSM ioctl. SIGALRM then ends the helper (exit 1)
/// and the entrypoint's loop starts it again.
pub const ALARM_S: u32 = 5;

/// Probe builds only: the NSM time reported is scaled by +200 ppm of the
/// time since boot (MONOTONIC_RAW).
#[cfg(feature = "fake-drift")]
pub const FAKE_DRIFT_PPM: i64 = 200;
/// The marker check-image.sh looks for: the release binary must not hold it.
#[cfg(feature = "fake-drift")]
pub const FAKE_DRIFT_MARKER: &str = "WAPPIE_FAKE_DRIFT";

/// Writes a file whole or not at all: a temporary file next to it, then a
/// rename over it, so a reader never sees half a file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    {
        let mut file = fs::File::create(tmp)?;
        file.write_all(bytes)?;
        file.flush()?;
    }
    fs::rename(tmp, path)
}

/// Reads a file, or None when it does not exist.
pub fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
