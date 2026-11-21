// One sample: the three clocks read before and after an NSM request, the
// document it returned, and the rules that decide whether it is kept.
use super::cose::{self, DocError};
use super::{
    CONSISTENT_BASE_NS, CONSISTENT_PPM, NEW_LEVEL_SAMPLES, NS_PER_MS, NS_PER_S, RTT_FACTOR,
    RTT_HARD_CAP_NS, RTT_WINDOW, STEP_TOLERANCE_NS, TS_ROUNDING_NS,
};
use std::collections::VecDeque;

/// The clocks at one moment, in ns. `real` is CLOCK_REALTIME (what chronyd
/// steers), `raw` is CLOCK_MONOTONIC_RAW (the bare oscillator, untouched by
/// chronyd) and `mono` is CLOCK_MONOTONIC (the clock the reader's Node reads
/// through performance.now()).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub real_ns: i64,
    pub raw_ns: i64,
    pub mono_ns: i64,
}

// time_t and c_long are i64 on aarch64 and x86_64 Linux, not everywhere.
#[allow(clippy::useless_conversion)]
fn clock_ns(id: libc::clockid_t) -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid timespec; these clock ids always exist on Linux.
    unsafe { libc::clock_gettime(id, &mut ts) };
    i64::from(ts.tv_sec) * NS_PER_S + i64::from(ts.tv_nsec)
}

/// Reads the three clocks, MONOTONIC_RAW in the middle.
pub fn read_clocks() -> Reading {
    let real_ns = clock_ns(libc::CLOCK_REALTIME);
    let raw_ns = clock_ns(libc::CLOCK_MONOTONIC_RAW);
    let mono_ns = clock_ns(libc::CLOCK_MONOTONIC);
    Reading { real_ns, raw_ns, mono_ns }
}

/// The kernel's frequency correction in ppm (adjtimex `freq` / 65536), read
/// only. Positive speeds the clock up, so a clock that gains settles negative.
pub fn freq_ppm() -> Option<f64> {
    // SAFETY: an all-zero timex is valid; modes 0 only reads.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = 0;
    if unsafe { libc::adjtimex(&mut tx) } < 0 {
        return None;
    }
    Some(tx.freq as f64 / 65_536.0)
}

/// One request to the NSM. `document` is None when the NSM answered with an
/// error.
#[derive(Clone, Debug)]
pub struct Attempt {
    pub before: Reading,
    pub after: Reading,
    pub nonce: [u8; 32],
    pub document: Option<Vec<u8>>,
}

/// Why a sample was not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The NSM answered with an error.
    Nsm,
    /// The document failed to decode or failed a check (PCR0 included).
    Document(DocError),
    /// The clock was stepped while the NSM answered.
    Step,
    /// The round-trip keep rule.
    Rtt,
    /// NSM time disagrees with the last accepted sample (rule S2).
    Inconsistent,
}

impl Reject {
    /// The NSM or its document is at fault, not the timing.
    pub fn is_integrity(self) -> bool {
        matches!(self, Reject::Nsm | Reject::Document(_))
    }
}

/// A sample that passed the per-attempt checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub mid: Reading,
    /// Round trip on MONOTONIC_RAW.
    pub rtt_ns: i64,
    pub nsm_ms: u64,
    /// NSM - system at `mid.real_ns`.
    pub offset_ns: i64,
    pub pcr0: Vec<u8>,
}

fn midpoint(a: i64, b: i64) -> i64 {
    a + (b - a) / 2
}

/// NSM time minus system time, in ns, for an NSM timestamp in whole
/// milliseconds read at system time `mid_real_ns`. Positive: the system clock
/// is behind. This is the sign chronyd's SOCK driver expects.
pub fn offset_ns(nsm_ms: u64, mid_real_ns: i64) -> i64 {
    nsm_ms as i64 * NS_PER_MS + TS_ROUNDING_NS - mid_real_ns
}

#[cfg(feature = "fake-drift")]
fn fake_drift(nsm_ms: u64, mid_raw_ns: i64) -> u64 {
    let extra_ms = mid_raw_ns as i128 * super::FAKE_DRIFT_PPM as i128 / 1_000_000 / NS_PER_MS as i128;
    nsm_ms + extra_ms as u64
}

/// The per-attempt checks: an answer, no step during the request, a good
/// document for this nonce, and the PCR0 of this boot (when known).
pub fn examine(attempt: &Attempt, pcr0: Option<&[u8]>) -> Result<Candidate, Reject> {
    let document = attempt.document.as_deref().ok_or(Reject::Nsm)?;
    let (b, a) = (attempt.before, attempt.after);
    let rtt_ns = a.raw_ns - b.raw_ns;
    if rtt_ns < 0 || ((a.real_ns - b.real_ns) - rtt_ns).abs() > STEP_TOLERANCE_NS {
        return Err(Reject::Step);
    }
    let doc = cose::decode(document, &attempt.nonce).map_err(Reject::Document)?;
    if pcr0.is_some_and(|p| p != doc.pcr0.as_slice()) {
        return Err(Reject::Document(DocError::Pcr0));
    }
    let mid = Reading {
        real_ns: midpoint(b.real_ns, a.real_ns),
        raw_ns: midpoint(b.raw_ns, a.raw_ns),
        mono_ns: midpoint(b.mono_ns, a.mono_ns),
    };
    #[cfg(feature = "fake-drift")]
    let nsm_ms = fake_drift(doc.timestamp_ms, mid.raw_ns);
    #[cfg(not(feature = "fake-drift"))]
    let nsm_ms = doc.timestamp_ms;
    Ok(Candidate { mid, rtt_ns, nsm_ms, offset_ns: offset_ns(nsm_ms, mid.real_ns), pcr0: doc.pcr0 })
}

/// The round-trip keep rule (see RTT_FACTOR). Each cycle's best round trip
/// goes into the window whether it is kept or not, so the minimum follows a
/// sustained change in latency within RTT_WINDOW cycles.
#[derive(Debug, Default)]
pub struct RttFilter {
    recent: VecDeque<i64>,
}

impl RttFilter {
    pub fn keep(&mut self, rtt_ns: i64) -> bool {
        self.recent.push_back(rtt_ns);
        while self.recent.len() > RTT_WINDOW {
            self.recent.pop_front();
        }
        let min = self.recent.iter().copied().min().unwrap_or(rtt_ns);
        rtt_ns <= RTT_HARD_CAP_NS && rtt_ns <= RTT_FACTOR.saturating_mul(min)
    }
}

/// A point on the NSM timeline: (NSM ms, MONOTONIC_RAW ns).
type Point = (u64, i64);

/// Rule S2: NSM time must move with MONOTONIC_RAW, within 1 s + 200 ppm of
/// the time between two samples. A sample that disagrees with the last
/// accepted one is held back; NEW_LEVEL_SAMPLES samples in a row that agree
/// with each other become the new level.
#[derive(Debug, Default)]
pub struct Consistency {
    anchor: Option<Point>,
    pending: Vec<Point>,
}

pub fn agree(a: Point, b: Point) -> bool {
    let d_raw = b.1 - a.1;
    let d_nsm = (b.0 as i64 - a.0 as i64) * NS_PER_MS;
    (d_nsm - d_raw).abs() <= CONSISTENT_BASE_NS + d_raw.abs() / 1_000_000 * CONSISTENT_PPM
}

impl Consistency {
    pub fn accept(&mut self, nsm_ms: u64, raw_ns: i64) -> bool {
        let point = (nsm_ms, raw_ns);
        match self.anchor {
            Some(anchor) if !agree(anchor, point) => {
                if !self.pending.iter().all(|&p| agree(p, point)) {
                    self.pending.clear();
                }
                self.pending.push(point);
                if self.pending.len() < NEW_LEVEL_SAMPLES {
                    return false;
                }
            }
            _ => {}
        }
        self.anchor = Some(point);
        self.pending.clear();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_sign_system_behind_is_positive() {
        // NSM says 12:00:00.000 (centred: .0005); the system reads 11:59:59.000.
        let ts = 1_795_089_600_000u64;
        let system = ts as i64 * NS_PER_MS - NS_PER_S;
        assert_eq!(offset_ns(ts, system), NS_PER_S + 500_000);
        // System ahead by 2 s: negative.
        assert_eq!(offset_ns(ts, ts as i64 * NS_PER_MS + 2 * NS_PER_S), -2 * NS_PER_S + 500_000);
    }

    #[test]
    fn half_a_millisecond_centres_the_truncated_timestamp() {
        let ts = 1_795_089_600_000u64;
        assert_eq!(TS_ROUNDING_NS, 500_000);
        assert_eq!(offset_ns(ts, ts as i64 * NS_PER_MS + 500_000), 0);
        assert_eq!(offset_ns(ts, ts as i64 * NS_PER_MS), 500_000);
    }

    #[test]
    fn rtt_rule_keeps_up_to_twice_the_window_minimum() {
        let ms = NS_PER_MS;
        let mut f = RttFilter::default();
        assert!(f.keep(10 * ms), "the first sample is its own minimum");
        assert!(f.keep(20 * ms), "exactly 2x");
        assert!(!f.keep(21 * ms), "over 2x");
        assert!(f.keep(5 * ms));
        assert!(!f.keep(11 * ms), "the minimum is now 5 ms");
    }

    #[test]
    fn rtt_rule_follows_a_sustained_rise_within_the_window() {
        let ms = NS_PER_MS;
        let mut f = RttFilter::default();
        assert!(f.keep(ms));
        let mut kept_at = None;
        for i in 1..=RTT_WINDOW {
            if f.keep(100 * ms) {
                kept_at = Some(i);
                break;
            }
        }
        assert_eq!(kept_at, Some(RTT_WINDOW), "kept once the 1 ms sample leaves the window");
    }

    #[test]
    fn rtt_rule_hard_cap() {
        let mut f = RttFilter::default();
        assert!(f.keep(RTT_HARD_CAP_NS));
        assert!(!f.keep(RTT_HARD_CAP_NS + 1));
        let mut f = RttFilter::default();
        assert!(!f.keep(RTT_HARD_CAP_NS + 1), "even as the window's only sample");
    }

    fn attempt(before: Reading, after: Reading) -> Attempt {
        Attempt { before, after, nonce: [0; 32], document: Some(vec![0xf6]) }
    }

    #[test]
    fn a_step_during_the_request_rejects_the_sample() {
        let b = Reading { real_ns: 1_000 * NS_PER_S, raw_ns: 10 * NS_PER_S, mono_ns: 10 * NS_PER_S };
        let a = |real_extra: i64| Reading {
            real_ns: b.real_ns + 3 * NS_PER_MS + real_extra,
            raw_ns: b.raw_ns + 3 * NS_PER_MS,
            mono_ns: b.mono_ns + 3 * NS_PER_MS,
        };
        assert_eq!(examine(&attempt(b, a(STEP_TOLERANCE_NS + 1)), None), Err(Reject::Step));
        assert_eq!(examine(&attempt(b, a(-STEP_TOLERANCE_NS - 1)), None), Err(Reject::Step));
        // Within tolerance the step check passes and the (bogus) document fails.
        assert!(matches!(examine(&attempt(b, a(STEP_TOLERANCE_NS)), None), Err(Reject::Document(_))));
        let mut no_answer = attempt(b, a(0));
        no_answer.document = None;
        assert_eq!(examine(&no_answer, None), Err(Reject::Nsm));
    }

    #[test]
    fn consistency_accepts_time_moving_with_the_oscillator() {
        let mut c = Consistency::default();
        let t0 = 1_795_089_600_000u64;
        assert!(c.accept(t0, 0), "the first sample sets the level");
        assert!(c.accept(t0 + 4_000, 4 * NS_PER_S));
        // 1 s off after 4 s: at the limit (1 s + 200 ppm of 4 s = 1.0008 s).
        assert!(c.accept(t0 + 9_000, 8 * NS_PER_S));
    }

    #[test]
    fn consistency_allows_200_ppm_over_long_gaps() {
        let mut c = Consistency::default();
        let t0 = 1_795_089_600_000u64;
        assert!(c.accept(t0, 0));
        // 10 000 s later: 1 s + 2 s allowed.
        let raw = 10_000 * NS_PER_S;
        assert!(c.accept(t0 + 10_000_000 + 2_999, raw));
        let mut c = Consistency::default();
        assert!(c.accept(t0, 0));
        assert!(!c.accept(t0 + 10_000_000 + 3_001, raw));
    }

    #[test]
    fn consistency_takes_a_new_level_after_three_agreeing_samples() {
        let mut c = Consistency::default();
        let t0 = 1_795_089_600_000u64;
        assert!(c.accept(t0, 0));
        // NSM jumps back 2 s.
        assert!(!c.accept(t0 + 4_000 - 2_000, 4 * NS_PER_S));
        assert!(!c.accept(t0 + 8_000 - 2_000, 8 * NS_PER_S));
        assert!(c.accept(t0 + 12_000 - 2_000, 12 * NS_PER_S), "the third agreeing sample");
        assert!(c.accept(t0 + 16_000 - 2_000, 16 * NS_PER_S), "the new level holds");
    }

    #[test]
    fn consistency_restarts_the_count_when_held_samples_disagree() {
        let mut c = Consistency::default();
        let t0 = 1_795_089_600_000u64;
        assert!(c.accept(t0, 0));
        assert!(!c.accept(t0 + 4_000 + 5_000, 4 * NS_PER_S));
        assert!(!c.accept(t0 + 8_000 + 5_000, 8 * NS_PER_S));
        // A third sample on yet another level: the count starts again.
        assert!(!c.accept(t0 + 12_000 - 7_000, 12 * NS_PER_S));
        // Back on the old level: accepted at once.
        assert!(c.accept(t0 + 16_000, 16 * NS_PER_S));
    }
}
