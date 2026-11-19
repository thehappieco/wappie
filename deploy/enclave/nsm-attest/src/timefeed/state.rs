// One cycle of nsm-timefeed, from the attempts to the state file, with every
// input passed in so the tests can drive it.
//
// <state_dir>/state.json is written whole (a temporary file, then a rename)
// at the end of every cycle:
//   {"v":1, "mono_ns", "last_good_mono_ns", "state", "synced", "nsm_skew_ms",
//    "rtt_us", "good", "bad", "corr_hour_ms", "corr_day_ms", "freq_ppm",
//    "steps"}
// - mono_ns and last_good_mono_ns are CLOCK_MONOTONIC, the clock the reader's
//   Node reads, at the end of this cycle and at the last good sample;
// - nsm_skew_ms is system minus NSM at the last good sample (the negated
//   offset), rtt_us its round trip; null before the first good sample;
// - good and bad count this helper's cycles;
// - corr_hour_ms and corr_day_ms are the ledger's ranges (null until the
//   ledger starts), steps its count of clock steps;
// - freq_ppm is the kernel's frequency correction (adjtimex freq/65536).
//
// state, the first that applies:
// - cap_exceeded: the ledger tripped (sticky for the boot; nothing is fed);
// - boot_refused: the boot gate refused (sticky for the boot; nothing is fed);
// - nsm_error: NSM_ERROR_CYCLES cycles in a row with every attempt failing
//   at the NSM or a document check;
// - nsm_stale: no good sample for STALE_NS (counted from the helper's start
//   when it has had none);
// - starting: no good sample yet;
// - chronyd_gone: the last send failed and nothing reached chronyd for
//   CHRONYD_GRACE_NS (counted from the helper's start when nothing has);
// - ok.
use super::boot::{self, Boot};
use super::ledger::Ledger;
use super::sample::{examine, Attempt, Candidate, Consistency, Reading, Reject, RttFilter};
use super::sock::{SockSample, SAMPLE_LEN};
use super::{
    write_atomic, CHRONYD_GRACE_NS, NSM_ERROR_CYCLES, NS_PER_MS, STALE_NS, SYNC_MAX_OFFSET_NS,
    SYNC_SPAN_NS,
};
use std::io;
use std::path::{Path, PathBuf};

pub const STATE_FILE: &str = "state.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ok,
    Starting,
    BootRefused,
    CapExceeded,
    ChronydGone,
    NsmStale,
    NsmError,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Starting => "starting",
            State::BootRefused => "boot_refused",
            State::CapExceeded => "cap_exceeded",
            State::ChronydGone => "chronyd_gone",
            State::NsmStale => "nsm_stale",
            State::NsmError => "nsm_error",
        }
    }
}

/// What one cycle saw.
pub struct CycleInput {
    /// The clocks at the start of the cycle (the ledger's reading).
    pub start: Reading,
    /// BEST_OF attempts, in order.
    pub attempts: Vec<Attempt>,
    /// adjtimex's frequency, if it could be read.
    pub freq_ppm: Option<f64>,
    /// CLOCK_MONOTONIC at the end of the cycle.
    pub end_mono_ns: i64,
}

/// The last good sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Good {
    pub mono_ns: i64,
    pub offset_ns: i64,
    pub rtt_ns: i64,
}

/// The result of one cycle, as written to state.json.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub mono_ns: i64,
    pub last_good: Option<Good>,
    pub state: State,
    pub synced: bool,
    pub good: u64,
    pub bad: u64,
    pub corr_hour_ns: Option<i64>,
    pub corr_day_ns: Option<i64>,
    pub freq_ppm: Option<f64>,
    pub steps: u64,
    /// Whether this cycle sent a sample to chronyd (not in the file).
    pub fed: bool,
    /// Why this cycle's sample was not used, if it was not (not in the file).
    pub reject: Option<Reject>,
}

fn round_div(n: i64, d: i64) -> i64 {
    (n as f64 / d as f64).round() as i64
}

impl Snapshot {
    pub fn to_json(&self) -> String {
        let int = |v: Option<i64>| v.map_or("null".to_owned(), |v| v.to_string());
        let float = |v: Option<f64>| v.filter(|v| v.is_finite()).map_or("null".to_owned(), |v| format!("{v:.3}"));
        let g = self.last_good;
        format!(
            concat!(
                "{{\"v\":1,\"mono_ns\":{},\"last_good_mono_ns\":{},\"state\":\"{}\",\"synced\":{},",
                "\"nsm_skew_ms\":{},\"rtt_us\":{},\"good\":{},\"bad\":{},\"corr_hour_ms\":{},",
                "\"corr_day_ms\":{},\"freq_ppm\":{},\"steps\":{}}}\n"
            ),
            self.mono_ns,
            int(g.map(|g| g.mono_ns)),
            self.state.as_str(),
            self.synced,
            float(g.map(|g| -(g.offset_ns as f64) / NS_PER_MS as f64)),
            int(g.map(|g| round_div(g.rtt_ns, 1_000))),
            self.good,
            self.bad,
            int(self.corr_hour_ns.map(|v| round_div(v, NS_PER_MS))),
            int(self.corr_day_ns.map(|v| round_div(v, NS_PER_MS))),
            float(self.freq_ppm),
            self.steps,
        )
    }
}

/// nsm-timefeed's state across cycles.
pub struct Machine {
    dir: PathBuf,
    started_mono_ns: i64,
    boot: Option<Boot>,
    pcr0: Option<Vec<u8>>,
    rtt: RttFilter,
    consistency: Consistency,
    ledger: Ledger,
    good: u64,
    bad: u64,
    last_good: Option<Good>,
    sync_since_mono_ns: Option<i64>,
    failing_cycles: u32,
    delivered_mono_ns: i64,
    send_failing: bool,
}

impl Machine {
    /// Loads what this boot has recorded in `dir` (which must exist).
    pub fn open(dir: &Path, started_mono_ns: i64) -> io::Result<Machine> {
        if !dir.is_dir() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "state_dir is not a directory"));
        }
        // A PCR0 file that cannot be read is replaced by the next good
        // document's; the boot decision and the ledger fail closed instead.
        let pcr0 = boot::load_pcr0(dir).or_else(|e| match e.kind() {
            io::ErrorKind::InvalidData => Ok(None),
            _ => Err(e),
        })?;
        Ok(Machine {
            dir: dir.to_path_buf(),
            started_mono_ns,
            boot: boot::load(dir)?,
            pcr0,
            rtt: RttFilter::default(),
            consistency: Consistency::default(),
            ledger: Ledger::load(dir)?,
            good: 0,
            bad: 0,
            last_good: None,
            sync_since_mono_ns: None,
            failing_cycles: 0,
            delivered_mono_ns: started_mono_ns,
            send_failing: false,
        })
    }

    /// Picks this cycle's sample: the smallest round trip among the attempts
    /// that pass their own checks, then the round-trip rule and rule S2.
    fn choose(&mut self, attempts: &[Attempt]) -> Result<Candidate, Reject> {
        let mut best: Option<Candidate> = None;
        let mut first_reject = None;
        let mut timing_reject = false;
        for attempt in attempts {
            match examine(attempt, self.pcr0.as_deref()) {
                Ok(c) => {
                    if best.as_ref().is_none_or(|b| c.rtt_ns < b.rtt_ns) {
                        best = Some(c);
                    }
                }
                Err(r) => {
                    timing_reject |= !r.is_integrity();
                    first_reject.get_or_insert(r);
                }
            }
        }
        let Some(best) = best else {
            // Every attempt failed: an integrity failure only if none of them
            // failed on timing alone.
            if timing_reject {
                self.failing_cycles = 0;
            } else {
                self.failing_cycles += 1;
            }
            return Err(first_reject.unwrap_or(Reject::Nsm));
        };
        self.failing_cycles = 0;
        if !self.rtt.keep(best.rtt_ns) {
            return Err(Reject::Rtt);
        }
        if !self.consistency.accept(best.nsm_ms, best.mid.raw_ns) {
            return Err(Reject::Inconsistent);
        }
        Ok(best)
    }

    /// Runs one cycle. `send` delivers a sample to chronyd.
    pub fn cycle(
        &mut self,
        input: CycleInput,
        send: &mut dyn FnMut(&[u8; SAMPLE_LEN]) -> io::Result<()>,
    ) -> io::Result<Snapshot> {
        let chosen = self.choose(&input.attempts);
        let (sample, reject) = match chosen {
            Ok(c) => (Some(c), None),
            Err(r) => (None, Some(r)),
        };

        // The ledger first, so a breach in this cycle already stops the feed.
        let corr_ns = input.start.real_ns - input.start.raw_ns;
        self.ledger.observe(input.start.raw_ns, corr_ns, sample.as_ref().map(|c| c.offset_ns));
        self.ledger.store(&self.dir)?;

        let mut fed = false;
        if let Some(c) = &sample {
            self.good += 1;
            self.last_good = Some(Good { mono_ns: c.mid.mono_ns, offset_ns: c.offset_ns, rtt_ns: c.rtt_ns });
            if self.pcr0.is_none() {
                boot::store_pcr0(&self.dir, &c.pcr0)?;
                self.pcr0 = Some(c.pcr0.clone());
            }
            if self.boot.is_none() {
                let decided = Boot::decide(c.offset_ns);
                boot::store(&self.dir, decided)?;
                self.boot = Some(decided);
            }
            if c.offset_ns.abs() <= SYNC_MAX_OFFSET_NS {
                self.sync_since_mono_ns.get_or_insert(c.mid.mono_ns);
            } else {
                self.sync_since_mono_ns = None;
            }
            if self.boot == Some(Boot::Ok) && !self.ledger.breached() {
                match send(&SockSample::new(c.mid.real_ns, c.offset_ns).to_bytes()) {
                    Ok(()) => {
                        fed = true;
                        self.send_failing = false;
                        self.delivered_mono_ns = input.end_mono_ns;
                    }
                    Err(_) => self.send_failing = true,
                }
            }
        } else {
            self.bad += 1;
        }

        let now = input.end_mono_ns;
        let good_age = now - self.last_good.map_or(self.started_mono_ns, |g| g.mono_ns);
        let stale = good_age >= STALE_NS;
        if stale {
            self.sync_since_mono_ns = None;
        }
        let synced = match (self.sync_since_mono_ns, self.last_good) {
            (Some(since), Some(g)) => g.mono_ns - since >= SYNC_SPAN_NS,
            _ => false,
        };
        let state = if self.ledger.breached() {
            State::CapExceeded
        } else if self.boot == Some(Boot::Refused) {
            State::BootRefused
        } else if self.failing_cycles >= NSM_ERROR_CYCLES {
            State::NsmError
        } else if stale {
            State::NsmStale
        } else if self.last_good.is_none() {
            State::Starting
        } else if self.send_failing && now - self.delivered_mono_ns > CHRONYD_GRACE_NS {
            State::ChronydGone
        } else {
            State::Ok
        };

        let snapshot = Snapshot {
            mono_ns: now,
            last_good: self.last_good,
            state,
            synced,
            good: self.good,
            bad: self.bad,
            corr_hour_ns: self.ledger.hour_ns(),
            corr_day_ns: self.ledger.day_ns(),
            freq_ppm: input.freq_ppm,
            steps: self.ledger.steps(),
            fed,
            reject,
        };
        write_atomic(&self.dir.join(STATE_FILE), snapshot.to_json().as_bytes())?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape() {
        let s = Snapshot {
            mono_ns: 123_000_000_000,
            last_good: Some(Good { mono_ns: 122_000_000_000, offset_ns: 1_234_567, rtt_ns: 2_500_400 }),
            state: State::Ok,
            synced: true,
            good: 7,
            bad: 2,
            corr_hour_ns: Some(1_499_999),
            corr_day_ns: Some(-1),
            freq_ppm: Some(-17.25),
            steps: 1,
            fed: true,
            reject: None,
        };
        assert_eq!(
            s.to_json(),
            "{\"v\":1,\"mono_ns\":123000000000,\"last_good_mono_ns\":122000000000,\"state\":\"ok\",\
             \"synced\":true,\"nsm_skew_ms\":-1.235,\"rtt_us\":2500,\"good\":7,\"bad\":2,\
             \"corr_hour_ms\":1,\"corr_day_ms\":0,\"freq_ppm\":-17.250,\"steps\":1}\n"
        );
        let empty = Snapshot { last_good: None, corr_hour_ns: None, corr_day_ns: None, freq_ppm: None, state: State::Starting, synced: false, ..s };
        assert_eq!(
            empty.to_json(),
            "{\"v\":1,\"mono_ns\":123000000000,\"last_good_mono_ns\":null,\"state\":\"starting\",\
             \"synced\":false,\"nsm_skew_ms\":null,\"rtt_us\":null,\"good\":7,\"bad\":2,\
             \"corr_hour_ms\":null,\"corr_day_ms\":null,\"freq_ppm\":null,\"steps\":1}\n"
        );
    }
}
