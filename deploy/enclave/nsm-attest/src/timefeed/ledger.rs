// The cap watchdog. Correction is corr = REALTIME - MONOTONIC_RAW: steps,
// slewing and frequency correction all show up in it, and so does a step
// nobody explains (which should fail closed).
//
// The ledger starts (its baseline) at the first good sample within 1 s of NSM
// time, which keeps the boot step out of the budget. From then on it keeps
// the smallest and largest corr seen in each hour since the baseline, for the
// current hour and the 24 before it (25 buckets), in <state_dir>/ledger, so a
// restarted helper carries on.
//
// The caps are checked on whole buckets, which errs towards tripping:
// - hour: the range of corr over the current and previous bucket (a window of
//   one to two hours, so it holds every one-hour window ending now) must stay
//   within HOUR_CAP_NS;
// - day: the range over all 25 buckets (24 to 25 hours) within DAY_CAP_NS.
// chronyd's own limits (maxslewrate 60 + maxdrift 50, 110 ppm) allow at most
// 0.8 s in two hours and 9.9 s in 25 hours, so a working chronyd stays under
// both. A breach is sticky for the rest of the boot and stops the feed.
//
// It also counts clock steps: a change in corr over CLOCK_STEP_NS between two
// cycles, from the helper's first cycle of the boot, so the boot step counts.
use super::{
    read_optional, write_atomic, BASELINE_MAX_OFFSET_NS, CLOCK_STEP_NS, DAY_CAP_NS, HOUR_CAP_NS,
    HOUR_NS,
};
use std::io;
use std::path::Path;

/// Hours kept: the current one and the 24 before it.
pub const BUCKETS: i64 = 25;
const FILE: &str = "ledger";
const HEADER: &str = "wappie-clock-ledger v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    /// Whole hours since the baseline, on MONOTONIC_RAW.
    pub hour: i64,
    pub min_ns: i64,
    pub max_ns: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    base_raw_ns: Option<i64>,
    buckets: Vec<Bucket>,
    breached: bool,
    steps: u64,
    last_corr_ns: Option<i64>,
    /// The last ranges worked out (not stored; None until the next cycle).
    hour_ns: Option<i64>,
    day_ns: Option<i64>,
}

impl Ledger {
    /// A ledger that cannot be read: breached, so the feed fails closed.
    pub fn damaged() -> Self {
        Ledger { breached: true, ..Ledger::default() }
    }

    pub fn breached(&self) -> bool {
        self.breached
    }

    pub fn steps(&self) -> u64 {
        self.steps
    }

    pub fn started(&self) -> bool {
        self.base_raw_ns.is_some()
    }

    /// The range of corr over the hour window, in ns (None before the baseline).
    pub fn hour_ns(&self) -> Option<i64> {
        self.hour_ns
    }

    /// The range of corr over the day window, in ns.
    pub fn day_ns(&self) -> Option<i64> {
        self.day_ns
    }

    /// One cycle: corr read at `raw_ns`, and this cycle's good offset if any.
    pub fn observe(&mut self, raw_ns: i64, corr_ns: i64, offset_ns: Option<i64>) {
        if let Some(last) = self.last_corr_ns {
            if (corr_ns - last).abs() > CLOCK_STEP_NS {
                self.steps += 1;
            }
        }
        self.last_corr_ns = Some(corr_ns);

        let base = match (self.base_raw_ns, offset_ns) {
            (Some(base), _) => base,
            (None, Some(offset)) if offset.abs() < BASELINE_MAX_OFFSET_NS => {
                self.base_raw_ns = Some(raw_ns);
                raw_ns
            }
            (None, _) => return,
        };
        let hour = (raw_ns - base).div_euclid(HOUR_NS);
        match self.buckets.iter_mut().find(|b| b.hour == hour) {
            Some(b) => {
                b.min_ns = b.min_ns.min(corr_ns);
                b.max_ns = b.max_ns.max(corr_ns);
            }
            None => self.buckets.push(Bucket { hour, min_ns: corr_ns, max_ns: corr_ns }),
        }
        self.buckets.retain(|b| b.hour > hour - BUCKETS);
        let range = |from: i64| {
            let within = self.buckets.iter().filter(|b| b.hour >= from);
            let max = within.clone().map(|b| b.max_ns).max().unwrap_or(corr_ns);
            let min = within.map(|b| b.min_ns).min().unwrap_or(corr_ns);
            max - min
        };
        let (hour_ns, day_ns) = (range(hour - 1), range(hour - (BUCKETS - 1)));
        self.hour_ns = Some(hour_ns);
        self.day_ns = Some(day_ns);
        if hour_ns > HOUR_CAP_NS || day_ns > DAY_CAP_NS {
            self.breached = true;
        }
    }

    pub fn to_text(&self) -> String {
        let opt = |v: Option<i64>| v.map_or("-".to_owned(), |v| v.to_string());
        let mut out = format!(
            "{HEADER}\nbase {}\nsteps {}\nlast {}\nbreached {}\n",
            opt(self.base_raw_ns),
            self.steps,
            opt(self.last_corr_ns),
            u8::from(self.breached)
        );
        for b in &self.buckets {
            out.push_str(&format!("bucket {} {} {}\n", b.hour, b.min_ns, b.max_ns));
        }
        out
    }

    pub fn from_text(text: &str) -> Option<Ledger> {
        let mut lines = text.lines();
        if lines.next()? != HEADER {
            return None;
        }
        let mut field = |name: &str| -> Option<String> {
            let line = lines.next()?;
            let value = line.strip_prefix(name)?.strip_prefix(' ')?;
            Some(value.to_owned())
        };
        let opt = |v: String| -> Option<Option<i64>> {
            if v == "-" { Some(None) } else { v.parse().ok().map(Some) }
        };
        let base_raw_ns = opt(field("base")?)?;
        let steps = field("steps")?.parse().ok()?;
        let last_corr_ns = opt(field("last")?)?;
        let breached = match field("breached")?.as_str() {
            "0" => false,
            "1" => true,
            _ => return None,
        };
        let mut buckets = Vec::new();
        for line in lines {
            let mut parts = line.strip_prefix("bucket ")?.split(' ');
            let mut num = || parts.next()?.parse::<i64>().ok();
            let bucket = Bucket { hour: num()?, min_ns: num()?, max_ns: num()? };
            if parts.next().is_some() || bucket.min_ns > bucket.max_ns {
                return None;
            }
            buckets.push(bucket);
        }
        if buckets.len() as i64 > BUCKETS || (base_raw_ns.is_none() && !buckets.is_empty()) {
            return None;
        }
        Some(Ledger { base_raw_ns, buckets, breached, steps, last_corr_ns, hour_ns: None, day_ns: None })
    }

    /// The stored ledger, a new one when there is none, or a breached one
    /// when the file cannot be parsed.
    pub fn load(dir: &Path) -> io::Result<Ledger> {
        Ok(match read_optional(&dir.join(FILE))? {
            None => Ledger::default(),
            Some(bytes) => std::str::from_utf8(&bytes).ok().and_then(Ledger::from_text).unwrap_or_else(Ledger::damaged),
        })
    }

    pub fn store(&self, dir: &Path) -> io::Result<()> {
        write_atomic(&dir.join(FILE), self.to_text().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timefeed::{NS_PER_MS, NS_PER_S};

    const BOOT_REAL: i64 = 1_795_089_600 * NS_PER_S;
    const MIN: i64 = 60 * NS_PER_S;

    /// Feeds a cycle every minute from `from` to `to` (raw ns) with corr given
    /// by `corr(raw)`, and a good offset of 0.
    fn run(l: &mut Ledger, from: i64, to: i64, corr: impl Fn(i64) -> i64) {
        let mut raw = from;
        while raw <= to {
            l.observe(raw, corr(raw), Some(0));
            raw += MIN;
        }
    }

    #[test]
    fn the_boot_step_is_left_out() {
        let mut l = Ledger::default();
        // 300 s off at boot: no baseline yet.
        l.observe(0, BOOT_REAL - 300 * NS_PER_S, Some(300 * NS_PER_S));
        assert!(!l.started());
        // chronyd steps; the next sample is within 1 s.
        l.observe(4 * NS_PER_S, BOOT_REAL, Some(200 * NS_PER_MS));
        assert!(l.started());
        assert_eq!(l.steps(), 1);
        assert_eq!(l.hour_ns(), Some(0));
        run(&mut l, 8 * NS_PER_S, 2 * HOUR_NS, |_| BOOT_REAL);
        assert!(!l.breached());
        assert_eq!(l.steps(), 1);
    }

    #[test]
    fn no_baseline_without_a_good_sample_within_one_second() {
        let mut l = Ledger::default();
        l.observe(0, BOOT_REAL, None);
        l.observe(MIN, BOOT_REAL, Some(NS_PER_S));
        assert!(!l.started());
        assert_eq!(l.hour_ns(), None);
        l.observe(2 * MIN, BOOT_REAL, Some(-NS_PER_S + 1));
        assert!(l.started());
    }

    #[test]
    fn hour_window_trips_over_five_seconds() {
        let mut l = Ledger::default();
        run(&mut l, 0, HOUR_NS, |_| BOOT_REAL);
        l.observe(HOUR_NS + MIN, BOOT_REAL + 5 * NS_PER_S, Some(0));
        assert!(!l.breached(), "exactly 5 s");
        assert_eq!(l.steps(), 1);
        l.observe(HOUR_NS + 2 * MIN, BOOT_REAL + 5 * NS_PER_S + 1, Some(0));
        assert!(l.breached());
    }

    #[test]
    fn a_three_second_step_stays_under_the_caps() {
        let mut l = Ledger::default();
        run(&mut l, 0, 30 * MIN, |_| BOOT_REAL);
        run(&mut l, 31 * MIN, 3 * HOUR_NS, |_| BOOT_REAL + 3 * NS_PER_S);
        assert!(!l.breached());
        assert_eq!(l.hour_ns(), Some(0), "two hours later the step has left the hour window");
        assert_eq!(l.day_ns(), Some(3 * NS_PER_S));
    }

    #[test]
    fn day_window_trips_over_ten_seconds_with_every_hour_under_five() {
        // 0.45 s per hour: never near the hour cap, 10 s after 22.2 hours.
        let rate = |raw: i64| (raw as i128 * 450 * NS_PER_MS as i128 / HOUR_NS as i128) as i64;
        let mut l = Ledger::default();
        run(&mut l, 0, 22 * HOUR_NS, |r| BOOT_REAL + rate(r));
        assert!(!l.breached());
        assert!(l.hour_ns().unwrap() < HOUR_CAP_NS);
        run(&mut l, 22 * HOUR_NS + MIN, 23 * HOUR_NS, |r| BOOT_REAL + rate(r));
        assert!(l.breached());
        assert!(l.day_ns().unwrap() > DAY_CAP_NS);
    }

    #[test]
    fn day_window_forgets_after_25_hours() {
        // Two 4.5 s steps two hours apart (each under the hour cap): the day
        // range holds 9 s while their hours are among the 25 buckets, then
        // drops to 0, and a third step counts on its own.
        let step = 4_500 * NS_PER_MS;
        let mut l = Ledger::default();
        run(&mut l, 0, 30 * MIN, |_| BOOT_REAL);
        run(&mut l, 31 * MIN, 2 * HOUR_NS + 30 * MIN, |_| BOOT_REAL + step);
        run(&mut l, 2 * HOUR_NS + 31 * MIN, 26 * HOUR_NS, |_| BOOT_REAL + 2 * step);
        assert!(!l.breached());
        assert_eq!(l.day_ns(), Some(step), "hour 0 has left the window, hour 2 has not");
        run(&mut l, 26 * HOUR_NS + MIN, 27 * HOUR_NS + 30 * MIN, |_| BOOT_REAL + 2 * step);
        assert_eq!(l.day_ns(), Some(0));
        l.observe(27 * HOUR_NS + 31 * MIN, BOOT_REAL + 3 * step, Some(0));
        assert!(!l.breached());
        assert_eq!(l.day_ns(), Some(step), "4.5 s, not 13.5");
        assert_eq!(l.steps(), 3);
    }

    #[test]
    fn a_return_within_the_hour_window_counts_both_ways() {
        // +4 s, then -8 s three hours later: the range does not care about
        // direction, so the hour window sees 8 s.
        let mut l = Ledger::default();
        run(&mut l, 0, 3 * HOUR_NS, |_| BOOT_REAL);
        l.observe(3 * HOUR_NS + MIN, BOOT_REAL + 4 * NS_PER_S, Some(0));
        run(&mut l, 3 * HOUR_NS + 2 * MIN, 6 * HOUR_NS, |_| BOOT_REAL + 4 * NS_PER_S);
        assert!(!l.breached());
        l.observe(6 * HOUR_NS + MIN, BOOT_REAL - 4 * NS_PER_S, Some(0));
        assert!(l.breached());
        assert_eq!(l.hour_ns(), Some(8 * NS_PER_S));
    }

    #[test]
    fn text_round_trip_and_damage() {
        let mut l = Ledger::default();
        run(&mut l, 0, 3 * HOUR_NS, |r| BOOT_REAL + r / 1_000_000);
        let back = Ledger::from_text(&l.to_text()).unwrap();
        assert_eq!(back.base_raw_ns, l.base_raw_ns);
        assert_eq!(back.buckets, l.buckets);
        assert_eq!(back.steps, l.steps);
        assert_eq!(back.last_corr_ns, l.last_corr_ns);
        assert!(!back.breached);
        for bad in ["", "wappie-clock-ledger v2\n", &l.to_text().replace("breached 0", "breached 2"), &(l.to_text() + "bucket 1 2\n")] {
            assert_eq!(Ledger::from_text(bad), None, "{bad:?}");
        }

        let dir = std::env::temp_dir().join(format!("nsm-timefeed-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(Ledger::load(&dir).unwrap(), Ledger::default());
        l.store(&dir).unwrap();
        let loaded = Ledger::load(&dir).unwrap();
        assert_eq!(loaded.buckets, l.buckets);
        std::fs::write(dir.join(FILE), "garbage").unwrap();
        assert!(Ledger::load(&dir).unwrap().breached(), "a damaged ledger fails closed");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
