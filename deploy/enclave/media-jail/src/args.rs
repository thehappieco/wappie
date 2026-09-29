// Command line of media-jail (docs/mcp-enclave.md §16.6). Kept pure (no
// syscalls) so the parser is unit tested on any host. The runtime (jail.rs,
// selfcheck.rs) reads a validated Config; a bad invocation exits 3, like
// nsm-attest, before anything is opened.
//
//   media-jail --worker <id> --slot light --id <job> --mem-mb N --pids N \
//              --cpus LIST --wall-s N --tmp-mb N
//   media-jail --self-check
//   media-jail --table
//
// Every limit is required: there is no default that could drop a bound
// silently. The worker names a row of the compiled-in table (workers.rs),
// which fixes the program and its arguments, and every value must be positive
// and at most that row's ceiling. The heavy slot belongs to A2 (transcription,
// deferred) and is refused.

use crate::workers::{self, Worker};
use std::collections::BTreeSet;

pub const USAGE: &str = "usage: media-jail --worker <image|pdf|office> --slot light --id <16 hex> \
--mem-mb N --pids N --cpus LIST --wall-s N --tmp-mb N\n\
       media-jail --self-check\n\
       media-jail --table";

/// Which uid/gid the child drops to. A1 has one slot; the uid stays per slot
/// so a second slot (A2's heavy one) could never read the light slot's jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// the single light slot (images, PDF, office, zip): uid/gid 65533.
    Light,
}

impl Slot {
    pub fn uid(self) -> u32 {
        match self {
            Slot::Light => 65533,
        }
    }
    pub fn gid(self) -> u32 {
        self.uid()
    }
    pub fn name(self) -> &'static str {
        match self {
            Slot::Light => "light",
        }
    }
    pub fn nice(self) -> i32 {
        match self {
            Slot::Light => 19,
        }
    }
}

/// A validated run request. `id` names the cgroup leaf together with the
/// slot; the program and its argv come from the worker's row.
#[derive(Debug)]
pub struct Config {
    pub worker: &'static Worker,
    pub slot: Slot,
    pub id: String,
    pub mem_bytes: u64,
    pub pids_max: u64,
    pub cpus: String,
    pub tmp_bytes: u64,
    pub wall_s: u64,
}

#[derive(Debug)]
pub enum Parsed {
    Run(Box<Config>),
    SelfCheck,
    Table,
}

pub fn parse<I, S>(argv: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = argv.into_iter().map(Into::into).collect();
    match args.as_slice() {
        [one] if one == "--self-check" => return Ok(Parsed::SelfCheck),
        [one] if one == "--table" => return Ok(Parsed::Table),
        _ => {}
    }

    let mut worker: Option<String> = None;
    let mut slot: Option<String> = None;
    let mut id: Option<String> = None;
    let mut mem_mb: Option<u64> = None;
    let mut pids: Option<u64> = None;
    let mut cpus: Option<String> = None;
    let mut wall_s: Option<u64> = None;
    let mut tmp_mb: Option<u64> = None;

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let slot_for = match flag.as_str() {
            "--worker" => &mut worker,
            "--slot" => &mut slot,
            "--id" => &mut id,
            "--cpus" => &mut cpus,
            "--mem-mb" => {
                set_once(&flag, &mut mem_mb, number(&flag, &value)?)?;
                continue;
            }
            "--pids" => {
                set_once(&flag, &mut pids, number(&flag, &value)?)?;
                continue;
            }
            "--wall-s" => {
                set_once(&flag, &mut wall_s, number(&flag, &value)?)?;
                continue;
            }
            "--tmp-mb" => {
                set_once(&flag, &mut tmp_mb, number(&flag, &value)?)?;
                continue;
            }
            other => return Err(format!("unknown argument {other}")),
        };
        set_once(&flag, slot_for, value)?;
    }

    let name = worker.ok_or("--worker is required")?;
    let worker = workers::find(&name).ok_or_else(|| format!("unknown worker {name:?}"))?;
    let slot = match slot.ok_or("--slot is required")?.as_str() {
        "light" => Slot::Light,
        "heavy" => return Err("--slot heavy is A2 (transcription), which is deferred".into()),
        other => return Err(format!("--slot must be light, not {other}")),
    };
    let id = id.ok_or("--id is required")?;
    if id.len() != 16
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("--id must be 16 lowercase hex characters".into());
    }
    let cpus = cpus.ok_or("--cpus is required")?;
    cpu_list(&cpus)?;
    let max = worker.max;
    let mem_mb = within("--mem-mb", mem_mb, max.mem_mb)?;
    let pids = within("--pids", pids, max.pids)?;
    let wall_s = within("--wall-s", wall_s, max.wall_s)?;
    let tmp_mb = within("--tmp-mb", tmp_mb, max.tmp_mb)?;

    Ok(Parsed::Run(Box::new(Config {
        worker,
        slot,
        id,
        mem_bytes: mem_mb * 1024 * 1024,
        pids_max: pids,
        cpus,
        tmp_bytes: tmp_mb * 1024 * 1024,
        wall_s,
    })))
}

fn set_once<T>(flag: &str, slot: &mut Option<T>, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{flag} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

fn number(flag: &str, value: &str) -> Result<u64, String> {
    if value.is_empty() || value.len() > 12 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{flag} must be a decimal integer, not {value:?}"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{flag}: {value:?} is out of range"))
}

/// A required limit, positive and at most the worker's ceiling.
fn within(flag: &str, value: Option<u64>, max: u64) -> Result<u64, String> {
    let v = value.ok_or_else(|| format!("{flag} is required"))?;
    if v == 0 || v > max {
        return Err(format!("{flag} must be between 1 and {max}, not {v}"));
    }
    Ok(v)
}

/// The highest CPU id a `cpu_set_t` holds (CPU_SETSIZE is 1024), so a list the
/// cpuset accepts can also be applied with sched_setaffinity when the kernel
/// has no cgroup2 cpuset.
const MAX_CPU: u32 = 1023;

/// A Linux cpuset list: comma-separated singletons or `a-b` ranges of decimal
/// CPU ids, e.g. `0`, `0-2`, `1,3`, as the ids it names in ascending order.
/// Written verbatim to `cpuset.cpus`, or applied with sched_setaffinity, so it
/// is validated tightly here rather than trusting the caller.
pub fn cpu_list(cpus: &str) -> Result<Vec<u32>, String> {
    if cpus.is_empty() {
        return Err("--cpus must not be empty".into());
    }
    let mut seen = BTreeSet::new();
    for part in cpus.split(',') {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a, b),
            None => (part, part),
        };
        let lo: u32 = lo
            .parse()
            .map_err(|_| format!("--cpus: bad cpu id in {part:?}"))?;
        let hi: u32 = hi
            .parse()
            .map_err(|_| format!("--cpus: bad cpu id in {part:?}"))?;
        if lo > hi {
            return Err(format!("--cpus: reversed range {part:?}"));
        }
        if hi > MAX_CPU {
            return Err(format!("--cpus: cpu {hi} is above {MAX_CPU}"));
        }
        for c in lo..=hi {
            if !seen.insert(c) {
                return Err(format!("--cpus: cpu {c} listed twice"));
            }
        }
    }
    Ok(seen.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "0123456789abcdef";

    fn full(worker: &str) -> Vec<String> {
        [
            "--worker", worker, "--slot", "light", "--id", JOB, "--mem-mb", "256", "--pids", "64",
            "--cpus", "0", "--wall-s", "10", "--tmp-mb", "16",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn with(worker: &str, flag: &str, value: &str) -> Vec<String> {
        let mut a = full(worker);
        let at = a.iter().position(|x| x == flag).unwrap();
        a[at + 1] = value.to_string();
        a
    }

    fn run(args: Vec<String>) -> Result<Config, String> {
        match parse(args)? {
            Parsed::Run(c) => Ok(*c),
            _ => Err("expected a run".into()),
        }
    }

    #[test]
    fn the_reader_invocation() {
        let c = run(full("image")).unwrap();
        assert_eq!(c.worker.id, "image");
        assert_eq!(c.worker.argv.last(), Some(&"/opt/media/worker/image.mjs"));
        assert_eq!(c.slot, Slot::Light);
        assert_eq!(c.slot.uid(), 65533);
        assert_eq!(c.id, JOB);
        assert_eq!(c.mem_bytes, 256 * 1024 * 1024);
        assert_eq!(c.pids_max, 64);
        assert_eq!(c.cpus, "0");
        assert_eq!(c.wall_s, 10);
        assert_eq!(c.tmp_bytes, 16 * 1024 * 1024);
        // Flag order is free.
        let mut reversed = full("pdf");
        reversed.reverse();
        let pairs: Vec<String> = reversed
            .chunks(2)
            .flat_map(|p| [p[1].clone(), p[0].clone()])
            .collect();
        assert_eq!(run(pairs).unwrap().worker.id, "pdf");
    }

    #[test]
    fn self_check_and_table_run_alone() {
        assert!(matches!(
            parse(["--self-check"]).unwrap(),
            Parsed::SelfCheck
        ));
        assert!(matches!(parse(["--table"]).unwrap(), Parsed::Table));
        assert!(parse(["--self-check", "--table"]).is_err());
        assert!(parse(["--table", "x"]).is_err());
        let mut a = full("image");
        a.push("--table".into());
        assert!(run(a).is_err());
    }

    #[test]
    fn no_free_form_program() {
        let mut a = full("image");
        a.extend(["--".to_string(), "/bin/sh".to_string()]);
        assert!(run(a).is_err());
        assert!(run(with("image", "--worker", "/usr/local/bin/node")).is_err());
        assert!(run(with("image", "--worker", "ffmpeg")).is_err());
        assert!(run(with("image", "--worker", "whisper")).is_err());
        let mut profile = full("image");
        profile.extend(["--profile".to_string(), "node-worker".to_string()]);
        assert!(run(profile).is_err());
    }

    #[test]
    fn every_flag_is_required() {
        let base = full("office");
        for k in (0..base.len()).step_by(2) {
            let mut a = base.clone();
            a.drain(k..k + 2);
            assert!(run(a).is_err(), "without {}", base[k]);
        }
    }

    #[test]
    fn values_above_the_row_or_zero_are_refused() {
        assert!(run(with("image", "--mem-mb", "257")).is_err());
        assert!(run(with("pdf", "--mem-mb", "384")).is_ok());
        assert!(run(with("pdf", "--mem-mb", "385")).is_err());
        assert!(run(with("image", "--wall-s", "11")).is_err());
        assert!(run(with("pdf", "--wall-s", "20")).is_ok());
        assert!(run(with("office", "--wall-s", "16")).is_err());
        assert!(run(with("image", "--pids", "65")).is_err());
        assert!(run(with("image", "--tmp-mb", "17")).is_err());
        for flag in ["--mem-mb", "--pids", "--wall-s", "--tmp-mb"] {
            assert!(run(with("image", flag, "0")).is_err(), "{flag} 0");
            assert!(run(with("image", flag, "-1")).is_err(), "{flag} -1");
            assert!(run(with("image", flag, "+5")).is_err(), "{flag} +5");
            assert!(
                run(with("image", flag, "99999999999999999999")).is_err(),
                "{flag} huge"
            );
        }
        assert!(run(with("image", "--mem-mb", "128")).is_ok());
    }

    #[test]
    fn the_heavy_slot_is_deferred() {
        assert!(run(with("image", "--slot", "heavy"))
            .unwrap_err()
            .contains("deferred"));
        assert!(run(with("image", "--slot", "medium")).is_err());
    }

    #[test]
    fn the_job_id_is_16_lowercase_hex() {
        for bad in [
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789ABCDEF",
            "0123456789abcdeg",
            "../../../../etc/x",
            "",
        ] {
            assert!(run(with("image", "--id", bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_flag_twice_or_unknown_is_refused() {
        let mut twice = full("image");
        twice.extend(["--pids".to_string(), "32".to_string()]);
        assert!(run(twice).is_err());
        let mut unknown = full("image");
        unknown.extend(["--frobnicate".to_string(), "x".to_string()]);
        assert!(run(unknown).is_err());
        let mut dangling = full("image");
        dangling.push("--pids".into());
        assert!(run(dangling).is_err());
    }

    #[test]
    fn cpus_validation() {
        assert!(cpu_list("0").is_ok());
        assert!(cpu_list("0-2").is_ok());
        assert!(cpu_list("1,3,5").is_ok());
        assert!(cpu_list("0-1,3").is_ok());
        for bad in ["", "2-0", "0,0", "a", "0-", "-1", "1024", "1020-1024"] {
            assert!(cpu_list(bad).is_err(), "{bad:?}");
        }
        assert_eq!(cpu_list("3,0-1").unwrap(), vec![0, 1, 3]);
        assert!(run(with("image", "--cpus", "0,0")).is_err());
    }
}
