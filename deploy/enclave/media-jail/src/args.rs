// Command line of media-jail. Kept pure (no syscalls) so the parser is unit
// tested on any host. The runtime (jail.rs, selfcheck.rs) reads a validated
// Config; a bad invocation exits 3, like nsm-attest, before anything is opened.
//
//   media-jail --profile <name> --slot <heavy|light> --mem-mb N --pids N \
//              --cpus LIST --wall-s N [--id STR] [--tmp-mb N] -- <program> [args…]
//   media-jail --self-check
//
// There is no free-form default: every numeric bound and the slot are required
// for a real run, so a caller cannot silently drop a limit.

use std::collections::BTreeSet;

pub const USAGE: &str = "usage: media-jail --profile <name> --slot <heavy|light> \
--mem-mb N --pids N --cpus LIST --wall-s N [--id STR] [--tmp-mb N] -- <program> [args…]\n\
       media-jail --self-check";

/// Which uid/gid the child drops to. One per slot, so two concurrent jobs
/// cannot read each other even if a parser escaped its /proc namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// cpuset-wide, heavier caps (native decoders, whisper): uid/gid 65532.
    Heavy,
    /// the single light slot (images, text, office, zip): uid/gid 65533.
    Light,
}

impl Slot {
    pub fn uid(self) -> u32 {
        match self {
            Slot::Heavy => 65532,
            Slot::Light => 65533,
        }
    }
    pub fn gid(self) -> u32 {
        self.uid()
    }
    pub fn name(self) -> &'static str {
        match self {
            Slot::Heavy => "heavy",
            Slot::Light => "light",
        }
    }
}

/// A validated run request. `id` names the cgroup leaf together with the slot,
/// and `program`/`argv` are execve'd after the sandbox is built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub profile: String,
    pub slot: Slot,
    pub id: String,
    pub mem_bytes: u64,
    pub pids_max: u64,
    pub cpus: String,
    pub tmp_bytes: u64,
    pub wall_s: u64,
    pub program: String,
    pub argv: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Run(Box<Config>),
    SelfCheck,
}

/// Default /tmp size when `--tmp-mb` is absent (§16.8: 128 MiB, RLIMIT_FSIZE).
const DEFAULT_TMP_MB: u64 = 128;

pub fn parse<I, S>(argv: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = argv.into_iter().map(Into::into).collect();

    let mut profile: Option<String> = None;
    let mut slot: Option<Slot> = None;
    let mut id: Option<String> = None;
    let mut mem_mb: Option<u64> = None;
    let mut pids_max: Option<u64> = None;
    let mut cpus: Option<String> = None;
    let mut tmp_mb: Option<u64> = None;
    let mut wall_s: Option<u64> = None;
    let mut self_check = false;

    // A single pass: flags are read until `--`, after which everything is the
    // program and its own arguments (so a jailed `media-jail --self-check` is
    // not mistaken for our own self-check). `--self-check` is a flag like any
    // other and only counts before `--`.
    let mut it = args.into_iter();
    let mut program: Option<String> = None;
    let mut child_argv: Vec<String> = Vec::new();
    let mut saw_double_dash = false;
    while let Some(flag) = it.next() {
        if flag == "--" {
            // Everything after `--` is the program and its own arguments.
            saw_double_dash = true;
            program = it.next();
            child_argv.extend(it.by_ref());
            break;
        }
        if flag == "--self-check" {
            self_check = true;
            continue;
        }
        let mut take = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--profile" => profile = Some(take()?),
            "--slot" => {
                slot = Some(match take()?.as_str() {
                    "heavy" => Slot::Heavy,
                    "light" => Slot::Light,
                    other => return Err(format!("--slot must be heavy or light, not {other}")),
                })
            }
            "--id" => id = Some(take()?),
            "--mem-mb" => mem_mb = Some(parse_u64("--mem-mb", &take()?)?),
            "--pids" => pids_max = Some(parse_u64("--pids", &take()?)?),
            "--cpus" => cpus = Some(take()?),
            "--tmp-mb" => tmp_mb = Some(parse_u64("--tmp-mb", &take()?)?),
            "--wall-s" => wall_s = Some(parse_u64("--wall-s", &take()?)?),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    if self_check {
        // --self-check runs alone: no run flags, no program.
        let combined = profile.is_some()
            || slot.is_some()
            || id.is_some()
            || mem_mb.is_some()
            || pids_max.is_some()
            || cpus.is_some()
            || tmp_mb.is_some()
            || wall_s.is_some()
            || saw_double_dash;
        if combined {
            return Err("--self-check takes no other arguments".into());
        }
        return Ok(Parsed::SelfCheck);
    }

    let profile = profile.ok_or("--profile is required")?;
    let slot = slot.ok_or("--slot is required")?;
    let mem_mb = mem_mb.ok_or("--mem-mb is required")?;
    let pids_max = pids_max.ok_or("--pids is required")?;
    let cpus = cpus.ok_or("--cpus is required")?;
    let wall_s = wall_s.ok_or("--wall-s is required")?;
    let program = program.ok_or("missing program after --")?;

    if profile.is_empty() || !profile.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("--profile must be a non-empty [A-Za-z0-9-] name".into());
    }
    validate_cpus(&cpus)?;
    if mem_mb == 0 {
        return Err("--mem-mb must be positive".into());
    }
    if pids_max == 0 {
        return Err("--pids must be positive".into());
    }
    if wall_s == 0 {
        return Err("--wall-s must be positive".into());
    }
    let id = match id {
        Some(id) => {
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err("--id must be a non-empty [A-Za-z0-9-] name".into());
            }
            id
        }
        // A stable-per-process default keeps the leaf name unique without a
        // clock: the caller normally passes --id <job>. The slot already
        // prefixes the leaf, so the default id is just the pid.
        None => std::process::id().to_string(),
    };
    let tmp_mb = tmp_mb.unwrap_or(DEFAULT_TMP_MB);
    if tmp_mb == 0 {
        return Err("--tmp-mb must be positive".into());
    }

    Ok(Parsed::Run(Box::new(Config {
        profile,
        slot,
        id,
        mem_bytes: mem_mb.saturating_mul(1024 * 1024),
        pids_max,
        cpus,
        tmp_bytes: tmp_mb.saturating_mul(1024 * 1024),
        wall_s,
        program,
        argv: child_argv,
    })))
}

fn parse_u64(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a non-negative integer, not {value}"))
}

/// The highest CPU id a `cpu_set_t` holds (CPU_SETSIZE is 1024), so a list the
/// cpuset accepts can also be applied with sched_setaffinity when the kernel
/// has no cgroup2 cpuset.
const MAX_CPU: u32 = 1023;

fn validate_cpus(cpus: &str) -> Result<(), String> {
    cpu_list(cpus).map(|_| ())
}

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
        let lo: u32 = lo.parse().map_err(|_| format!("--cpus: bad cpu id in {part:?}"))?;
        let hi: u32 = hi.parse().map_err(|_| format!("--cpus: bad cpu id in {part:?}"))?;
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

    fn run(args: &[&str]) -> Result<Config, String> {
        match parse(args.iter().copied())? {
            Parsed::Run(c) => Ok(*c),
            Parsed::SelfCheck => Err("expected a run".into()),
        }
    }

    #[test]
    fn full_invocation() {
        let c = run(&[
            "--profile", "node-worker", "--slot", "light", "--mem-mb", "256", "--pids", "64",
            "--cpus", "0", "--wall-s", "10", "--id", "job1", "--", "/usr/local/bin/node", "w.mjs",
        ])
        .unwrap();
        assert_eq!(c.profile, "node-worker");
        assert_eq!(c.slot, Slot::Light);
        assert_eq!(c.slot.uid(), 65533);
        assert_eq!(c.mem_bytes, 256 * 1024 * 1024);
        assert_eq!(c.pids_max, 64);
        assert_eq!(c.cpus, "0");
        assert_eq!(c.tmp_bytes, 128 * 1024 * 1024);
        assert_eq!(c.wall_s, 10);
        assert_eq!(c.id, "job1");
        assert_eq!(c.program, "/usr/local/bin/node");
        assert_eq!(c.argv, vec!["w.mjs"]);
    }

    #[test]
    fn heavy_slot_uid() {
        let c = run(&[
            "--profile", "whisper", "--slot", "heavy", "--mem-mb", "1280", "--pids", "64",
            "--cpus", "0-2", "--wall-s", "60", "--", "/opt/media/bin/whisper-pcm",
        ])
        .unwrap();
        assert_eq!(c.slot.uid(), 65532);
        assert!(c.argv.is_empty());
    }

    #[test]
    fn self_check_alone() {
        assert_eq!(parse(["--self-check"]).unwrap(), Parsed::SelfCheck);
        assert!(parse(["--self-check", "--slot", "light"]).is_err());
    }

    #[test]
    fn self_check_after_double_dash_is_a_program_argument_not_our_flag() {
        // Jailing `media-jail --self-check` must parse as a run of that program,
        // not as our own self-check.
        let c = run(&[
            "--profile", "node-worker", "--slot", "light", "--mem-mb", "128", "--pids", "64",
            "--cpus", "0", "--wall-s", "5", "--", "/usr/local/bin/media-jail", "--self-check",
        ])
        .unwrap();
        assert_eq!(c.program, "/usr/local/bin/media-jail");
        assert_eq!(c.argv, vec!["--self-check"]);
    }

    #[test]
    fn program_args_after_double_dash_are_not_parsed_as_flags() {
        let c = run(&[
            "--profile", "node-worker", "--slot", "light", "--mem-mb", "256", "--pids", "64",
            "--cpus", "0", "--wall-s", "10", "--", "/bin/echo", "--slot", "--mem-mb",
        ])
        .unwrap();
        assert_eq!(c.program, "/bin/echo");
        assert_eq!(c.argv, vec!["--slot", "--mem-mb"]);
    }

    #[test]
    fn missing_required_flags() {
        assert!(run(&["--slot", "light", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        assert!(run(&["--profile", "p", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        assert!(run(&["--profile", "p", "--slot", "light", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        assert!(run(&["--profile", "p", "--slot", "light", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1"]).is_err());
    }

    #[test]
    fn bad_values() {
        let base = ["--profile", "p", "--slot", "light", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"];
        // zero limits
        assert!(run(&["--profile", "p", "--slot", "light", "--mem-mb", "0", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        assert!(run(&["--profile", "p", "--slot", "light", "--mem-mb", "1", "--pids", "0", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        assert!(run(&["--profile", "p", "--slot", "light", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "0", "--", "/bin/true"]).is_err());
        // bad slot
        assert!(run(&["--profile", "p", "--slot", "medium", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        // unknown flag
        let mut with_unknown = vec!["--frobnicate", "x"];
        with_unknown.extend_from_slice(&base);
        assert!(run(&with_unknown).is_err());
    }

    #[test]
    fn cpus_validation() {
        assert!(validate_cpus("0").is_ok());
        assert!(validate_cpus("0-2").is_ok());
        assert!(validate_cpus("1,3,5").is_ok());
        assert!(validate_cpus("0-1,3").is_ok());
        assert!(validate_cpus("").is_err());
        assert!(validate_cpus("2-0").is_err());
        assert!(validate_cpus("0,0").is_err());
        assert!(validate_cpus("a").is_err());
        assert!(validate_cpus("0-").is_err());
        assert!(validate_cpus("-1").is_err());
        assert!(validate_cpus("1024").is_err());
        assert!(validate_cpus("1020-1024").is_err());
    }

    #[test]
    fn cpu_list_expands_ranges_in_order() {
        assert_eq!(cpu_list("0").unwrap(), vec![0]);
        assert_eq!(cpu_list("3,0-1").unwrap(), vec![0, 1, 3]);
        assert_eq!(cpu_list("1023").unwrap(), vec![1023]);
    }

    #[test]
    fn profile_name_charset() {
        assert!(run(&["--profile", "bad name", "--slot", "light", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
        assert!(run(&["--profile", "", "--slot", "light", "--mem-mb", "1", "--pids", "1", "--cpus", "0", "--wall-s", "1", "--", "/bin/true"]).is_err());
    }
}
