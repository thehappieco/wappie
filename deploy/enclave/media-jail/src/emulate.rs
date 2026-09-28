// A0 ONLY: make media-jail behave as it would on an older kernel, so the
// fallback paths the Nitro blob kernel (Linux 4.14) needs can be exercised on a
// newer test kernel. MEDIA_JAIL_EMULATE is a comma-separated list of the
// features to treat as missing:
//
//   no-cgroup-kill  no cgroup.kill (5.14): kill the job's PID 1 instead
//   no-oom-group    no memory.oom.group (4.19): media-jail ends the job itself
//                   on the first oom_kill
//   no-peak         no memory.peak (5.19): sampled memory.current only
//   no-cpuset       no cgroup2 cpuset (5.0): sched_setaffinity in the child
//   no-pivot-root   pivot_root refused (EINVAL): the move+chroot root switch
//   kill-thread     no SECCOMP_RET_KILL_PROCESS (4.14): KILL_THREAD default
//
// Every token only takes a kernel feature away, and every fallback keeps the
// §16.6 properties, so the switch can never widen the jail. The status line and
// --self-check list what was emulated. A1 removes this module: the released
// binary detects features only.

pub const ENV: &str = "MEDIA_JAIL_EMULATE";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Emulate {
    pub no_cgroup_kill: bool,
    pub no_oom_group: bool,
    pub no_peak: bool,
    pub no_cpuset: bool,
    pub no_pivot_root: bool,
    pub kill_thread: bool,
}

impl Emulate {
    /// Parse the MEDIA_JAIL_EMULATE list. Unknown tokens are an error, so a
    /// typo cannot silently test the wrong path.
    pub fn parse(text: &str) -> Result<Emulate, String> {
        let mut e = Emulate::default();
        for token in text.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match token {
                "no-cgroup-kill" => e.no_cgroup_kill = true,
                "no-oom-group" => e.no_oom_group = true,
                "no-peak" => e.no_peak = true,
                "no-cpuset" => e.no_cpuset = true,
                "no-pivot-root" => e.no_pivot_root = true,
                "kill-thread" => e.kill_thread = true,
                other => return Err(format!("{ENV}: unknown feature {other:?}")),
            }
        }
        Ok(e)
    }

    /// From the environment; unset or empty means a real run.
    pub fn from_env() -> Result<Emulate, String> {
        match std::env::var(ENV) {
            Ok(v) => Emulate::parse(&v),
            Err(_) => Ok(Emulate::default()),
        }
    }

    /// The emulated features, for the reports.
    pub fn names(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (on, name) in [
            (self.no_cgroup_kill, "no-cgroup-kill"),
            (self.no_oom_group, "no-oom-group"),
            (self.no_peak, "no-peak"),
            (self.no_cpuset, "no-cpuset"),
            (self.no_pivot_root, "no-pivot-root"),
            (self.kill_thread, "kill-thread"),
        ] {
            if on {
                out.push(name);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_a_real_run() {
        assert_eq!(Emulate::parse("").unwrap(), Emulate::default());
        assert!(Emulate::default().names().is_empty());
    }

    #[test]
    fn the_4_14_set_parses_and_round_trips() {
        let all = "no-cgroup-kill,no-oom-group,no-peak,no-cpuset,no-pivot-root,kill-thread";
        let e = Emulate::parse(all).unwrap();
        assert!(e.no_cgroup_kill && e.no_oom_group && e.no_peak);
        assert!(e.no_cpuset && e.no_pivot_root && e.kill_thread);
        assert_eq!(e.names().join(","), all);
    }

    #[test]
    fn unknown_token_is_an_error() {
        assert!(Emulate::parse("no-cgroup-kill,no-seccomp").is_err());
        assert!(Emulate::parse("everything").is_err());
    }
}
