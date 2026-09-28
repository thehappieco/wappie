// Seccomp profiles are per-workload syscall ALLOWLISTS. Each profile lists only
// the plain syscalls that workload needs; the security-critical rules (the
// argument filters on socket/clone/ioctl/prctl, the io_uring ENOSYS shims, and
// the always-denied set) live in seccomp.rs and hold for every profile, so a
// profile edit can only ever widen the plain set, never reach a reserved call.
//
// The .txt files are compiled in with include_str! so they are measured into
// PCR0 with the binary (§16.6: "compiled into the binary, so they are
// measured"). A0 ships the `node-worker` profile; ffmpeg and whisper are A2.

/// Names seccomp.rs owns through an argument-filtered or ENOSYS rule. A profile
/// that lists one of these is rejected, so the plain allowlist can never grant
/// an unconditional `socket` or `ioctl` that would defeat those filters.
pub const RESERVED: &[&str] = &[
    "socket",
    "socketpair",
    "clone",
    "clone3",
    "ioctl",
    "prctl",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // Never grantable at all (kept out of the allowlist even as plain names).
    "userfaultfd",
    "bpf",
    "perf_event_open",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "keyctl",
    "add_key",
    "request_key",
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "open_by_handle_at",
    "name_to_handle_at",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
];

/// The compiled-in profiles, keyed by --profile name.
pub fn source(name: &str) -> Option<&'static str> {
    match name {
        "node-worker" => Some(include_str!("../profiles/node-worker.txt")),
        _ => None,
    }
}

/// Parse a profile's plain-allowlist text into de-duplicated syscall names,
/// preserving nothing but the names. `#` starts a comment; blank lines are
/// ignored. A reserved name is an error (it belongs to a code-owned rule).
pub fn parse(text: &str) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = match raw.split_once('#') {
            Some((before, _)) => before,
            None => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if line.split_whitespace().count() != 1 {
            return Err(format!("profile line {}: expected one syscall name, got {:?}", n + 1, line));
        }
        if !line.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(format!("profile line {}: {:?} is not a syscall name", n + 1, line));
        }
        if RESERVED.contains(&line) {
            return Err(format!("profile line {}: {:?} is reserved for a code-owned rule", n + 1, line));
        }
        if !names.iter().any(|existing| existing == line) {
            names.push(line.to_string());
        }
    }
    if names.is_empty() {
        return Err("profile has no syscalls".into());
    }
    Ok(names)
}

/// Load and parse a named profile, or explain why it is unknown/invalid.
pub fn load(name: &str) -> Result<Vec<String>, String> {
    let text = source(name).ok_or_else(|| format!("unknown profile {name:?} (A0 ships: node-worker)"))?;
    parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_worker_profile_loads() {
        let names = load("node-worker").unwrap();
        // A representative core syscall Node cannot start without.
        assert!(names.iter().any(|n| n == "futex"));
        assert!(names.iter().any(|n| n == "read"));
        assert!(names.iter().any(|n| n == "write"));
        // No reserved name slipped into the allowlist.
        for name in &names {
            assert!(!RESERVED.contains(&name.as_str()), "{name} is reserved");
        }
    }

    #[test]
    fn unknown_profile() {
        assert!(load("ffmpeg").is_err());
        assert!(load("whisper").is_err());
        assert!(load("nope").is_err());
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let names = parse("# header\n\nread  # inline\nwrite\n\n").unwrap();
        assert_eq!(names, vec!["read", "write"]);
    }

    #[test]
    fn duplicates_collapse() {
        assert_eq!(parse("read\nread\nwrite\n").unwrap(), vec!["read", "write"]);
    }

    #[test]
    fn reserved_name_rejected() {
        assert!(parse("read\nsocket\n").is_err());
        assert!(parse("ptrace\n").is_err());
        assert!(parse("io_uring_setup\n").is_err());
    }

    #[test]
    fn junk_rejected() {
        assert!(parse("read write\n").is_err());
        assert!(parse("read!\n").is_err());
        assert!(parse("# only comments\n").is_err());
    }
}
