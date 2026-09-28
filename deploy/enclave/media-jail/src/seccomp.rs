// The seccomp allowlist installed just before execve (§16.6 step 6). It is the
// last line of defence: even a fully compromised parser can only make the
// syscalls named here, with the argument filters below.
//
// Two stacked cBPF filters, evaluated together by the kernel (the most
// restrictive action wins):
//
//   ALLOW filter  every profile syscall + the code-owned argument-filtered
//                 calls → Allow; anything else → KILL_PROCESS. This is the
//                 real allowlist. It also *allows* io_uring_*/clone3 so the
//                 shim below can turn them into ENOSYS rather than the kernel
//                 killing them here.
//   SHIM filter   io_uring_setup/enter/register and clone3 → ENOSYS; everything
//                 else → Allow. ERRNO is more restrictive than ALLOW, so these
//                 four resolve to ENOSYS, and libuv/glibc fall back (§16.6:
//                 "io_uring_setup and clone3 return ENOSYS").
//
// Installing the shim first and the allowlist last means the prctl/seccomp
// calls that install the allowlist are still permitted (the shim allows them),
// and nothing runs between installing the allowlist and execve but execve
// itself, which the allowlist grants.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

// CLONE_NEW* bits: a clone/clone3 that sets any of them is a namespace escape
// attempt and is denied; ordinary thread creation sets none of them.
const CLONE_NS_MASK: u64 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWTIME) as u64;

const AF_UNIX: u64 = libc::AF_UNIX as u64;

/// Map an aarch64 syscall name to its number. Explicit rather than table-driven
/// so a reviewer can read exactly what is granted; an unknown name is an error,
/// which makes a typo in a profile a test failure, not a silent kill.
fn number(name: &str) -> Option<i64> {
    let n: libc::c_long = match name {
        // stdio, files, directories
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "readv" => libc::SYS_readv,
        "writev" => libc::SYS_writev,
        "pread64" => libc::SYS_pread64,
        "pwrite64" => libc::SYS_pwrite64,
        "preadv2" => libc::SYS_preadv2,
        "pwritev2" => libc::SYS_pwritev2,
        "close" => libc::SYS_close,
        "close_range" => libc::SYS_close_range,
        "lseek" => libc::SYS_lseek,
        "openat" => libc::SYS_openat,
        "openat2" => libc::SYS_openat2,
        "fstat" => libc::SYS_fstat,
        "newfstatat" => libc::SYS_newfstatat,
        "statx" => libc::SYS_statx,
        "fstatfs" => libc::SYS_fstatfs,
        "statfs" => libc::SYS_statfs,
        "getdents64" => libc::SYS_getdents64,
        "faccessat" => libc::SYS_faccessat,
        "faccessat2" => libc::SYS_faccessat2,
        "readlinkat" => libc::SYS_readlinkat,
        "mkdirat" => libc::SYS_mkdirat,
        "unlinkat" => libc::SYS_unlinkat,
        "renameat2" => libc::SYS_renameat2,
        "symlinkat" => libc::SYS_symlinkat,
        "linkat" => libc::SYS_linkat,
        "ftruncate" => libc::SYS_ftruncate,
        "fallocate" => libc::SYS_fallocate,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "fcntl" => libc::SYS_fcntl,
        "flock" => libc::SYS_flock,
        "dup" => libc::SYS_dup,
        "dup3" => libc::SYS_dup3,
        "pipe2" => libc::SYS_pipe2,
        "getcwd" => libc::SYS_getcwd,
        // memory
        "brk" => libc::SYS_brk,
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "mremap" => libc::SYS_mremap,
        "madvise" => libc::SYS_madvise,
        "mlock" => libc::SYS_mlock,
        "mlock2" => libc::SYS_mlock2,
        "munlock" => libc::SYS_munlock,
        "memfd_create" => libc::SYS_memfd_create,
        // signals
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "rt_sigtimedwait" => libc::SYS_rt_sigtimedwait,
        "rt_sigpending" => libc::SYS_rt_sigpending,
        "rt_sigsuspend" => libc::SYS_rt_sigsuspend,
        "sigaltstack" => libc::SYS_sigaltstack,
        "signalfd4" => libc::SYS_signalfd4,
        "tgkill" => libc::SYS_tgkill,
        "kill" => libc::SYS_kill,
        "restart_syscall" => libc::SYS_restart_syscall,
        // threads, scheduling, futexes
        "futex" => libc::SYS_futex,
        "futex_waitv" => libc::SYS_futex_waitv,
        "set_robust_list" => libc::SYS_set_robust_list,
        "get_robust_list" => libc::SYS_get_robust_list,
        "rseq" => libc::SYS_rseq,
        "set_tid_address" => libc::SYS_set_tid_address,
        "sched_yield" => libc::SYS_sched_yield,
        "sched_getaffinity" => libc::SYS_sched_getaffinity,
        "sched_getparam" => libc::SYS_sched_getparam,
        "sched_getscheduler" => libc::SYS_sched_getscheduler,
        "sched_get_priority_max" => libc::SYS_sched_get_priority_max,
        "sched_get_priority_min" => libc::SYS_sched_get_priority_min,
        "membarrier" => libc::SYS_membarrier,
        "gettid" => libc::SYS_gettid,
        "getpid" => libc::SYS_getpid,
        "getppid" => libc::SYS_getppid,
        // time
        "nanosleep" => libc::SYS_nanosleep,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "clock_gettime" => libc::SYS_clock_gettime,
        "clock_getres" => libc::SYS_clock_getres,
        "gettimeofday" => libc::SYS_gettimeofday,
        "timerfd_create" => libc::SYS_timerfd_create,
        "timerfd_settime" => libc::SYS_timerfd_settime,
        "timerfd_gettime" => libc::SYS_timerfd_gettime,
        // event loop
        "epoll_create1" => libc::SYS_epoll_create1,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "epoll_pwait" => libc::SYS_epoll_pwait,
        "epoll_pwait2" => libc::SYS_epoll_pwait2,
        "eventfd2" => libc::SYS_eventfd2,
        "ppoll" => libc::SYS_ppoll,
        "pselect6" => libc::SYS_pselect6,
        // identity, limits, misc info
        "getuid" => libc::SYS_getuid,
        "geteuid" => libc::SYS_geteuid,
        "getgid" => libc::SYS_getgid,
        "getegid" => libc::SYS_getegid,
        "getgroups" => libc::SYS_getgroups,
        "getrandom" => libc::SYS_getrandom,
        "capget" => libc::SYS_capget,
        "uname" => libc::SYS_uname,
        "sysinfo" => libc::SYS_sysinfo,
        "getrlimit" => libc::SYS_getrlimit,
        "prlimit64" => libc::SYS_prlimit64,
        "getrusage" => libc::SYS_getrusage,
        "getcpu" => libc::SYS_getcpu,
        // already-open socket fds
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "shutdown" => libc::SYS_shutdown,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "getsockopt" => libc::SYS_getsockopt,
        "setsockopt" => libc::SYS_setsockopt,
        // process teardown
        "wait4" => libc::SYS_wait4,
        "waitid" => libc::SYS_waitid,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        // code-owned (argument-filtered or ENOSYS): resolved for the rules below
        "execve" => libc::SYS_execve,
        "execveat" => libc::SYS_execveat,
        "socket" => libc::SYS_socket,
        "socketpair" => libc::SYS_socketpair,
        "clone" => libc::SYS_clone,
        "clone3" => libc::SYS_clone3,
        "ioctl" => libc::SYS_ioctl,
        "prctl" => libc::SYS_prctl,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        _ => return None,
    };
    Some(n as i64)
}

fn num(name: &str) -> Result<i64, String> {
    number(name).ok_or_else(|| format!("no aarch64 syscall number for {name:?}"))
}

fn eq(arg: u8, value: u64) -> Result<SeccompRule, String> {
    let cond = SeccompCondition::new(arg, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, value)
        .map_err(|e| format!("condition: {e}"))?;
    SeccompRule::new(vec![cond]).map_err(|e| format!("rule: {e}"))
}

fn masked_zero(arg: u8, mask: u64) -> Result<SeccompRule, String> {
    let cond = SeccompCondition::new(arg, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(mask), 0)
        .map_err(|e| format!("condition: {e}"))?;
    SeccompRule::new(vec![cond]).map_err(|e| format!("rule: {e}"))
}

/// The argument-filtered rules that every profile carries, keyed by syscall.
/// These are the invariants a profile edit cannot touch.
fn code_owned_rules() -> Result<BTreeMap<i64, Vec<SeccompRule>>, String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // execve/execveat: the launcher's own exec, and nothing more the worker
    // needs — but a worker that re-execs itself is harmless under the same
    // filters, so they are plain allows.
    rules.insert(num("execve")?, vec![]);
    rules.insert(num("execveat")?, vec![]);
    // socket/socketpair only in AF_UNIX: no AF_INET, AF_INET6 or AF_VSOCK, so a
    // parser cannot reach the network or the parent over vsock (§4 JAIL).
    rules.insert(num("socket")?, vec![eq(0, AF_UNIX)?]);
    rules.insert(num("socketpair")?, vec![eq(0, AF_UNIX)?]);
    // clone/clone3 only without a CLONE_NEW* flag: threads yes, new namespaces
    // no. clone3 also gets ENOSYS in the shim, so glibc uses clone here.
    rules.insert(num("clone")?, vec![masked_zero(0, CLONE_NS_MASK)?]);
    rules.insert(num("clone3")?, vec![masked_zero(0, CLONE_NS_MASK)?]);
    // ioctl only for the terminal/fd requests libuv issues; the NSM ioctl is
    // not here, so even if /dev/nsm appeared it could not be driven (§16.6).
    let ioctl_allowed: [u64; 6] = [
        libc::TCGETS as u64,
        libc::TIOCGWINSZ as u64,
        libc::FIONBIO as u64,
        libc::FIONREAD as u64,
        libc::FIOCLEX as u64,
        libc::FIONCLEX as u64,
    ];
    let mut ioctl_rules = Vec::new();
    for req in ioctl_allowed {
        ioctl_rules.push(eq(1, req)?);
    }
    rules.insert(num("ioctl")?, ioctl_rules);
    // prctl only PR_SET_NAME/PR_GET_NAME/PR_SET_VMA (thread names, VMA naming).
    const PR_SET_VMA: u64 = 0x53564d41;
    rules.insert(
        num("prctl")?,
        vec![
            eq(0, libc::PR_SET_NAME as u64)?,
            eq(0, libc::PR_GET_NAME as u64)?,
            eq(0, PR_SET_VMA)?,
        ],
    );
    // io_uring_* are allowed here only so the ALLOW filter does not KILL them;
    // the shim downgrades them to ENOSYS. Without this they would die by signal
    // instead of returning an errno libuv can handle.
    rules.insert(num("io_uring_setup")?, vec![]);
    rules.insert(num("io_uring_enter")?, vec![]);
    rules.insert(num("io_uring_register")?, vec![]);
    Ok(rules)
}

/// Syscalls the shim downgrades to ENOSYS.
fn shim_syscalls() -> Result<Vec<i64>, String> {
    Ok(vec![
        num("io_uring_setup")?,
        num("io_uring_enter")?,
        num("io_uring_register")?,
        num("clone3")?,
    ])
}

/// Compile the (allow, shim) pair for a profile. Pure: no syscalls, so it is
/// unit tested. `apply` installs the result.
pub fn compile(profile_names: &[String]) -> Result<(BpfProgram, BpfProgram), String> {
    // ALLOW filter: profile names (unconditional) + the code-owned rules.
    let mut allow: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in profile_names {
        allow.insert(num(name)?, vec![]);
    }
    for (sysno, rules) in code_owned_rules()? {
        // A profile cannot list a reserved name (profile.rs enforces it), so
        // these keys are always fresh; guard anyway.
        allow.entry(sysno).or_insert(rules);
    }
    let allow_filter = SeccompFilter::new(
        allow,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        TargetArch::aarch64,
    )
    .map_err(|e| format!("allow filter: {e}"))?;

    // SHIM filter: the four ENOSYS calls matched, everything else allowed.
    let mut shim: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for sysno in shim_syscalls()? {
        shim.insert(sysno, vec![]);
    }
    const ENOSYS: u32 = libc::ENOSYS as u32;
    let shim_filter = SeccompFilter::new(
        shim,
        SeccompAction::Allow,
        SeccompAction::Errno(ENOSYS),
        TargetArch::aarch64,
    )
    .map_err(|e| format!("shim filter: {e}"))?;

    let allow_prog: BpfProgram = allow_filter.try_into().map_err(|e| format!("allow compile: {e}"))?;
    let shim_prog: BpfProgram = shim_filter.try_into().map_err(|e| format!("shim compile: {e}"))?;
    Ok((allow_prog, shim_prog))
}

/// Install both filters on the current thread from a profile name (compile +
/// apply in one call). The jail uses `apply_programs` instead so a bad profile
/// fails before the fork; this is the shape the reader's boot check would use.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn apply(profile_names: &[String]) -> Result<(), String> {
    let (allow_prog, shim_prog) = compile(profile_names)?;
    apply_programs(&allow_prog, &shim_prog)
}

/// Install two already-compiled filters (the jail compiles them before the fork
/// so a bad profile fails early, then the child only installs them).
#[cfg(target_os = "linux")]
pub fn apply_programs(allow: &BpfProgram, shim: &BpfProgram) -> Result<(), String> {
    seccompiler::apply_filter(shim).map_err(|e| format!("apply shim: {e}"))?;
    seccompiler::apply_filter(allow).map_err(|e| format!("apply allow: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;

    #[test]
    fn every_profile_name_has_a_number() {
        // A typo in node-worker.txt would surface here, not as a runtime kill.
        for name in profile::load("node-worker").unwrap() {
            assert!(number(&name).is_some(), "no syscall number for {name:?}");
        }
    }

    #[test]
    fn node_worker_compiles_to_two_non_empty_programs() {
        let names = profile::load("node-worker").unwrap();
        let (allow, shim) = compile(&names).unwrap();
        assert!(!allow.is_empty(), "allow program is empty");
        assert!(!shim.is_empty(), "shim program is empty");
    }

    #[test]
    fn code_owned_rules_cover_the_filtered_calls() {
        let rules = code_owned_rules().unwrap();
        for name in ["socket", "socketpair", "clone", "clone3", "ioctl", "prctl", "execve"] {
            assert!(rules.contains_key(&num(name).unwrap()), "missing rule for {name}");
        }
    }

    #[test]
    fn clone_mask_covers_every_new_namespace_bit() {
        // If a new CLONE_NEW* bit were added and left out of the mask, a parser
        // could create that namespace; assert the mask holds the known set.
        for bit in [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWTIME,
        ] {
            assert_eq!(CLONE_NS_MASK & bit as u64, bit as u64);
        }
    }

    #[test]
    fn an_unknown_syscall_name_is_an_error_not_a_number() {
        assert!(number("definitely_not_a_syscall").is_none());
        assert!(compile(&["definitely_not_a_syscall".to_string()]).is_err());
    }
}
