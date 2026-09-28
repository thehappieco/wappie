// The sandbox itself (§16.6). media-jail creates a cgroup v2 leaf, forks a child
// into fresh namespaces, builds a minimal read-only root and drops it to a slot
// uid with every capability set empty, under a seccomp allowlist, then execs the
// worker. media-jail keeps ITSELF out of the job cgroup so it can kill the job
// and read memory.events after the job is gone — the child and every
// descendant are the only members of the leaf.
//
// Kernel features are detected, never inferred from a version: the Nitro blob
// kernel is 4.14, a reader kernel of our own would be newer, and the same binary
// runs on both. Each feature 4.14 lacks has a fallback that keeps the §16.6
// property:
//
//   cgroup.kill (5.14)        SIGKILL the child, PID 1 of the job's PID
//                             namespace: the kernel kills every process in it
//   memory.oom.group (4.19)   media-jail kills the job that way on the first
//                             oom_kill in memory.events
//   memory.peak (5.19)        memory.current sampled every 50 ms, plus the
//                             worker's ru_maxrss
//   cgroup2 cpuset (5.0)      sched_setaffinity in the child; the allowlist
//                             never grants it back
//   pivot_root EINVAL         the switch_root pattern (move_root), safe
//                             because the worker holds no capability
//
// Ownership of the namespaces: the parent unshares only the PID namespace
// (deferred: it does not move the parent, only makes the forked child PID 1),
// so the parent keeps the host mount namespace and can drive cgroupfs by path
// throughout. The child unshares mount/net/ipc/uts for itself, so its root
// switch and mounts never disturb the parent. This is the one deviation from
// annex §16.6 step 1 (where the main Node would hold cgroup.kill); giving
// media-jail the wall enforcement is what the A0 task asks for.

use crate::args::{cpu_list, Config, Slot};
use crate::emulate::Emulate;
use crate::json::Val;
use crate::seccomp::KillAction;
use crate::{profile, seccomp};
use seccompiler::BpfProgram;
use std::ffi::{c_void, CString};
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

const CGROUP_BASE: &str = "/run/cg2/media";

/// How long a killed job has to disappear after cgroup.kill before media-jail
/// SIGKILLs its PID 1, and again after that before media-jail gives up on it.
const KILL_GRACE: Duration = Duration::from_secs(2);

fn last() -> io::Error {
    io::Error::last_os_error()
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("path contains an interior NUL")
}

fn do_mount(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let s = cstr(src);
    let t = cstr(target);
    let f = cstr(fstype);
    let d = data.map(cstr);
    let dptr = d.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null());
    let fptr = if fstype.is_empty() { std::ptr::null() } else { f.as_ptr() };
    let r = unsafe { libc::mount(s.as_ptr(), t.as_ptr(), fptr, flags, dptr as *const c_void) };
    if r != 0 {
        return Err(format!("mount {src} -> {target} ({fstype}): {}", last()));
    }
    Ok(())
}

fn pivot_root(new_root: &str, put_old: &str) -> io::Result<()> {
    let n = cstr(new_root);
    let o = cstr(put_old);
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) };
    if r != 0 {
        return Err(last());
    }
    Ok(())
}

fn chdir(path: &str) -> Result<(), String> {
    if unsafe { libc::chdir(cstr(path).as_ptr()) } != 0 {
        return Err(format!("chdir {path}: {}", last()));
    }
    Ok(())
}

/// Lazily detach the mount at `path` (and everything under it).
fn detach(path: &str) -> io::Result<()> {
    if unsafe { libc::umount2(cstr(path).as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(last());
    }
    Ok(())
}

fn mkdir_p(path: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("mkdir -p {path}: {e}"))
}

fn set_rlimit(res: libc::c_int, name: &str, val: u64) -> Result<(), String> {
    let lim = libc::rlimit {
        rlim_cur: val,
        rlim_max: val,
    };
    let r = unsafe { libc::setrlimit(res, &lim) };
    if r != 0 {
        return Err(format!("setrlimit {name}: {}", last()));
    }
    Ok(())
}

/// Close every fd >= `lo`, so the worker inherits only stdio. close_range needs
/// 5.9; before that (the 4.14 blob) the open fds are listed from /proc/self/fd —
/// the jail's own /proc is mounted by then — and closed one by one, with a
/// sweep up to the fd limit as the last resort.
fn close_from(lo: libc::c_uint) {
    let r = unsafe { libc::syscall(libc::SYS_close_range, lo, libc::c_uint::MAX, 0) };
    if r == 0 {
        return;
    }
    let listed: Option<Vec<libc::c_int>> = fs::read_dir("/proc/self/fd").ok().map(|dir| {
        dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect()
    });
    match listed {
        // The listing's own fd is already closed again; closing it is a no-op.
        Some(fds) => {
            for fd in fds.into_iter().filter(|&fd| fd >= lo as libc::c_int) {
                unsafe { libc::close(fd) };
            }
        }
        None => {
            let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
            let max = if max < 0 { 1024 } else { max as libc::c_int };
            for fd in lo as libc::c_int..max {
                unsafe { libc::close(fd) };
            }
        }
    }
}

// ---- cgroup (parent side, host mount namespace, plain paths) ----------------

/// The job's leaf and what its kernel offers there. An interface file exists
/// only if the kernel has the feature and the controller is enabled above the
/// leaf, so each optional one is detected by its presence.
struct Leaf {
    path: String,
    /// What memory.swap.max holds: "0", or "absent-no-swap" on a kernel
    /// without swap accounting and without swap.
    swap_max: &'static str,
    /// memory.oom.group=1 was written (4.19): the kernel's OOM kill takes the
    /// whole job. Without it media-jail does, on the first oom_kill event.
    oom_group: bool,
    /// cpuset.cpus was written (cgroup2 cpuset, 5.0). Without it the child
    /// pins itself with sched_setaffinity.
    cpuset: bool,
    /// cgroup.kill exists (5.14).
    kill_file: bool,
    /// memory.peak exists (5.19).
    peak_file: bool,
}

fn write_cg(leaf: &str, file: &str, value: &str) -> Result<(), String> {
    let path = format!("{leaf}/{file}");
    fs::write(&path, value).map_err(|e| format!("write {path} = {value:?}: {e}"))
}

/// True when the leaf has `file` and it is not emulated away.
fn has_cg(leaf: &str, file: &str, emulated_absent: bool) -> bool {
    !emulated_absent && Path::new(&format!("{leaf}/{file}")).exists()
}

/// Write an optional interface file: Ok(false) when the kernel lacks it, an
/// error when it exists but refuses the value.
fn write_optional_cg(
    leaf: &str,
    file: &str,
    value: &str,
    emulated_absent: bool,
) -> Result<bool, String> {
    if !has_cg(leaf, file, emulated_absent) {
        return Ok(false);
    }
    write_cg(leaf, file, value).map(|()| true)
}

/// True when the kernel has no swap device (or no swap support: no
/// /proc/swaps), so a missing memory.swap.max leaves nothing to bound.
fn no_swap_devices() -> bool {
    fs::read_to_string("/proc/swaps")
        .map(|t| t.lines().count() <= 1)
        .unwrap_or(true)
}

/// Create the job's leaf and write its caps. The leaf is removed again on any
/// error.
fn create_cgroup(cfg: &Config, emu: &Emulate) -> Result<Leaf, String> {
    if !Path::new(CGROUP_BASE).is_dir() {
        return Err(format!(
            "{CGROUP_BASE} is absent; cgroup2 must be mounted at /run/cg2 with \
             memory and pids enabled (see deploy/enclave/probe/entrypoint-probe.sh, §16.6)"
        ));
    }
    let leaf = format!("{CGROUP_BASE}/{}-{}", cfg.slot.name(), cfg.id);
    match fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(format!("cgroup leaf {leaf} already exists (stale or colliding --id)"));
        }
        Err(e) => return Err(format!("mkdir {leaf}: {e}")),
    }
    match write_caps(cfg, &leaf, emu) {
        Ok(l) => Ok(l),
        Err(e) => {
            let _ = fs::remove_dir(&leaf);
            Err(e)
        }
    }
}

fn write_caps(cfg: &Config, leaf: &str, emu: &Emulate) -> Result<Leaf, String> {
    // Order: caps first, then the process joins (done by the parent after fork).
    // memory.max and pids.max are the bounds every supported kernel has; a
    // leaf without them is an error, never a silently unbounded job.
    write_cg(leaf, "memory.max", &cfg.mem_bytes.to_string())?;
    // memory.swap.max exists only with swap accounting (CONFIG_SWAP and, before
    // 6.1, CONFIG_MEMCG_SWAP; not with swapaccount=0). Its absence is tolerated
    // only when no swap device exists either, so the job still cannot swap. It
    // is detected by presence like the other optional files, not by the write
    // error: cgroupfs answers a write to a missing file with EACCES, not ENOENT.
    let swap_max = if has_cg(leaf, "memory.swap.max", emu.no_swap_max) {
        write_cg(leaf, "memory.swap.max", "0")?;
        "0"
    } else if no_swap_devices() {
        "absent-no-swap"
    } else {
        return Err(format!(
            "{leaf}/memory.swap.max is absent but /proc/swaps lists a swap device"
        ));
    };
    let oom_group = write_optional_cg(leaf, "memory.oom.group", "1", emu.no_oom_group)?;
    write_cg(leaf, "pids.max", &cfg.pids_max.to_string())?;
    let cpuset = write_optional_cg(leaf, "cpuset.cpus", &cfg.cpus, emu.no_cpuset)?;
    Ok(Leaf {
        path: leaf.to_string(),
        swap_max,
        oom_group,
        cpuset,
        kill_file: has_cg(leaf, "cgroup.kill", emu.no_cgroup_kill),
        peak_file: has_cg(leaf, "memory.peak", emu.no_peak),
    })
}

fn read_events(leaf: &str) -> (u64, u64) {
    let mut oom_kill = 0;
    let mut oom_group_kill = 0;
    if let Ok(text) = fs::read_to_string(format!("{leaf}/memory.events")) {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next()) {
                (Some("oom_kill"), Some(n)) => oom_kill = n.parse().unwrap_or(0),
                (Some("oom_group_kill"), Some(n)) => oom_group_kill = n.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    (oom_kill, oom_group_kill)
}

/// A single-number cgroup file (memory.peak, memory.current), or None if the
/// kernel lacks it.
fn read_u64(leaf: &str, file: &str) -> Option<u64> {
    fs::read_to_string(format!("{leaf}/{file}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Poll for the child's exit for up to `grace`. True once it is reaped; its
/// wait status and resource usage are then in `status` and `usage`.
fn reap_within(
    pid: libc::pid_t,
    status: &mut libc::c_int,
    usage: &mut libc::rusage,
    grace: Duration,
) -> bool {
    let start = Instant::now();
    loop {
        let r = unsafe { libc::wait4(pid, status, libc::WNOHANG, usage) };
        if r == pid {
            return true;
        }
        if r < 0 && last().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
        if start.elapsed() >= grace {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Kill the job and reap the child, never blocking on a job that will not die.
/// cgroup.kill first (every process in the leaf) where the kernel has it; then,
/// or instead, SIGKILL the child: it is PID 1 of the job's PID namespace, so the
/// kernel kills every other process in it, and no job process can leave that
/// namespace (no setns, unshare or CLONE_NEWPID in the allowlist). Returns how
/// it was killed ("cgroup.kill", "cgroup.kill+pid1" or "pid1") and whether the
/// child was reaped.
fn kill_job(
    leaf: &Leaf,
    pid: libc::pid_t,
    status: &mut libc::c_int,
    usage: &mut libc::rusage,
) -> (&'static str, bool) {
    let via_cgroup = leaf.kill_file && fs::write(format!("{}/cgroup.kill", leaf.path), "1").is_ok();
    if via_cgroup && reap_within(pid, status, usage, KILL_GRACE) {
        return ("cgroup.kill", true);
    }
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let reaped = reap_within(pid, status, usage, KILL_GRACE);
    (if via_cgroup { "cgroup.kill+pid1" } else { "pid1" }, reaped)
}

/// Bind `src` read-only at the same path under `root`. Deliberately without
/// MS_REC: the kernel applies a read-only bind remount to one mount only, so a
/// submount carried in recursively would stay writable. A path the image lacks
/// is skipped.
fn bind_ro(root: &str, src: &str) -> Result<(), String> {
    let meta = match fs::metadata(src) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("stat {src}: {e}")),
    };
    let dst = format!("{root}{src}");
    if meta.is_dir() {
        mkdir_p(&dst)?;
    } else {
        if let Some(parent) = Path::new(&dst).parent() {
            mkdir_p(&parent.to_string_lossy())?;
        }
        fs::write(&dst, b"").map_err(|e| format!("touch {dst}: {e}"))?;
    }
    do_mount(src, &dst, "", libc::MS_BIND as libc::c_ulong, None)?;
    do_mount(
        "",
        &dst,
        "",
        (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV)
            as libc::c_ulong,
        None,
    )
}

// ---- the root switch --------------------------------------------------------

/// How the child entered its new root; the status line reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootSwitch {
    PivotRoot,
    MoveChroot,
}

impl RootSwitch {
    fn name(self) -> &'static str {
        match self {
            RootSwitch::PivotRoot => "pivot_root",
            RootSwitch::MoveChroot => "move+chroot",
        }
    }
}

/// Undo mountinfo's octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash) in a mount point.
fn unescape_mount(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c));
        if b[i] == b'\\' && octal {
            let digit = |k: usize| (b[i + k] - b'0') as u32;
            out.push((digit(1) * 64 + digit(2) * 8 + digit(3)) as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mount points of a /proc/self/mountinfo text (field 5) that lie outside
/// `root` and are not "/" itself, deepest first so each can be detached before
/// the mount it sits on.
fn mounts_outside(mountinfo: &str, root: &str) -> Vec<String> {
    let inside = format!("{root}/");
    let mut points: Vec<String> = mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(unescape_mount)
        .filter(|p| p != "/" && p != root && !p.starts_with(&inside))
        .collect();
    points.sort_by(|a, b| {
        let depth = |p: &str| p.matches('/').count();
        depth(b).cmp(&depth(a)).then_with(|| b.cmp(a))
    });
    points.dedup();
    points
}

/// Enter the new root with nothing else reachable. pivot_root is the §16.6
/// path. The kernel refuses it with EINVAL when the current root cannot be
/// pivoted — it is the initramfs itself (rootfs has no parent mount) or not a
/// mount root at all — and then the switch_root pattern (move_root) does the
/// same job.
fn enter_root(root: &str, emu: &Emulate) -> Result<RootSwitch, String> {
    let put_old = format!("{root}/oldroot");
    mkdir_p(&put_old)?;
    let pivoted = if emu.no_pivot_root {
        Err(io::Error::from_raw_os_error(libc::EINVAL))
    } else {
        pivot_root(root, &put_old)
    };
    let how = match pivoted {
        Ok(()) => {
            chdir("/")?;
            detach("/oldroot").map_err(|e| format!("umount2 /oldroot: {e}"))?;
            RootSwitch::PivotRoot
        }
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            move_root(root).map_err(|m| format!("pivot_root({root}): {e}; move+chroot: {m}"))?;
            RootSwitch::MoveChroot
        }
        Err(e) => return Err(format!("pivot_root({root}, {put_old}): {e}")),
    };
    let _ = unsafe { libc::rmdir(cstr("/oldroot").as_ptr()) };
    Ok(how)
}

/// The switch_root pattern, for a root pivot_root refuses: move the new root
/// over "/" and chroot into it, after lazily detaching every other mount of
/// this private namespace, so the old root keeps nothing mounted on it. The
/// old root's own filesystem (the initramfs) stays under the new root — it is
/// the namespace root and cannot be unmounted — but nothing can reach it:
///
/// - the worker holds no capability (clear_capabilities, then the uid drop,
///   checked by verify_no_capabilities), so no chroot-and-chdir("..") walk back
///   out, no mount and no pivot_root;
/// - the allowlist never grants chroot, mount, umount2, pivot_root, unshare,
///   setns or a namespace-creating clone (profile.rs RESERVED), and the kernel
///   refuses a user namespace to a chrooted process (create_user_ns);
/// - the worker has no fd or cwd outside the new root (close_from, chdir "/"),
///   and its fresh /proc shows only its own PID namespace.
fn move_root(root: &str) -> Result<(), String> {
    let mountinfo =
        fs::read_to_string("/proc/self/mountinfo").map_err(|e| format!("read mountinfo: {e}"))?;
    let others = mounts_outside(&mountinfo, root);
    chdir(root)?;
    do_mount(".", "/", "", libc::MS_MOVE as libc::c_ulong, None)?;
    // The process root is still the old one, so absolute paths still resolve
    // there (a lookup does not descend into the mount now on "/"): detach what
    // was mounted on it. EINVAL: already gone with a detached parent; ENOENT:
    // its path went with one.
    for point in &others {
        if let Err(e) = detach(point) {
            if !matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT)) {
                return Err(format!("umount2 {point}: {e}"));
            }
        }
    }
    if unsafe { libc::chroot(cstr(".").as_ptr()) } != 0 {
        return Err(format!("chroot .: {}", last()));
    }
    chdir("/")
}

// ---- capabilities -----------------------------------------------------------

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// _LINUX_CAPABILITY_VERSION_3: two CapData words, capabilities 0-63.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn capget() -> Result<[CapData; 2], String> {
    let mut hdr = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) } != 0 {
        return Err(format!("capget: {}", last()));
    }
    Ok(data)
}

fn capset(data: &[CapData; 2]) -> Result<(), String> {
    let mut hdr = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    if unsafe { libc::syscall(libc::SYS_capset, &mut hdr, data.as_ptr()) } != 0 {
        return Err(format!("capset: {}", last()));
    }
    Ok(())
}

fn prctl2(option: libc::c_int, arg: libc::c_ulong) -> libc::c_int {
    unsafe { libc::prctl(option, arg, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) }
}

fn prctl3(option: libc::c_int, arg2: libc::c_ulong, arg3: libc::c_ulong) -> libc::c_int {
    unsafe { libc::prctl(option, arg2, arg3, 0 as libc::c_ulong, 0 as libc::c_ulong) }
}

/// Empty the capability sets the uid drop leaves alone, while still root
/// (dropping from the bounding set needs CAP_SETPCAP): the bounding set, so no
/// exec can ever grant one back; the ambient set (4.3+; EINVAL before that,
/// when there is none); and the inheritable set. setresuid to a non-zero uid
/// then clears permitted and effective (SECBIT_KEEP_CAPS is never set).
fn clear_capabilities() -> Result<(), String> {
    // PR_CAPBSET_READ answers EINVAL past the kernel's last capability.
    for cap in 0..64 {
        match prctl2(libc::PR_CAPBSET_READ, cap) {
            r if r < 0 => break,
            1 => {
                if prctl2(libc::PR_CAPBSET_DROP, cap) != 0 {
                    return Err(format!("drop capability {cap} from the bounding set: {}", last()));
                }
            }
            _ => {}
        }
    }
    if prctl3(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0) != 0
        && last().raw_os_error() != Some(libc::EINVAL)
    {
        return Err(format!("clear the ambient capabilities: {}", last()));
    }
    let mut data = capget()?;
    for d in data.iter_mut() {
        d.inheritable = 0;
    }
    capset(&data)
}

/// After the uid drop, every capability set must be empty: permitted,
/// effective and inheritable (capget), bounding and ambient (prctl). Anything
/// else is fatal to the job; the status line reports `caps: cleared` only when
/// this passed.
fn verify_no_capabilities() -> Result<(), String> {
    let data = capget()?;
    if data.iter().any(|d| d.effective | d.permitted | d.inheritable != 0) {
        return Err(format!(
            "capabilities remain after the uid drop: eff {:08x}{:08x} prm {:08x}{:08x} inh {:08x}{:08x}",
            data[1].effective, data[0].effective, data[1].permitted, data[0].permitted,
            data[1].inheritable, data[0].inheritable,
        ));
    }
    for cap in 0..64 {
        match prctl2(libc::PR_CAPBSET_READ, cap) {
            r if r < 0 => break,
            0 => {}
            _ => return Err(format!("capability {cap} is still in the bounding set")),
        }
    }
    for cap in 0..64 {
        match prctl3(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong, cap) {
            r if r < 0 => break,
            0 => {}
            _ => return Err(format!("capability {cap} is still in the ambient set")),
        }
    }
    Ok(())
}

/// Pin the job to its CPU list when its cgroup has no cpuset (cgroup2 cpuset
/// needs 5.0). Threads and children inherit the mask, and the allowlist never
/// grants sched_setaffinity (profile.rs RESERVED), so the worker cannot widen
/// it.
fn pin_cpus(cpus: &[u32]) -> Result<(), String> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &c in cpus {
        unsafe { libc::CPU_SET(c as usize, &mut set) };
    }
    let r = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    if r != 0 {
        return Err(format!("sched_setaffinity({cpus:?}): {}", last()));
    }
    Ok(())
}

// ---- child facts -------------------------------------------------------------

/// What only the child knows, sent to the parent over a close-on-exec pipe just
/// before the exec: how it entered its root, and that its capability sets were
/// verified empty. One line of `key=value` words.
fn send_facts(fd: libc::c_int, how: RootSwitch) {
    let line = format!("root_switch={} caps=cleared\n", how.name());
    unsafe { libc::write(fd, line.as_ptr() as *const c_void, line.len()) };
}

fn parse_facts(text: &str) -> Vec<(String, String)> {
    text.split_whitespace()
        .filter_map(|w| w.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Whatever the child sent, without blocking: by the time the parent reads,
/// the child has exec'd (the write end closed) or is gone.
fn read_facts(fd: libc::c_int) -> String {
    unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..n as usize]).into_owned()
}

// ---- child ------------------------------------------------------------------

/// Everything the child needs, prepared by the parent before the fork.
struct Plan<'a> {
    cfg: &'a Config,
    binds: &'a [&'a str],
    /// The CPU ids to pin with sched_setaffinity, when the leaf has no cpuset.
    pin: Option<Vec<u32>>,
    emu: Emulate,
    allow: &'a BpfProgram,
    shim: &'a BpfProgram,
}

/// Everything the child does after fork, ending in execve. Any error is fatal
/// to the child alone: it prints one line and _exit(127)s.
fn child(plan: &Plan, go_read: libc::c_int, facts: libc::c_int) -> ! {
    match child_inner(plan, go_read, facts) {
        Ok(()) => {
            // child_inner only returns on execve failure, which it reports.
            let _ = writeln!(io::stderr(), "media-jail child: unreachable");
            unsafe { libc::_exit(127) }
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "media-jail child: {e}");
            unsafe { libc::_exit(127) }
        }
    }
}

fn child_inner(plan: &Plan, go_read: libc::c_int, facts: libc::c_int) -> Result<(), String> {
    let cfg = plan.cfg;

    // 1. Wait until the parent has moved us into the job cgroup, so every page
    //    we and the worker touch is charged to the memcg.
    let mut b = [0u8; 1];
    let n = unsafe { libc::read(go_read, b.as_mut_ptr() as *mut c_void, 1) };
    if n != 1 {
        return Err("parent closed the sync pipe before releasing the child".into());
    }
    unsafe { libc::close(go_read) };

    // 2. Our own mount/net/ipc/uts namespaces (PID came from the parent).
    let flags = libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(format!("unshare(mount,net,ipc,uts): {}", last()));
    }
    // A stable, meaningless hostname; no uts leak of the parent's.
    let host = b"jail\0";
    unsafe { libc::sethostname(host.as_ptr() as *const libc::c_char, 4) };

    // 3. Private propagation, then build the new root on a tiny tmpfs.
    do_mount("none", "/", "", (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong, None)?;
    let root = "/run/media-jail-root";
    mkdir_p(root)?;
    do_mount(
        "tmpfs",
        root,
        "tmpfs",
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        Some("mode=0555,size=1m,nr_inodes=4096"),
    )?;

    // Read-only binds of only what the profile's worker needs (profile.rs):
    // the runtime, its libraries and the worker tree. No /etc (so /etc/hosts
    // is unreachable), no /run, no /sys, no /dev/nsm.
    for src in plan.binds {
        bind_ro(root, src)?;
    }

    // A writable /tmp with its own size cap, charged to the job memcg.
    let tmp = format!("{root}/tmp");
    mkdir_p(&tmp)?;
    do_mount(
        "tmpfs",
        &tmp,
        "tmpfs",
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        Some(&format!("mode=1777,size={},nr_inodes=65536", cfg.tmp_bytes)),
    )?;

    // A minimal /dev: only null, zero and urandom (§16.6 step 3).
    let dev = format!("{root}/dev");
    mkdir_p(&dev)?;
    do_mount(
        "tmpfs",
        &dev,
        "tmpfs",
        libc::MS_NOSUID as libc::c_ulong,
        Some("mode=0755,size=64k,nr_inodes=64"),
    )?;
    for node in ["null", "zero", "urandom"] {
        let src = format!("/dev/{node}");
        if Path::new(&src).exists() {
            let dst = format!("{dev}/{node}");
            fs::write(&dst, b"").map_err(|e| format!("touch {dst}: {e}"))?;
            do_mount(&src, &dst, "", libc::MS_BIND as libc::c_ulong, None)?;
        }
    }

    mkdir_p(&format!("{root}/proc"))?;

    // 4. Enter the new root with the old one detached, and give the new PID
    //    namespace its own /proc (never the host's: a fresh instance shows
    //    only this job, whatever hidepid the host /proc has).
    let how = enter_root(root, &plan.emu)?;
    do_mount(
        "proc",
        "/proc",
        "proc",
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        None,
    )?;
    // The root tmpfs and /dev are fully populated; only /tmp stays writable.
    do_mount(
        "",
        "/",
        "",
        (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV)
            as libc::c_ulong,
        None,
    )?;
    do_mount(
        "",
        "/dev",
        "",
        (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID) as libc::c_ulong,
        None,
    )?;

    // 5. Sacrifice this subtree first if memory runs out; be nice to the rest;
    //    stay on the job's CPUs when the cgroup cannot hold them.
    fs::write("/proc/self/oom_score_adj", b"1000\n")
        .map_err(|e| format!("oom_score_adj: {e}"))?;
    let nice = match cfg.slot {
        Slot::Light => 19,
        Slot::Heavy => 10,
    };
    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
    if let Some(cpus) = &plan.pin {
        pin_cpus(cpus)?;
    }

    // 6. Resource limits. RLIMIT_AS is deliberately unset: V8 reserves large
    //    virtual ranges for WebAssembly, so an address-space cap is useless for
    //    a Node worker; the memcg is the real bound (§16.6 step 4).
    set_rlimit(libc::RLIMIT_NOFILE, "NOFILE", 64)?;
    set_rlimit(libc::RLIMIT_FSIZE, "FSIZE", cfg.tmp_bytes)?;
    set_rlimit(libc::RLIMIT_CORE, "CORE", 0)?;

    // 7. Empty the capability sets, drop to the slot uid/gid, and verify that
    //    root cannot be regained and that no capability is left anywhere.
    clear_capabilities()?;
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(format!("setgroups(0): {}", last()));
    }
    let gid = cfg.slot.gid();
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        return Err(format!("setresgid({gid}): {}", last()));
    }
    let uid = cfg.slot.uid();
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        return Err(format!("setresuid({uid}): {}", last()));
    }
    if unsafe { libc::setuid(0) } == 0 {
        return Err("regained uid 0 after dropping privileges".into());
    }
    verify_no_capabilities()?;

    // 8. No new privileges.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("prctl(NO_NEW_PRIVS): {}", last()));
    }

    // 9. Tell the parent how the root was entered, then the worker's fds
    //    (§16.6 step 7): stdin, stdout, and /dev/null as stderr. media-jail's
    //    stderr carries the parent's status line, so the worker must never be
    //    able to write there. A close-on-exec copy of the real stderr carries
    //    this child's own last errors until execve. close_from also closes the
    //    facts pipe.
    send_facts(facts, how);
    close_from(3);
    let diag = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
    let null = unsafe { libc::open(cstr("/dev/null").as_ptr(), libc::O_WRONLY) };
    if null < 0 {
        return Err(format!("open /dev/null: {}", last()));
    }
    if null != 2 {
        unsafe {
            libc::dup2(null, 2);
            libc::close(null);
        }
    }
    let fail = |msg: String| -> String {
        if diag >= 0 {
            unsafe { libc::dup2(diag, 2) };
        }
        msg
    };

    // 10. The seccomp allowlist. After this only execve runs (the allowlist
    //     permits it, and dup3/write/exit_group for the error path); the shim
    //     is installed first so this very install is still allowed.
    seccomp::apply_programs(plan.allow, plan.shim).map_err(fail)?;

    // 11. execve with a controlled environment (§16.6 step 7).
    let prog = cstr(&cfg.program);
    let mut argv_c: Vec<CString> = Vec::with_capacity(cfg.argv.len() + 1);
    argv_c.push(cstr(&cfg.program));
    for a in &cfg.argv {
        argv_c.push(cstr(a));
    }
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());

    let env: Vec<CString> = [
        "UV_USE_IO_URING=0",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HOME=/tmp",
        "TMPDIR=/tmp",
    ]
    .iter()
    .map(|s| cstr(s))
    .collect();
    let mut env_p: Vec<*const libc::c_char> = env.iter().map(|c| c.as_ptr()).collect();
    env_p.push(std::ptr::null());

    unsafe { libc::execve(prog.as_ptr(), argv_p.as_ptr(), env_p.as_ptr()) };
    let err = last();
    Err(fail(format!("execve {}: {err}", cfg.program)))
}

// ---- parent orchestration ---------------------------------------------------

/// Run one job. Returns the process exit code media-jail itself exits with:
/// the worker's code on a clean exit, 124 on the wall timeout, 137 on an OOM
/// kill, 128+signal on any other signal, 125 when a killed job could not be
/// reaped, 3 on a setup error before the fork.
pub fn run(cfg: Config) -> i32 {
    let emu = match Emulate::from_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 3;
        }
    };
    // Compile the seccomp filters before doing anything irreversible, so a bad
    // profile fails cleanly with exit 3 and no cgroup is left behind.
    let names = match profile::load(&cfg.profile) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 3;
        }
    };
    let binds = match profile::binds(&cfg.profile) {
        Some(b) => b,
        None => {
            eprintln!("media-jail: profile {:?} has no bind list", cfg.profile);
            return 3;
        }
    };
    let kill = if emu.kill_thread { KillAction::Thread } else { seccomp::kill_action() };
    let (allow, shim) = match seccomp::compile(&names, kill) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("media-jail: seccomp: {e}");
            return 3;
        }
    };
    let cpus = match cpu_list(&cfg.cpus) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 3;
        }
    };

    let leaf = match create_cgroup(&cfg, &emu) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 3;
        }
    };
    // From here the cgroup exists; make sure it is removed on every path.
    let plan = Plan {
        cfg: &cfg,
        binds,
        pin: if leaf.cpuset { None } else { Some(cpus) },
        emu,
        allow: &allow,
        shim: &shim,
    };
    let code = run_with_cgroup(&plan, &leaf, kill);
    let _ = fs::remove_dir(&leaf.path);
    code
}

fn run_with_cgroup(plan: &Plan, leaf: &Leaf, kill: KillAction) -> i32 {
    let cfg = plan.cfg;
    // Sync pipe: the parent releases the child once it is in the cgroup. Facts
    // pipe: the child's report of its root switch, closed by the exec.
    let mut fds = [0 as libc::c_int; 4];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0
        || unsafe { libc::pipe2(fds[2..].as_mut_ptr(), libc::O_CLOEXEC) } != 0
    {
        eprintln!("media-jail: pipe2: {}", last());
        return 3;
    }
    let (go_read, go_write, facts_read, facts_write) = (fds[0], fds[1], fds[2], fds[3]);
    let close_all = || unsafe {
        for fd in fds {
            libc::close(fd);
        }
    };

    // The child is PID 1 of a new PID namespace: unshare it in the parent
    // (deferred — the parent stays put), then fork.
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        eprintln!("media-jail: unshare(pid): {}", last());
        close_all();
        return 3;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("media-jail: fork: {}", last());
        close_all();
        return 3;
    }
    if pid == 0 {
        // Child: never touches go_write or the read end of the facts pipe.
        unsafe {
            libc::close(go_write);
            libc::close(facts_read);
        }
        child(plan, go_read, facts_write);
    }

    // Parent.
    unsafe {
        libc::close(go_read);
        libc::close(facts_write);
    }
    let start = Instant::now();
    let mut status: libc::c_int = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };

    // Move the child into the job cgroup, then release it.
    if let Err(e) = fs::write(format!("{}/cgroup.procs", leaf.path), pid.to_string()) {
        eprintln!("media-jail: join {}/cgroup.procs: {e}", leaf.path);
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::close(go_write);
            libc::close(facts_read);
            libc::wait4(pid, &mut status, 0, &mut usage);
        };
        return 3;
    }
    // One byte: "you are in the cgroup, proceed".
    let one = [1u8];
    unsafe { libc::write(go_write, one.as_ptr() as *const c_void, 1) };
    unsafe { libc::close(go_write) };

    // Wait, enforcing the wall timeout and, without memory.oom.group, ending
    // the whole job on its first OOM kill. memory.current is sampled on the
    // way, for kernels without memory.peak.
    let deadline = Duration::from_secs(cfg.wall_s);
    let mut timed_out = false;
    let mut kill_method: Option<&str> = None;
    let mut reaped = true;
    let mut current_max: Option<u64> = None;
    loop {
        let r = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
        if r == pid {
            break;
        }
        if r < 0 {
            if last().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            eprintln!("media-jail: waitpid: {}", last());
            let (method, ok) = kill_job(leaf, pid, &mut status, &mut usage);
            kill_method = Some(method);
            reaped = ok;
            break;
        }
        // r == 0: still running.
        if let Some(c) = read_u64(&leaf.path, "memory.current") {
            current_max = Some(current_max.map_or(c, |m| m.max(c)));
        }
        if !leaf.oom_group && read_events(&leaf.path).0 > 0 {
            // The kernel killed one process of the job; end the rest with it,
            // as memory.oom.group would have.
            let (method, ok) = kill_job(leaf, pid, &mut status, &mut usage);
            kill_method = Some(method);
            reaped = ok;
            break;
        }
        if start.elapsed() >= deadline {
            timed_out = true;
            let (method, ok) = kill_job(leaf, pid, &mut status, &mut usage);
            kill_method = Some(method);
            reaped = ok;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let wall_ms = start.elapsed().as_millis() as i64;
    let (oom_kill, oom_group_kill) = read_events(&leaf.path);
    let peak = if leaf.peak_file { read_u64(&leaf.path, "memory.peak") } else { None };
    let facts = parse_facts(&read_facts(facts_read));
    let fact = |key: &str| {
        facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| Val::s(v.clone()))
            .unwrap_or(Val::Null)
    };

    let exited = libc::WIFEXITED(status);
    let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
    let signaled = libc::WIFSIGNALED(status);
    let term_sig = if signaled { libc::WTERMSIG(status) } else { -1 };

    let (outcome, code): (&str, i32) = if !reaped {
        // status was never filled in; the leaf stays behind (rmdir is EBUSY).
        ("unreaped", 125)
    } else if oom_group_kill > 0 || oom_kill > 0 {
        ("oom", 137)
    } else if timed_out {
        ("timeout", 124)
    } else if signaled {
        ("signaled", 128 + term_sig)
    } else if exited {
        ("exited", exit_code)
    } else {
        ("unknown", 1)
    };

    // One status line on stderr, so it never mixes with worker stdout; the
    // worker's own stderr is /dev/null, so this line cannot be forged. The A0
    // probe records it; production Node reads memory.events itself (§16.10).
    let report = Val::Obj(vec![
        ("tool".into(), Val::s("media-jail")),
        ("id".into(), Val::s(cfg.id.clone())),
        ("slot".into(), Val::s(cfg.slot.name())),
        ("profile".into(), Val::s(cfg.profile.clone())),
        ("outcome".into(), Val::s(outcome)),
        ("exit_code".into(), Val::Int(exit_code as i64)),
        ("term_signal".into(), Val::Int(term_sig as i64)),
        ("timed_out".into(), Val::Bool(timed_out)),
        (
            "kill_method".into(),
            kill_method.map(Val::s).unwrap_or(Val::Null),
        ),
        ("reaped".into(), Val::Bool(reaped)),
        // The child's pid as the kernel logs it (the host PID namespace), to
        // match console lines such as a SIGILL report to this job.
        ("child_pid".into(), Val::Int(pid as i64)),
        ("root_switch".into(), fact("root_switch")),
        ("caps".into(), fact("caps")),
        (
            "cpu_pin".into(),
            Val::s(if leaf.cpuset { "cpuset" } else { "affinity" }),
        ),
        (
            "oom_group".into(),
            Val::s(if leaf.oom_group { "kernel" } else { "media-jail" }),
        ),
        ("seccomp_kill".into(), Val::s(kill.name())),
        (
            "cgroup".into(),
            Val::Obj(vec![
                ("version".into(), Val::s("v2")),
                ("cgroup.kill".into(), Val::Bool(leaf.kill_file)),
                ("memory.oom.group".into(), Val::Bool(leaf.oom_group)),
                ("memory.peak".into(), Val::Bool(leaf.peak_file)),
                ("cpuset.cpus".into(), Val::Bool(leaf.cpuset)),
            ]),
        ),
        ("swap_max".into(), Val::s(leaf.swap_max)),
        (
            "memory_events".into(),
            Val::Obj(vec![
                ("oom_kill".into(), Val::Int(oom_kill as i64)),
                ("oom_group_kill".into(), Val::Int(oom_group_kill as i64)),
            ]),
        ),
        (
            "memory_peak_bytes".into(),
            peak.map(|p| Val::Int(p as i64)).unwrap_or(Val::Null),
        ),
        (
            "memory_current_max_bytes".into(),
            current_max.map(|c| Val::Int(c as i64)).unwrap_or(Val::Null),
        ),
        (
            "ru_maxrss_kb".into(),
            if reaped { Val::Int(usage.ru_maxrss as i64) } else { Val::Null },
        ),
        ("wall_ms".into(), Val::Int(wall_ms)),
        (
            "emulated".into(),
            Val::Arr(plan.emu.names().into_iter().map(Val::s).collect()),
        ),
    ]);
    eprintln!("{}", report.to_string());
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trimmed mountinfo of the Nitro enclave as its init leaves it (a bind of
    // /rootfs moved over "/", then its own mounts), plus the jail's new root.
    const MOUNTINFO: &str = "\
20 1 0:2 /rootfs / rw - rootfs rootfs rw
21 20 0:5 / /dev rw,nosuid,noexec - devtmpfs dev rw
22 20 0:4 / /proc rw,nosuid,nodev,noexec - proc proc rw
23 20 0:17 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,mode=755
24 20 0:18 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw
25 24 0:19 / /sys/fs/cgroup rw - tmpfs cgroup_root rw,mode=755
26 25 0:20 / /sys/fs/cgroup/cpuset rw - cgroup cpuset rw,cpuset
27 23 0:21 / /run/cg2 rw - cgroup2 cgroup2 rw
28 23 0:22 / /run/media-jail-root rw - tmpfs tmpfs rw,size=1024k
29 28 0:2 /rootfs/lib /run/media-jail-root/lib ro - rootfs rootfs rw
30 20 0:23 / /mnt/with\\040space rw - tmpfs tmpfs rw
";

    #[test]
    fn mounts_outside_the_new_root_deepest_first() {
        let got = mounts_outside(MOUNTINFO, "/run/media-jail-root");
        assert_eq!(
            got,
            vec![
                "/sys/fs/cgroup/cpuset",
                "/sys/fs/cgroup",
                "/run/cg2",
                "/mnt/with space",
                "/sys",
                "/run",
                "/proc",
                "/dev",
            ]
        );
        // Never "/" itself, never the new root or anything under it.
        assert!(!got.iter().any(|p| p == "/" || p.starts_with("/run/media-jail-root")));
    }

    #[test]
    fn mountinfo_escapes_are_undone() {
        assert_eq!(unescape_mount("/a\\040b\\011c\\134d"), "/a b\tc\\d");
        assert_eq!(unescape_mount("/plain"), "/plain");
        // A lone backslash that is not an escape stays as it is.
        assert_eq!(unescape_mount("/x\\9"), "/x\\9");
    }

    #[test]
    fn child_facts_round_trip() {
        let facts = parse_facts("root_switch=move+chroot caps=cleared\n");
        assert_eq!(
            facts,
            vec![
                ("root_switch".to_string(), "move+chroot".to_string()),
                ("caps".to_string(), "cleared".to_string()),
            ]
        );
        assert!(parse_facts("").is_empty());
        assert_eq!(RootSwitch::PivotRoot.name(), "pivot_root");
    }
}
