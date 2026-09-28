// The sandbox itself (§16.6). media-jail creates a cgroup v2 leaf, forks a child
// into fresh namespaces, builds a minimal read-only root and drops it to a slot
// uid under a seccomp allowlist, then execs the worker. media-jail keeps ITSELF
// out of the job cgroup so it can enforce the wall timeout with cgroup.kill and
// read memory.events / memory.peak after the job is gone — the child and every
// descendant are the only members of the leaf. cgroup.kill is not the only way
// a job dies: if the write fails (a pre-5.14 kernel has no cgroup.kill) or the
// child outlives it, media-jail SIGKILLs the child, PID 1 of the job's PID
// namespace, which takes every other process in that namespace with it.
//
// Ownership of the namespaces: the parent unshares only the PID namespace
// (deferred: it does not move the parent, only makes the forked child PID 1),
// so the parent keeps the host mount namespace and can drive cgroupfs by path
// throughout. The child unshares mount/net/ipc/uts for itself, so its
// pivot_root and mounts never disturb the parent. This is the one deviation
// from annex §16.6 step 1 (where the main Node would hold cgroup.kill); giving
// media-jail the wall enforcement is what the A0 task asks for.

use crate::args::{Config, Slot};
use crate::json::Val;
use crate::{profile, seccomp};
use seccompiler::BpfProgram;
use std::ffi::{c_void, CString};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const CGROUP_BASE: &str = "/run/cg2/media";

/// How long a killed job has to disappear after cgroup.kill before media-jail
/// SIGKILLs its PID 1, and again after that before media-jail gives up on it.
const KILL_GRACE: Duration = Duration::from_secs(2);

fn last() -> std::io::Error {
    std::io::Error::last_os_error()
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

fn pivot_root(new_root: &str, put_old: &str) -> Result<(), String> {
    let n = cstr(new_root);
    let o = cstr(put_old);
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) };
    if r != 0 {
        return Err(format!("pivot_root({new_root}, {put_old}): {}", last()));
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

/// Close every fd >= 3, so the worker inherits only stdio.
fn close_from(lo: libc::c_uint) {
    let r = unsafe { libc::syscall(libc::SYS_close_range, lo, libc::c_uint::MAX, 0) };
    if r != 0 {
        let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        let max = if max < 0 { 1024 } else { max as libc::c_int };
        for fd in lo as libc::c_int..max {
            unsafe { libc::close(fd) };
        }
    }
}

// ---- cgroup (parent side, host mount namespace, plain paths) ----------------

fn write_cg(leaf: &str, file: &str, value: &str) -> Result<(), String> {
    let path = format!("{leaf}/{file}");
    fs::write(&path, value).map_err(|e| format!("write {path} = {value:?}: {e}"))
}

/// True when the kernel has no swap device (or no swap support: no
/// /proc/swaps), so a missing memory.swap.max leaves nothing to bound.
fn no_swap_devices() -> bool {
    fs::read_to_string("/proc/swaps")
        .map(|t| t.lines().count() <= 1)
        .unwrap_or(true)
}

/// Create the job's leaf and write its caps. Returns the leaf path and what
/// memory.swap.max holds ("0", or "absent-no-swap" on a kernel without swap
/// accounting and without swap). The leaf is removed again on any error.
fn create_cgroup(cfg: &Config) -> Result<(String, &'static str), String> {
    if !Path::new(CGROUP_BASE).is_dir() {
        return Err(format!(
            "{CGROUP_BASE} is absent; cgroup2 must be mounted at /run/cg2 with \
             memory/pids/cpuset enabled (see deploy/enclave/probe/entrypoint-probe.sh, §16.6)"
        ));
    }
    let leaf = format!("{CGROUP_BASE}/{}-{}", cfg.slot.name(), cfg.id);
    match fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!("cgroup leaf {leaf} already exists (stale or colliding --id)"));
        }
        Err(e) => return Err(format!("mkdir {leaf}: {e}")),
    }
    match write_caps(cfg, &leaf) {
        Ok(swap_max) => Ok((leaf, swap_max)),
        Err(e) => {
            let _ = fs::remove_dir(&leaf);
            Err(e)
        }
    }
}

fn write_caps(cfg: &Config, leaf: &str) -> Result<&'static str, String> {
    // Order: caps first, then the process joins (done by the parent after fork).
    write_cg(leaf, "memory.max", &cfg.mem_bytes.to_string())?;
    // memory.swap.max exists only with swap accounting (CONFIG_SWAP and, before
    // 6.1, CONFIG_MEMCG_SWAP). Its absence is tolerated only when no swap
    // device exists either, so the job still cannot swap.
    let swap_max = match fs::write(format!("{leaf}/memory.swap.max"), "0") {
        Ok(()) => "0",
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && no_swap_devices() => "absent-no-swap",
        Err(e) => return Err(format!("write {leaf}/memory.swap.max = \"0\": {e}")),
    };
    write_cg(leaf, "memory.oom.group", "1")?;
    write_cg(leaf, "pids.max", &cfg.pids_max.to_string())?;
    write_cg(leaf, "cpuset.cpus", &cfg.cpus)?;
    Ok(swap_max)
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
/// kernel lacks it (memory.peak needs 5.19).
fn read_u64(leaf: &str, file: &str) -> Option<u64> {
    fs::read_to_string(format!("{leaf}/{file}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Poll for the child's exit for up to `grace`. True once it is reaped.
fn reap_within(pid: libc::pid_t, status: &mut libc::c_int, grace: Duration) -> bool {
    let start = Instant::now();
    loop {
        let r = unsafe { libc::waitpid(pid, status, libc::WNOHANG) };
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
/// cgroup.kill first (every process in the leaf); if the write fails or the
/// child is still there after KILL_GRACE, SIGKILL the child itself. Returns how
/// it was killed ("cgroup.kill", "cgroup.kill+pid1" or "pid1") and whether the
/// child was reaped.
fn kill_job(leaf: &str, pid: libc::pid_t, status: &mut libc::c_int) -> (&'static str, bool) {
    let via_cgroup = fs::write(format!("{leaf}/cgroup.kill"), "1").is_ok();
    if via_cgroup && reap_within(pid, status, KILL_GRACE) {
        return ("cgroup.kill", true);
    }
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let reaped = reap_within(pid, status, KILL_GRACE);
    (if via_cgroup { "cgroup.kill+pid1" } else { "pid1" }, reaped)
}

/// Bind `src` read-only at the same path under `root`. Deliberately without
/// MS_REC: the kernel applies a read-only bind remount to one mount only, so a
/// submount carried in recursively would stay writable. A path the image lacks
/// is skipped.
fn bind_ro(root: &str, src: &str) -> Result<(), String> {
    let meta = match fs::metadata(src) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
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

// ---- child ------------------------------------------------------------------

/// Everything the child does after fork, ending in execve. Any error is fatal
/// to the child alone: it prints one line and _exit(127)s.
fn child(
    cfg: &Config,
    binds: &[&str],
    go_read: libc::c_int,
    allow: &BpfProgram,
    shim: &BpfProgram,
) -> ! {
    match child_inner(cfg, binds, go_read, allow, shim) {
        Ok(()) => {
            // child_inner only returns on execve failure, which it reports.
            let _ = writeln!(std::io::stderr(), "media-jail child: unreachable");
            unsafe { libc::_exit(127) }
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "media-jail child: {e}");
            unsafe { libc::_exit(127) }
        }
    }
}

use std::io::Write as _;

fn child_inner(
    cfg: &Config,
    binds: &[&str],
    go_read: libc::c_int,
    allow: &BpfProgram,
    shim: &BpfProgram,
) -> Result<(), String> {
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
    for src in binds {
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
    mkdir_p(&format!("{root}/oldroot"))?;

    // 4. Enter the new root; give the new PID namespace its own /proc; drop the
    //    old root so nothing outside the tree is reachable.
    pivot_root(root, &format!("{root}/oldroot"))?;
    if unsafe { libc::chdir(cstr("/").as_ptr()) } != 0 {
        return Err(format!("chdir /: {}", last()));
    }
    do_mount(
        "proc",
        "/proc",
        "proc",
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        None,
    )?;
    if unsafe { libc::umount2(cstr("/oldroot").as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(format!("umount2 /oldroot: {}", last()));
    }
    let _ = unsafe { libc::rmdir(cstr("/oldroot").as_ptr()) };
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

    // 5. Sacrifice this subtree first if memory runs out; be nice to the rest.
    fs::write("/proc/self/oom_score_adj", b"1000\n")
        .map_err(|e| format!("oom_score_adj: {e}"))?;
    let nice = match cfg.slot {
        Slot::Light => 19,
        Slot::Heavy => 10,
    };
    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };

    // 6. Resource limits. RLIMIT_AS is deliberately unset: V8 reserves large
    //    virtual ranges for WebAssembly, so an address-space cap is useless for
    //    a Node worker; the memcg is the real bound (§16.6 step 4).
    set_rlimit(libc::RLIMIT_NOFILE, "NOFILE", 64)?;
    set_rlimit(libc::RLIMIT_FSIZE, "FSIZE", cfg.tmp_bytes)?;
    set_rlimit(libc::RLIMIT_CORE, "CORE", 0)?;

    // 7. Drop to the slot uid/gid; verify root cannot be regained.
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

    // 8. No new privileges.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("prctl(NO_NEW_PRIVS): {}", last()));
    }

    // 9. The worker's fds (§16.6 step 7): stdin, stdout, and /dev/null as
    //    stderr. media-jail's stderr carries the parent's status line, so the
    //    worker must never be able to write there. A close-on-exec copy of the
    //    real stderr carries this child's own last errors until execve.
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
    seccomp::apply_programs(allow, shim).map_err(fail)?;

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
    let (allow, shim) = match seccomp::compile(&names) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("media-jail: seccomp: {e}");
            return 3;
        }
    };

    let (leaf, swap_max) = match create_cgroup(&cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 3;
        }
    };
    // From here the cgroup exists; make sure it is removed on every path.
    let code = run_with_cgroup(&cfg, binds, &leaf, swap_max, &allow, &shim);
    let _ = fs::remove_dir(&leaf);
    code
}

fn run_with_cgroup(
    cfg: &Config,
    binds: &[&str],
    leaf: &str,
    swap_max: &str,
    allow: &BpfProgram,
    shim: &BpfProgram,
) -> i32 {
    // Sync pipe: the parent releases the child once it is in the cgroup.
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        eprintln!("media-jail: pipe2: {}", last());
        return 3;
    }
    let (go_read, go_write) = (fds[0], fds[1]);

    // The child is PID 1 of a new PID namespace: unshare it in the parent
    // (deferred — the parent stays put), then fork.
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        eprintln!("media-jail: unshare(pid): {}", last());
        unsafe {
            libc::close(go_read);
            libc::close(go_write);
        }
        return 3;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("media-jail: fork: {}", last());
        return 3;
    }
    if pid == 0 {
        // Child: never touches go_write.
        unsafe { libc::close(go_write) };
        child(cfg, binds, go_read, allow, shim);
    }

    // Parent.
    unsafe { libc::close(go_read) };
    let start = Instant::now();

    // Move the child into the job cgroup, then release it.
    if let Err(e) = fs::write(format!("{leaf}/cgroup.procs"), pid.to_string()) {
        eprintln!("media-jail: join {leaf}/cgroup.procs: {e}");
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::close(go_write);
        };
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        return 3;
    }
    // One byte: "you are in the cgroup, proceed".
    let one = [1u8];
    unsafe { libc::write(go_write, one.as_ptr() as *const c_void, 1) };
    unsafe { libc::close(go_write) };

    // Wait, enforcing the wall timeout. memory.current is sampled on the way,
    // for kernels without memory.peak.
    let deadline = Duration::from_secs(cfg.wall_s);
    let mut timed_out = false;
    let mut kill_method: Option<&str> = None;
    let mut reaped = true;
    let mut current_max: Option<u64> = None;
    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            break;
        }
        if r < 0 {
            if last().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            eprintln!("media-jail: waitpid: {}", last());
            let (method, ok) = kill_job(leaf, pid, &mut status);
            kill_method = Some(method);
            reaped = ok;
            break;
        }
        // r == 0: still running.
        if let Some(c) = read_u64(leaf, "memory.current") {
            current_max = Some(current_max.map_or(c, |m| m.max(c)));
        }
        if start.elapsed() >= deadline {
            timed_out = true;
            let (method, ok) = kill_job(leaf, pid, &mut status);
            kill_method = Some(method);
            reaped = ok;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let wall_ms = start.elapsed().as_millis() as i64;
    let (oom_kill, oom_group_kill) = read_events(leaf);
    let peak = read_u64(leaf, "memory.peak");

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
        ("swap_max".into(), Val::s(swap_max)),
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
        ("wall_ms".into(), Val::Int(wall_ms)),
    ]);
    eprintln!("{}", report.to_string());
    code
}
