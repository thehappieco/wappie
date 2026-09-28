// The sandbox itself (§16.6). media-jail creates a cgroup v2 leaf, forks a child
// into fresh namespaces, builds a minimal read-only root and drops it to a slot
// uid under a seccomp allowlist, then execs the worker. media-jail keeps ITSELF
// out of the job cgroup so it can enforce the wall timeout with cgroup.kill and
// read memory.events / memory.peak after the job is gone — the child and every
// descendant are the only members of the leaf.
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
use crate::seccomp;
use seccompiler::BpfProgram;
use std::ffi::{c_void, CString};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const CGROUP_BASE: &str = "/run/cg2/media";

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

fn create_cgroup(cfg: &Config) -> Result<String, String> {
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
    // Order: caps first, then the process joins (done by the parent after fork).
    write_cg(&leaf, "memory.max", &cfg.mem_bytes.to_string())?;
    write_cg(&leaf, "memory.swap.max", "0")?;
    write_cg(&leaf, "memory.oom.group", "1")?;
    write_cg(&leaf, "pids.max", &cfg.pids_max.to_string())?;
    write_cg(&leaf, "cpuset.cpus", &cfg.cpus)?;
    Ok(leaf)
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

fn read_peak(leaf: &str) -> Option<u64> {
    fs::read_to_string(format!("{leaf}/memory.peak"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

// ---- child ------------------------------------------------------------------

/// Everything the child does after fork, ending in execve. Any error is fatal
/// to the child alone: it prints one line and _exit(127)s.
fn child(cfg: &Config, go_read: libc::c_int, allow: &BpfProgram, shim: &BpfProgram) -> ! {
    match child_inner(cfg, go_read, allow, shim) {
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

    // Read-only binds of only what a worker needs: the runtime, its libraries
    // and the worker/binary trees. No /etc (so /etc/hosts is unreachable), no
    // /run, no /sys, no /dev/nsm.
    for dir in ["/lib", "/lib64", "/usr", "/bin", "/sbin", "/opt"] {
        if Path::new(dir).is_dir() {
            let dst = format!("{root}{dir}");
            mkdir_p(&dst)?;
            do_mount(dir, &dst, "", (libc::MS_BIND | libc::MS_REC) as libc::c_ulong, None)?;
            do_mount(
                "",
                &dst,
                "",
                (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC) as libc::c_ulong,
                None,
            )?;
        }
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

    // A minimal /dev: only the character devices a parser legitimately reads.
    let dev = format!("{root}/dev");
    mkdir_p(&dev)?;
    do_mount(
        "tmpfs",
        &dev,
        "tmpfs",
        libc::MS_NOSUID as libc::c_ulong,
        Some("mode=0755,size=64k,nr_inodes=64"),
    )?;
    for node in ["null", "zero", "full", "urandom", "random", "tty"] {
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

    // 8. No new privileges, then the seccomp allowlist. After this only execve
    //    runs (the allowlist permits it); the shim is installed first so this
    //    very install is still allowed.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("prctl(NO_NEW_PRIVS): {}", last()));
    }
    close_from(3);
    seccomp::apply_programs(allow, shim)?;

    // 9. execve with a controlled environment (§16.6 step 7).
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
    Err(format!("execve {}: {}", cfg.program, last()))
}

// ---- parent orchestration ---------------------------------------------------

/// Run one job. Returns the process exit code media-jail itself exits with:
/// the worker's code on a clean exit, 124 on the wall timeout, 137 on an OOM
/// kill, 128+signal on any other signal, 3 on a setup error before the fork.
pub fn run(cfg: Config) -> i32 {
    // Compile the seccomp filters before doing anything irreversible, so a bad
    // profile fails cleanly with exit 3 and no cgroup is left behind.
    let names = match crate::profile::load(&cfg.profile) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("media-jail: {e}");
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

    let leaf = match create_cgroup(&cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 3;
        }
    };
    // From here the cgroup exists; make sure it is removed on every path.
    let code = run_with_cgroup(&cfg, &leaf, &allow, &shim);
    let _ = fs::remove_dir(&leaf);
    code
}

fn run_with_cgroup(cfg: &Config, leaf: &str, allow: &BpfProgram, shim: &BpfProgram) -> i32 {
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
        child(cfg, go_read, allow, shim);
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

    // Wait, enforcing the wall timeout with cgroup.kill.
    let deadline = Duration::from_secs(cfg.wall_s);
    let mut timed_out = false;
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
            let _ = fs::write(format!("{leaf}/cgroup.kill"), "1");
            unsafe { libc::waitpid(pid, &mut status, 0) };
            break;
        }
        // r == 0: still running.
        if start.elapsed() >= deadline {
            timed_out = true;
            let _ = fs::write(format!("{leaf}/cgroup.kill"), "1");
            unsafe { libc::waitpid(pid, &mut status, 0) };
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let wall_ms = start.elapsed().as_millis() as i64;
    let (oom_kill, oom_group_kill) = read_events(leaf);
    let peak = read_peak(leaf);

    let exited = libc::WIFEXITED(status);
    let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
    let signaled = libc::WIFSIGNALED(status);
    let term_sig = if signaled { libc::WTERMSIG(status) } else { -1 };

    let (outcome, code): (&str, i32) = if oom_group_kill > 0 || oom_kill > 0 {
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

    // One status line on stderr, so it never mixes with worker stdout. The A0
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
        ("wall_ms".into(), Val::Int(wall_ms)),
    ]);
    eprintln!("{}", report.to_string());
    code
}
