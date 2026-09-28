// `media-jail --self-check` prints one JSON object describing what the running
// kernel supports, and runs nothing (no unshare, no mount, no exec). The boot
// check in the reader (§16.6) calls this and requires exit 0; the A0 probe also
// records its output as raw evidence. It never fails hard: a field it cannot
// read is reported as null/false rather than aborting, so the caller sees the
// whole picture.

use crate::emulate::Emulate;
use crate::json::Val;
use crate::seccomp::KillAction;
use crate::{profile, seccomp};
use std::fs;
use std::path::Path;

fn read(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// The controllers a cgroup2 hierarchy advertises, from a `cgroup.controllers`
/// or `cgroup.subtree_control` file (space-separated on one line).
fn controllers(path: &str) -> Val {
    match read(path) {
        Some(text) => Val::Arr(text.split_whitespace().map(Val::s).collect()),
        None => Val::Null,
    }
}

/// True if the named namespace type exists for this process (the kernel was
/// built with it). Reads the symlink under /proc/self/ns.
fn ns_present(name: &str) -> bool {
    fs::read_link(format!("/proc/self/ns/{name}")).is_ok()
}

/// Where cgroup2 is mounted, scanning /proc/self/mountinfo for a `cgroup2` line.
fn cgroup2_mounts() -> Vec<String> {
    let mut mounts = Vec::new();
    if let Some(text) = read("/proc/self/mountinfo") {
        for line in text.lines() {
            // "... - <fstype> <source> <super opts>"; fstype is the field after
            // the " - " separator.
            if let Some((_, after)) = line.split_once(" - ") {
                let mut it = after.split_whitespace();
                if it.next() == Some("cgroup2") {
                    // The mount point is field 5 (index 4) of the pre-" - " part.
                    if let Some(point) = line.split_whitespace().nth(4) {
                        mounts.push(point.to_string());
                    }
                }
            }
        }
    }
    mounts
}

/// Which optional cgroup interface files a job leaf will have, read off the
/// media node (a leaf gets the files of the controllers enabled above it, and
/// cgroup.kill exists in every non-root cgroup on 5.14+). These pick the
/// fallbacks in jail.rs; none of them is required.
fn media_features(emu: &Emulate) -> Val {
    let has = |file: &str, emulated_absent: bool| {
        Val::Bool(!emulated_absent && Path::new(&format!("/run/cg2/media/{file}")).exists())
    };
    Val::Obj(vec![
        ("memory.max".into(), has("memory.max", false)),
        ("pids.max".into(), has("pids.max", false)),
        ("memory.swap.max".into(), has("memory.swap.max", false)),
        ("memory.oom.group".into(), has("memory.oom.group", emu.no_oom_group)),
        ("memory.peak".into(), has("memory.peak", emu.no_peak)),
        ("cgroup.kill".into(), has("cgroup.kill", emu.no_cgroup_kill)),
        ("cpuset.cpus".into(), has("cpuset.cpus", emu.no_cpuset)),
    ])
}

pub fn run() -> i32 {
    let kernel = read("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string());
    let emu = match Emulate::from_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("media-jail: {e}");
            return 1;
        }
    };
    let kill = if emu.kill_thread { KillAction::Thread } else { seccomp::kill_action() };

    // Seccomp: prove the filter for the shipped profile assembles (does not
    // install it). A failure here means the binary could never sandbox.
    let (seccomp_ok, allow_len, shim_len, seccomp_err) = match profile::load("node-worker")
        .and_then(|names| seccomp::compile(&names, kill))
    {
        Ok((allow, shim)) => (true, allow.len() as i64, shim.len() as i64, None),
        Err(e) => (false, 0, 0, Some(e)),
    };

    let cg2 = cgroup2_mounts();
    let unified_at = cg2.first().cloned();
    // The controller files at the primary cgroup2 mount, and at the media tree
    // if the entrypoint already prepared it.
    let (root_controllers, media_subtree) = match &unified_at {
        Some(m) => (
            controllers(&format!("{m}/cgroup.controllers")),
            controllers("/run/cg2/media/cgroup.subtree_control"),
        ),
        None => (Val::Null, controllers("/run/cg2/media/cgroup.subtree_control")),
    };

    let report = Val::Obj(vec![
        ("tool".into(), Val::s("media-jail")),
        ("self_check".into(), Val::Bool(true)),
        ("kernel".into(), kernel.map(Val::Str).unwrap_or(Val::Null)),
        (
            "euid".into(),
            Val::Int(unsafe { libc::geteuid() } as i64),
        ),
        (
            "egid".into(),
            Val::Int(unsafe { libc::getegid() } as i64),
        ),
        (
            "namespaces".into(),
            Val::Obj(
                ["mnt", "pid", "net", "ipc", "uts", "user", "cgroup"]
                    .iter()
                    .map(|n| (n.to_string(), Val::Bool(ns_present(n))))
                    .collect(),
            ),
        ),
        (
            "cgroup2".into(),
            Val::Obj(vec![
                (
                    "mounts".into(),
                    Val::Arr(cg2.iter().map(Val::s).collect()),
                ),
                (
                    "unified_at".into(),
                    unified_at.map(Val::Str).unwrap_or(Val::Null),
                ),
                ("root_controllers".into(), root_controllers),
                ("media_subtree_control".into(), media_subtree),
                (
                    "run_cg2_media_present".into(),
                    Val::Bool(Path::new("/run/cg2/media").is_dir()),
                ),
                ("media_files".into(), media_features(&emu)),
            ]),
        ),
        (
            "seccomp".into(),
            Val::Obj(vec![
                ("compiles".into(), Val::Bool(seccomp_ok)),
                // KILL_PROCESS from 4.14 on, KILL_THREAD before (seccomp.rs).
                ("kill_action".into(), Val::s(kill.name())),
                (
                    "actions_avail".into(),
                    read("/proc/sys/kernel/seccomp/actions_avail")
                        .map(|s| Val::Str(s.trim().to_string()))
                        .unwrap_or(Val::Null),
                ),
                ("allow_filter_insns".into(), Val::Int(allow_len)),
                ("shim_filter_insns".into(), Val::Int(shim_len)),
                (
                    "error".into(),
                    seccomp_err.map(Val::Str).unwrap_or(Val::Null),
                ),
            ]),
        ),
        (
            "dev_nsm".into(),
            Val::Bool(Path::new("/dev/nsm").exists()),
        ),
        (
            "emulated".into(),
            Val::Arr(emu.names().into_iter().map(Val::s).collect()),
        ),
    ]);

    println!("{}", report.to_string());
    // The binary is usable as long as the seccomp assembler works; the kernel
    // facts are advisory and reported either way.
    if seccomp_ok {
        0
    } else {
        1
    }
}
