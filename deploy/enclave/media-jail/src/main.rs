// media-jail: the sandbox launcher for the enclave's media parsers
// (deploy/enclave, docs/mcp-enclave.md §16.6). It creates a cgroup v2 leaf,
// forks a worker into fresh namespaces with a minimal read-only root, drops it
// to a slot uid with no capabilities under a seccomp allowlist, and execs it
// with the wall timeout enforced by cgroup.kill (and SIGKILL of the job's PID 1
// where the kernel has no cgroup.kill, e.g. the 4.14 Nitro blob). See
// src/jail.rs for the sequence, the per-feature fallbacks and the deviation
// from the annex on who holds the timeout.
//
//   media-jail --profile <name> --slot <heavy|light> --mem-mb N --pids N \
//              --cpus LIST --wall-s N [--id STR] [--tmp-mb N] -- <program> [args…]
//   media-jail --self-check
//
// Exit codes: the worker's own on a clean exit; 124 wall timeout; 137 OOM kill;
// 128+signal on any other signal; 125 a killed job that could not be reaped;
// 3 a bad invocation or setup error before the worker starts; 127 a child
// setup error after fork. --self-check exits 0 when the seccomp assembler
// works, 1 otherwise.

mod args;
mod emulate;
mod jail;
mod json;
mod profile;
mod seccomp;
mod selfcheck;

use std::process::exit;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match args::parse(argv) {
        Ok(args::Parsed::SelfCheck) => exit(selfcheck::run()),
        Ok(args::Parsed::Run(cfg)) => exit(jail::run(*cfg)),
        Err(e) => {
            eprintln!("media-jail: {e}\n{}", args::USAGE);
            exit(3);
        }
    }
}
