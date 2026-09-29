// media-jail: the sandbox launcher for the enclave's media parsers
// (deploy/enclave, docs/mcp-enclave.md §16.6). It creates a cgroup v2 leaf,
// forks one worker of its compiled-in table into fresh namespaces with a
// minimal read-only root, drops it to the slot uid with no capabilities under
// a seccomp allowlist, and execs it with the wall timeout enforced by
// cgroup.kill (and SIGKILL of the job's PID 1 where the kernel has no
// cgroup.kill, e.g. the 4.14 Nitro blob). See src/jail.rs for the sequence and
// the per-feature fallbacks, src/workers.rs for the table.
//
//   media-jail --worker <image|pdf|office> --slot light --id <16 hex> \
//              --mem-mb N --pids N --cpus LIST --wall-s N --tmp-mb N
//   media-jail --self-check
//   media-jail --table
//
// Exit codes: 0 and 2 the worker's (done, refused); 1 and 4-123 the worker's
// own non-zero exit; 3 a bad invocation, an unknown worker, a value above the
// row's ceiling or a setup error before the fork; 124 wall timeout; 125 a
// killed job that could not be reaped; 127 a child setup error after the fork;
// 137 OOM kill; 143 stopped by SIGTERM, SIGINT or SIGHUP (or the reader
// gone); 128+signal when the worker died of any other signal (159 a seccomp
// kill). --self-check and --table exit 0; --self-check exits 1 when a
// profile does not assemble.

mod args;
mod emulate;
mod jail;
mod json;
mod profile;
mod seccomp;
mod selfcheck;
mod workers;

use std::process::exit;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match args::parse(argv) {
        Ok(args::Parsed::SelfCheck) => exit(selfcheck::run()),
        Ok(args::Parsed::Table) => {
            println!("{}", workers::table());
            exit(0)
        }
        Ok(args::Parsed::Run(cfg)) => exit(jail::run(*cfg)),
        Err(e) => {
            eprintln!("media-jail: {e}\n{}", args::USAGE);
            exit(3);
        }
    }
}
