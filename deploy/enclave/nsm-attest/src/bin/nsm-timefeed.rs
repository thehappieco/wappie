// nsm-timefeed: feeds the Nitro Secure Module's time to chronyd's SOCK
// reference clock and writes <state_dir>/state.json every cycle for the
// reader (src/timefeed/ has the rules and the file formats).
//   nsm-timefeed <chrony_sock> <state_dir>
//   exit 2: no /dev/nsm; exit 3: bad arguments (checked before the device is
//   opened); exit 1: an NSM request hung past the alarm, or a fatal error
//   (such as a state directory it cannot write). Otherwise it never exits;
//   the clock start script runs it in a loop.
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
use nsm_attest::timefeed::sample::{freq_ppm, read_clocks, Attempt};
use nsm_attest::timefeed::sock::Feeder;
use nsm_attest::timefeed::state::{CycleInput, Machine};
use nsm_attest::timefeed::{ALARM_S, BEST_OF, CYCLE_NS, NS_PER_S};
use serde_bytes::ByteBuf;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

const USAGE: &str = "usage: nsm-timefeed <chrony_sock> <state_dir>";
/// sun_path is 108 bytes, with the terminating NUL.
const MAX_SOCK_PATH: usize = 107;

// One line on stderr. The clock start script sends stderr to /dev/null; this
// is for running it by hand.
fn fail(code: i32, reason: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "nsm-timefeed: {reason}");
    exit(code)
}

// SIGALRM while an NSM request hangs: end the helper with exit 1. _exit is
// async-signal-safe.
extern "C" fn on_alarm(_: libc::c_int) {
    // SAFETY: _exit only ends the process.
    unsafe { libc::_exit(1) }
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        // SAFETY: writes at most the remaining bytes of `nonce`.
        let n = unsafe {
            libc::getrandom(nonce[filled..].as_mut_ptr().cast(), nonce.len() - filled, 0)
        };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            fail(1, "getrandom failed");
        }
        filled += n as usize;
    }
    nonce
}

/// One attestation with a fresh nonce, the clocks read on either side, and
/// the alarm around the ioctl.
fn attempt(fd: i32) -> Attempt {
    let nonce = random_nonce();
    let request = Request::Attestation { user_data: None, nonce: Some(ByteBuf::from(nonce.to_vec())), public_key: None };
    let before = read_clocks();
    // SAFETY: alarm only (re)arms this process's timer.
    unsafe { libc::alarm(ALARM_S) };
    let response = nsm_process_request(fd, request);
    unsafe { libc::alarm(0) };
    let after = read_clocks();
    // Response is #[non_exhaustive]: anything but a document is a failure.
    let document = match response {
        Response::Attestation { document } => Some(document),
        _ => None,
    };
    Attempt { before, after, nonce, document }
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        fail(3, USAGE);
    }
    let sock = PathBuf::from(&args[0]);
    let dir = PathBuf::from(&args[1]);
    if !sock.is_absolute() || !dir.is_absolute() {
        fail(3, "both paths must be absolute");
    }
    if sock.as_os_str().len() > MAX_SOCK_PATH {
        fail(3, "chrony_sock: path too long for a unix socket");
    }

    #[cfg(feature = "fake-drift")]
    {
        use nsm_attest::timefeed::{FAKE_DRIFT_MARKER, FAKE_DRIFT_PPM};
        let _ = writeln!(std::io::stderr(), "nsm-timefeed: {FAKE_DRIFT_MARKER}: NSM time scaled by +{FAKE_DRIFT_PPM} ppm");
    }

    // SAFETY: installs a handler that only calls _exit.
    let handler: extern "C" fn(libc::c_int) = on_alarm;
    if unsafe { libc::signal(libc::SIGALRM, handler as libc::sighandler_t) } == libc::SIG_ERR {
        fail(1, "cannot set the SIGALRM handler");
    }

    let fd = nsm_init();
    if fd < 0 {
        fail(2, "cannot open /dev/nsm");
    }
    let feeder = Feeder::new(&sock).unwrap_or_else(|e| fail(1, &format!("socket: {e}")));
    let mut machine =
        Machine::open(&dir, read_clocks().mono_ns).unwrap_or_else(|e| fail(1, &format!("state_dir: {e}")));

    let mut next = read_clocks().mono_ns;
    loop {
        let start = read_clocks();
        let attempts = (0..BEST_OF).map(|_| attempt(fd)).collect();
        let input = CycleInput { start, attempts, freq_ppm: freq_ppm(), end_mono_ns: read_clocks().mono_ns };
        if let Err(e) = machine.cycle(input, &mut |bytes| feeder.send(bytes)) {
            fail(1, &format!("state_dir: {e}"));
        }
        // The next cycle on the CYCLE_NS grid; cycles that overran are skipped.
        next += CYCLE_NS;
        let now = read_clocks().mono_ns;
        while next <= now {
            next += CYCLE_NS;
        }
        let wait = next - now;
        std::thread::sleep(Duration::new((wait / NS_PER_S) as u64, (wait % NS_PER_S) as u32));
    }
}
