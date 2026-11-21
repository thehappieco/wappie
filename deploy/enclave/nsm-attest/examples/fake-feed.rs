// Test only: nsm-timefeed with a fake NSM, for deploy/enclave/chrony/test-chrony.sh.
// It runs nsm-timefeed's own cycle (src/timefeed: the document checks, the
// boot gate, the offset and its sign, the 40-byte sample, the state file) on
// the real clocks. Only the NSM is fake: each document's timestamp is the
// system time plus an offset, in milliseconds, read from a file every cycle,
// so the test can move the "true" time while it runs. Never in the image:
// the Dockerfile copies src/ alone, and cargo builds examples only on request.
//   fake-feed <chrony_sock> <state_dir> <offset_ms_file>
#[path = "../tests/common/mod.rs"]
mod common;

use common::DocSpec;
use nsm_attest::timefeed::sample::{read_clocks, Attempt};
use nsm_attest::timefeed::sock::Feeder;
use nsm_attest::timefeed::state::{CycleInput, Machine};
use nsm_attest::timefeed::{BEST_OF, CYCLE_NS, NS_PER_MS, NS_PER_S};
use std::path::PathBuf;
use std::time::Duration;

/// A request's round trip. A real one takes milliseconds; a zero round trip
/// would make the 2x keep rule a coin toss on scheduling noise.
const FAKE_RTT: Duration = Duration::from_millis(2);

fn main() {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [sock, dir, offset_file] = args.as_slice() else {
        eprintln!("usage: fake-feed <chrony_sock> <state_dir> <offset_ms_file>");
        std::process::exit(3);
    };
    let feeder = Feeder::new(sock).expect("socket");
    let mut machine = Machine::open(dir, read_clocks().mono_ns).expect("state_dir");
    let mut requests: u32 = 0;
    let mut next = read_clocks().mono_ns;
    loop {
        let text = std::fs::read_to_string(offset_file).expect("offset file");
        let offset_ms: i64 = text.trim().parse().expect("offset file holds whole milliseconds");
        let start = read_clocks();
        let attempts = (0..BEST_OF)
            .map(|_| {
                requests += 1;
                let mut nonce = [0u8; 32];
                nonce[..4].copy_from_slice(&requests.to_be_bytes());
                let before = read_clocks();
                std::thread::sleep(FAKE_RTT);
                let after = read_clocks();
                // The NSM's clock: the system clock plus the offset, read at
                // the middle of the request, in whole milliseconds.
                let mid = before.real_ns + (after.real_ns - before.real_ns) / 2;
                let ts_ms = (mid + offset_ms * NS_PER_MS).div_euclid(NS_PER_MS) as u64;
                Attempt { before, after, nonce, document: Some(DocSpec::new(ts_ms, &nonce).document()) }
            })
            .collect();
        let input = CycleInput { start, attempts, freq_ppm: None, end_mono_ns: read_clocks().mono_ns };
        let snapshot = machine.cycle(input, &mut |bytes| feeder.send(bytes)).expect("state_dir");
        println!("fake-feed: offset_ms {offset_ms} state {} fed {}", snapshot.state.as_str(), snapshot.fed);
        next += CYCLE_NS;
        let now = read_clocks().mono_ns;
        while next <= now {
            next += CYCLE_NS;
        }
        let wait = next - now;
        std::thread::sleep(Duration::new((wait / NS_PER_S) as u64, (wait % NS_PER_S) as u32));
    }
}
