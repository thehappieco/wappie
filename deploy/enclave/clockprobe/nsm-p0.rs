// nsm-p0: the clock probe's own measuring tool (deploy/enclave/clockprobe).
// NEVER in the release image. Dockerfile.clockprobe copies it into the
// nsm-attest crate as an example and builds it against the crate's own
// library and Cargo.lock, so it decodes documents with exactly the code
// nsm-timefeed uses (src/timefeed/cose.rs, which calls
// AttestationDoc::from_binary).
//
//   nsm-p0 sample                    one NSM sample
//   nsm-p0 latency <n> <label>       n attestations back to back on one fd
//   nsm-p0 concurrent <n>            two fds open at once, then two threads
//   nsm-p0 kernel                    clock resolutions, adjtimex, clock_settime
//   nsm-p0 align                     set CLOCK_REALTIME to NSM time
//   nsm-p0 shift <ms>                step CLOCK_REALTIME by <ms>
//   nsm-p0 restore <freq> <tick>     adjtimex frequency (raw) and tick
//   nsm-p0 watch <file> <nsm_every_s>
//       every second the three clocks, and an NSM sample every <nsm_every_s>
//       seconds (0: never), appended to <file> as JSON lines until killed
//
// Each command prints one JSON object on stdout (watch prints nothing).
// Exit 0 when it ran, 1 when it could not (the JSON says why), 2 without
// /dev/nsm, 3 on bad arguments.
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use nsm_attest::timefeed::cose;
use nsm_attest::timefeed::sample::{read_clocks, Reading};
use serde_bytes::ByteBuf;
use std::fmt::Write as _;
use std::io::Write;
use std::process::exit;
use std::time::{Duration, Instant};

const NS_PER_MS: i64 = 1_000_000;
const NS_PER_S: i64 = 1_000_000_000;
/// The same 0.5 ms nsm-timefeed adds to centre a truncated timestamp.
const ROUNDING_NS: i64 = NS_PER_MS / 2;

fn usage() -> ! {
    eprintln!("usage: nsm-p0 sample | latency <n> <label> | concurrent <n> | kernel | align | shift <ms> | restore <freq> <tick> | watch <file> <nsm_every_s>");
    exit(3)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn print(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn open() -> i32 {
    let fd = nsm_init();
    if fd < 0 {
        print("{\"ok\":false,\"error\":\"cannot open /dev/nsm\"}");
        exit(2);
    }
    fd
}

fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    let mut filled = 0;
    while filled < n.len() {
        // SAFETY: writes at most the remaining bytes of `n`.
        let r = unsafe { libc::getrandom(n[filled..].as_mut_ptr().cast(), n.len() - filled, 0) };
        if r < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            print("{\"ok\":false,\"error\":\"getrandom failed\"}");
            exit(1);
        }
        filled += r as usize;
    }
    n
}

/// One attestation: the clocks either side, and the decoded timestamp or why
/// there is none.
struct Sample {
    before: Reading,
    after: Reading,
    ts_ms: Option<u64>,
    error: Option<String>,
    tag18: bool,
    doc_len: usize,
}

impl Sample {
    fn rtt_ns(&self) -> i64 {
        self.after.raw_ns - self.before.raw_ns
    }
    fn mid_real_ns(&self) -> i64 {
        self.before.real_ns + (self.after.real_ns - self.before.real_ns) / 2
    }
    fn mid_raw_ns(&self) -> i64 {
        self.before.raw_ns + (self.after.raw_ns - self.before.raw_ns) / 2
    }
    /// NSM time minus system time at the midpoint, with nsm-timefeed's
    /// rounding (positive: the system clock is behind).
    fn offset_ns(&self) -> Option<i64> {
        self.ts_ms.map(|ts| ts as i64 * NS_PER_MS + ROUNDING_NS - self.mid_real_ns())
    }
    fn json(&self) -> String {
        let opt = |v: Option<i64>| v.map_or("null".to_owned(), |v| v.to_string());
        format!(
            "{{\"ts_ms\":{},\"rtt_ns\":{},\"mid_real_ns\":{},\"mid_raw_ns\":{},\"mid_mono_ns\":{},\"offset_ns\":{},\"tag18\":{},\"doc_len\":{},\"error\":{}}}",
            opt(self.ts_ms.map(|v| v as i64)),
            self.rtt_ns(),
            self.mid_real_ns(),
            self.mid_raw_ns(),
            self.before.mono_ns + (self.after.mono_ns - self.before.mono_ns) / 2,
            opt(self.offset_ns()),
            self.tag18,
            self.doc_len,
            self.error.as_deref().map_or("null".to_owned(), json_str),
        )
    }
}

fn sample(fd: i32) -> Sample {
    let n = nonce();
    let request = Request::Attestation { user_data: None, nonce: Some(ByteBuf::from(n.to_vec())), public_key: None };
    let before = read_clocks();
    let response = nsm_process_request(fd, request);
    let after = read_clocks();
    let mut s = Sample { before, after, ts_ms: None, error: None, tag18: false, doc_len: 0 };
    match response {
        Response::Attestation { document } => {
            s.doc_len = document.len();
            s.tag18 = document.first() == Some(&0xd2);
            match cose::decode(&document, &n) {
                Ok(doc) => s.ts_ms = Some(doc.timestamp_ms),
                Err(e) => s.error = Some(format!("document: {e:?}")),
            }
        }
        Response::Error(code) => s.error = Some(format!("nsm: {code:?}")),
        _ => s.error = Some("nsm: unexpected response".to_owned()),
    }
    s
}

/// The smallest round trip of `n` good samples (None if none was good).
fn best_of(fd: i32, n: usize) -> Option<Sample> {
    (0..n).map(|_| sample(fd)).filter(|s| s.ts_ms.is_some()).min_by_key(Sample::rtt_ns)
}

fn percentile(sorted: &[i64], p: f64) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn stats(values: &[i64]) -> String {
    let mut v = values.to_vec();
    v.sort_unstable();
    if v.is_empty() {
        return "null".to_owned();
    }
    let mean = v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64;
    format!(
        "{{\"n\":{},\"min\":{},\"p50\":{},\"p90\":{},\"p99\":{},\"max\":{},\"mean\":{:.0}}}",
        v.len(),
        v[0],
        percentile(&v, 0.5),
        percentile(&v, 0.9),
        percentile(&v, 0.99),
        v[v.len() - 1],
        mean
    )
}

fn errors_json(samples: &[Sample]) -> String {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for e in samples.iter().filter_map(|s| s.error.clone()) {
        match counts.iter_mut().find(|(k, _)| *k == e) {
            Some((_, c)) => *c += 1,
            None => counts.push((e, 1)),
        }
    }
    let body: Vec<String> = counts.iter().map(|(k, c)| format!("{}:{c}", json_str(k))).collect();
    format!("{{{}}}", body.join(","))
}

/// What the timestamps say about their resolution: the smallest change seen
/// between two samples, and how many fall on whole 10 ms, 100 ms and seconds
/// (with 1 ms resolution about 10%, 1% and 0.1%).
fn resolution_json(samples: &[Sample]) -> String {
    let ts: Vec<u64> = samples.iter().filter_map(|s| s.ts_ms).collect();
    let mut min_step: Option<u64> = None;
    for w in ts.windows(2) {
        if w[1] > w[0] {
            let d = w[1] - w[0];
            min_step = Some(min_step.map_or(d, |m| m.min(d)));
        }
    }
    let backwards = ts.windows(2).filter(|w| w[1] < w[0]).count();
    let frac = |m: u64| if ts.is_empty() { 0.0 } else { ts.iter().filter(|&&t| t % m == 0).count() as f64 / ts.len() as f64 };
    let mut distinct = ts.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let mut ms_digits: Vec<u64> = ts.iter().map(|t| t % 1000).collect();
    ms_digits.sort_unstable();
    ms_digits.dedup();
    // ts*1e6 - mid_real, without the rounding: for a timestamp truncated to
    // whole milliseconds its spread is about 1 ms plus the round trip.
    let raw_d: Vec<i64> = samples
        .iter()
        .filter_map(|s| s.ts_ms.map(|t| t as i64 * NS_PER_MS - s.mid_real_ns()))
        .collect();
    format!(
        "{{\"min_step_ms\":{},\"backwards\":{},\"distinct\":{},\"distinct_ms_of_second\":{},\"on_10ms\":{:.4},\"on_100ms\":{:.4},\"on_1s\":{:.4},\"ts_minus_mid_ns\":{}}}",
        min_step.map_or("null".to_owned(), |v| v.to_string()),
        backwards,
        distinct.len(),
        ms_digits.len(),
        frac(10),
        frac(100),
        frac(1000),
        stats(&raw_d)
    )
}

fn latency(n: usize, label: &str) {
    let fd = open();
    let started = Instant::now();
    let samples: Vec<Sample> = (0..n).map(|_| sample(fd)).collect();
    let elapsed = started.elapsed();
    nsm_exit(fd);
    let good: Vec<&Sample> = samples.iter().filter(|s| s.ts_ms.is_some()).collect();
    let rtts: Vec<i64> = samples.iter().map(Sample::rtt_ns).collect();
    let good_rtts: Vec<i64> = good.iter().map(|s| s.rtt_ns()).collect();
    let tag18 = good.iter().filter(|s| s.tag18).count();
    let doc_len: Vec<i64> = good.iter().map(|s| s.doc_len as i64).collect();
    print(&format!(
        "{{\"ok\":true,\"label\":{},\"n\":{n},\"good\":{},\"elapsed_ms\":{},\"rtt_ns\":{},\"good_rtt_ns\":{},\"errors\":{},\"from_binary_decoded\":{},\"tag18\":{tag18},\"doc_len\":{},\"resolution\":{},\"first\":{},\"last\":{}}}",
        json_str(label),
        good.len(),
        elapsed.as_millis(),
        stats(&rtts),
        stats(&good_rtts),
        errors_json(&samples),
        good.len(),
        stats(&doc_len),
        resolution_json(&samples),
        samples.first().map_or("null".to_owned(), Sample::json),
        samples.last().map_or("null".to_owned(), Sample::json),
    ));
}

fn concurrent(n: usize) {
    // Two descriptors open at the same time, used in turn.
    let a = open();
    let b = nsm_init();
    let mut both = Vec::new();
    let second_open = b >= 0;
    if second_open {
        for i in 0..n {
            both.push(sample(if i % 2 == 0 { a } else { b }));
        }
        nsm_exit(b);
    }
    nsm_exit(a);
    // Two threads, each with its own descriptor, at the same time.
    let threads: Vec<_> = (0..2)
        .map(|_| {
            std::thread::spawn(move || {
                let fd = nsm_init();
                if fd < 0 {
                    return (false, Vec::new());
                }
                let s: Vec<Sample> = (0..n / 2).map(|_| sample(fd)).collect();
                nsm_exit(fd);
                (true, s)
            })
        })
        .collect();
    let mut opened = 0;
    let mut parallel = Vec::new();
    for t in threads {
        if let Ok((ok, s)) = t.join() {
            opened += usize::from(ok);
            parallel.extend(s);
        }
    }
    let good = |v: &[Sample]| v.iter().filter(|s| s.ts_ms.is_some()).count();
    let rtts = |v: &[Sample]| v.iter().map(Sample::rtt_ns).collect::<Vec<_>>();
    print(&format!(
        "{{\"ok\":true,\"second_open\":{second_open},\"alternating\":{{\"n\":{},\"good\":{},\"errors\":{},\"rtt_ns\":{}}},\"threads_opened\":{opened},\"threads\":{{\"n\":{},\"good\":{},\"errors\":{},\"rtt_ns\":{}}}}}",
        both.len(),
        good(&both),
        errors_json(&both),
        stats(&rtts(&both)),
        parallel.len(),
        good(&parallel),
        errors_json(&parallel),
        stats(&rtts(&parallel)),
    ));
}

#[allow(clippy::useless_conversion)]
fn getres(id: libc::clockid_t) -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid timespec.
    if unsafe { libc::clock_getres(id, &mut ts) } != 0 {
        return -1;
    }
    i64::from(ts.tv_sec) * NS_PER_S + i64::from(ts.tv_nsec)
}

fn read_timex() -> Result<(libc::timex, i32), i32> {
    // SAFETY: an all-zero timex is valid; modes 0 only reads.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::adjtimex(&mut tx) };
    if rc < 0 {
        Err(errno())
    } else {
        Ok((tx, rc))
    }
}

fn timex_json(tx: &libc::timex, rc: i32) -> String {
    format!(
        "{{\"state\":{rc},\"freq_raw\":{},\"freq_ppm\":{:.3},\"tick\":{},\"status\":{},\"offset\":{},\"maxerror\":{},\"esterror\":{},\"constant\":{},\"precision\":{},\"tolerance\":{}}}",
        tx.freq,
        tx.freq as f64 / 65_536.0,
        tx.tick,
        tx.status,
        tx.offset,
        tx.maxerror,
        tx.esterror,
        tx.constant,
        tx.precision,
        tx.tolerance
    )
}

/// Steps CLOCK_REALTIME by `delta_ns` (clock_settime, as `date -s` does).
fn step(delta_ns: i64) -> Result<(), i32> {
    let now = read_clocks().real_ns + delta_ns;
    let ts = libc::timespec {
        tv_sec: now.div_euclid(NS_PER_S) as _,
        tv_nsec: now.rem_euclid(NS_PER_S) as _,
    };
    // SAFETY: ts is a valid timespec.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn kernel() {
    let res = format!(
        "{{\"realtime\":{},\"monotonic\":{},\"monotonic_raw\":{}}}",
        getres(libc::CLOCK_REALTIME),
        getres(libc::CLOCK_MONOTONIC),
        getres(libc::CLOCK_MONOTONIC_RAW)
    );
    let read = read_timex();
    let read_json = match &read {
        Ok((tx, rc)) => timex_json(tx, *rc),
        Err(e) => format!("{{\"errno\":{e}}}"),
    };
    // Write the frequency it already has: what chronyd needs, no change.
    let write_json = match &read {
        Ok((tx, _)) => {
            let mut w: libc::timex = unsafe { std::mem::zeroed() };
            w.modes = libc::ADJ_FREQUENCY;
            w.freq = tx.freq;
            // SAFETY: a valid timex with one mode bit.
            let rc = unsafe { libc::adjtimex(&mut w) };
            if rc < 0 {
                format!("{{\"ok\":false,\"errno\":{}}}", errno())
            } else {
                "{\"ok\":true}".to_owned()
            }
        }
        Err(_) => "null".to_owned(),
    };
    // A step of zero: the clock is set to what it reads (it moves by the
    // microseconds between the read and the set).
    let settime = match step(0) {
        Ok(()) => "{\"ok\":true}".to_owned(),
        Err(e) => format!("{{\"ok\":false,\"errno\":{e}}}"),
    };
    print(&format!(
        "{{\"ok\":true,\"clock_getres_ns\":{res},\"adjtimex_read\":{read_json},\"adjtimex_write_same_freq\":{write_json},\"clock_settime_now\":{settime}}}"
    ));
}

fn align() {
    let fd = open();
    let Some(before) = best_of(fd, 5) else {
        nsm_exit(fd);
        print("{\"ok\":false,\"error\":\"no good NSM sample\"}");
        exit(1);
    };
    let offset = before.offset_ns().unwrap_or(0);
    let stepped = step(offset);
    let after = best_of(fd, 5);
    nsm_exit(fd);
    let after_json = after.as_ref().map_or("null".to_owned(), Sample::json);
    match stepped {
        Ok(()) => print(&format!(
            "{{\"ok\":true,\"offset_before_ns\":{offset},\"offset_after_ns\":{},\"before\":{},\"after\":{after_json}}}",
            after.as_ref().and_then(Sample::offset_ns).map_or("null".to_owned(), |v| v.to_string()),
            before.json()
        )),
        Err(e) => {
            print(&format!("{{\"ok\":false,\"error\":\"clock_settime\",\"errno\":{e},\"offset_before_ns\":{offset}}}"));
            exit(1);
        }
    }
}

fn shift(ms: i64) {
    let before = read_clocks();
    match step(ms * NS_PER_MS) {
        Ok(()) => {
            let after = read_clocks();
            let moved = (after.real_ns - after.raw_ns) - (before.real_ns - before.raw_ns);
            print(&format!("{{\"ok\":true,\"asked_ms\":{ms},\"moved_ns\":{moved}}}"));
        }
        Err(e) => {
            print(&format!("{{\"ok\":false,\"asked_ms\":{ms},\"errno\":{e}}}"));
            exit(1);
        }
    }
}

fn restore(freq: i64, tick: i64) {
    let mut w: libc::timex = unsafe { std::mem::zeroed() };
    w.modes = libc::ADJ_FREQUENCY | libc::ADJ_TICK;
    w.freq = freq as _;
    w.tick = tick as _;
    // SAFETY: a valid timex with two mode bits.
    if unsafe { libc::adjtimex(&mut w) } < 0 {
        print(&format!("{{\"ok\":false,\"errno\":{}}}", errno()));
        exit(1);
    }
    match read_timex() {
        Ok((tx, rc)) => print(&format!("{{\"ok\":true,\"now\":{}}}", timex_json(&tx, rc))),
        Err(e) => print(&format!("{{\"ok\":true,\"now\":{{\"errno\":{e}}}}}")),
    }
}

fn watch(file: &str, nsm_every_s: u64) {
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(file).unwrap_or_else(|e| {
        print(&format!("{{\"ok\":false,\"error\":{}}}", json_str(&e.to_string())));
        exit(1)
    });
    let fd = if nsm_every_s > 0 { open() } else { -1 };
    let mut tick: u64 = 0;
    let start = Instant::now();
    loop {
        let c = read_clocks();
        let mut line = format!("{{\"real_ns\":{},\"raw_ns\":{},\"mono_ns\":{}", c.real_ns, c.raw_ns, c.mono_ns);
        if nsm_every_s > 0 && tick.is_multiple_of(nsm_every_s) {
            if let Some(s) = best_of(fd, 3) {
                let _ = write!(line, ",\"nsm\":{}", s.json());
            }
        }
        line.push_str("}\n");
        if out.write_all(line.as_bytes()).is_err() {
            exit(1);
        }
        tick += 1;
        // On a grid of whole seconds from the start (monotonic, so steps of
        // the system clock do not move it).
        let next = Duration::from_secs(tick);
        if let Some(wait) = next.checked_sub(start.elapsed()) {
            std::thread::sleep(wait);
        }
    }
}

fn arg<T: std::str::FromStr>(args: &[String], i: usize) -> T {
    args.get(i).and_then(|a| a.parse().ok()).unwrap_or_else(|| usage())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sample") if args.len() == 1 => {
            let fd = open();
            let s = sample(fd);
            nsm_exit(fd);
            let ok = s.ts_ms.is_some();
            print(&format!("{{\"ok\":{ok},\"sample\":{}}}", s.json()));
            if !ok {
                exit(1);
            }
        }
        Some("latency") if args.len() == 3 => latency(arg(&args, 1), &args[2]),
        Some("concurrent") if args.len() == 2 => concurrent(arg(&args, 1)),
        Some("kernel") if args.len() == 1 => kernel(),
        Some("align") if args.len() == 1 => align(),
        Some("shift") if args.len() == 2 => shift(arg(&args, 1)),
        Some("restore") if args.len() == 3 => restore(arg(&args, 1), arg(&args, 2)),
        Some("watch") if args.len() == 3 => watch(&args[1], arg(&args, 2)),
        _ => usage(),
    }
}
