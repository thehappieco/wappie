// nsm-timefeed's cycle (src/timefeed/state.rs) against a simulated enclave.
mod common;

use common::{Nsm, Sim, TempDir};
use nsm_attest::timefeed::cose::DocError;
use nsm_attest::timefeed::sample::Reject;
use nsm_attest::timefeed::sock::SAMPLE_LEN;
use nsm_attest::timefeed::state::{Machine, State, STATE_FILE};
use nsm_attest::timefeed::{
    CHRONYD_GRACE_NS, CYCLE_NS, NSM_ERROR_CYCLES, NS_PER_MS, NS_PER_S, RTT_HARD_CAP_NS, STALE_NS,
    SYNC_SPAN_NS,
};

fn read(dir: &TempDir, name: &str) -> String {
    std::fs::read_to_string(dir.0.join(name)).unwrap()
}

#[test]
fn a_good_sample_is_fed_with_the_right_offset() {
    let dir = TempDir::new("fed");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    // The system clock is 1.25 s behind NSM: offset +1.25 s.
    let mut sim = Sim { sys_err_ns: -1_250 * NS_PER_MS, ..Sim::default() };
    let mut sent = Vec::new();
    let input = sim.input();
    let mid_real = input.attempts[0].before.real_ns + NS_PER_MS;
    let s = m.cycle(input, &mut |b: &[u8; SAMPLE_LEN]| {
        sent.push(*b);
        Ok(())
    })
    .unwrap();
    assert_eq!((s.state, s.fed, s.reject), (State::Ok, true, None));
    let g = s.last_good.unwrap();
    // NSM truncates to the millisecond, +0.5 ms centres it: within 0.5 ms.
    assert!((g.offset_ns - 1_250 * NS_PER_MS).abs() <= NS_PER_MS / 2, "{}", g.offset_ns);
    assert_eq!(g.rtt_ns, 2 * NS_PER_MS);
    assert_eq!(sent.len(), 1);
    let b = sent[0];
    let sec = i64::from_ne_bytes(b[0..8].try_into().unwrap());
    let usec = i64::from_ne_bytes(b[8..16].try_into().unwrap());
    assert_eq!(sec * NS_PER_S + usec * 1_000, mid_real / 1_000 * 1_000);
    let offset = f64::from_ne_bytes(b[16..24].try_into().unwrap());
    assert!((offset - 1.25).abs() <= 0.0005, "{offset}");
    assert!(read(&dir, STATE_FILE).contains("\"state\":\"ok\""));
    assert!(read(&dir, STATE_FILE).contains("\"nsm_skew_ms\":-1250.500,"), "skew is system minus NSM");
}

#[test]
fn best_of_three_takes_the_smallest_round_trip() {
    let dir = TempDir::new("best");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim { rtts_ns: [30 * NS_PER_MS, 10 * NS_PER_MS, 20 * NS_PER_MS], ..Sim::default() };
    let s = sim.run(&mut m);
    assert_eq!(s.last_good.unwrap().rtt_ns, 10 * NS_PER_MS);
}

#[test]
fn boot_cap_599_is_fed_601_is_refused_and_the_marker_survives_a_restart() {
    // 599 s behind: fed.
    let dir = TempDir::new("boot-ok");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim { sys_err_ns: -599 * NS_PER_S, ..Sim::default() };
    let s = sim.run(&mut m);
    assert!(s.fed);
    assert_eq!(s.state, State::Ok);
    assert_eq!(read(&dir, "boot"), "ok\n");
    // A restarted helper keeps "ok" even when the clock is now 700 s off.
    let mut m = Machine::open(&dir.0, sim.t_ns).unwrap();
    sim.sys_err_ns = 700 * NS_PER_S;
    let s = sim.run(&mut m);
    assert!(s.fed);

    // 601 s ahead: refused, never fed, still sampled.
    let dir = TempDir::new("boot-refused");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim { sys_err_ns: 601 * NS_PER_S, ..Sim::default() };
    for _ in 0..3 {
        let s = sim.run(&mut m);
        assert_eq!((s.state, s.fed), (State::BootRefused, false));
        assert!(s.last_good.is_some(), "the skew is still reported");
    }
    assert_eq!(read(&dir, "boot"), "boot_refused\n");
    #[cfg(not(feature = "fake-drift"))]
    assert!(read(&dir, STATE_FILE).contains("\"nsm_skew_ms\":600999.500,"), "601 s ahead, less the 0.5 ms centring");
    // A restarted helper keeps refusing, even once the clock is right.
    let mut m = Machine::open(&dir.0, sim.t_ns).unwrap();
    sim.sys_err_ns = 0;
    let s = sim.run(&mut m);
    assert_eq!((s.state, s.fed), (State::BootRefused, false));
}

#[test]
fn nsm_stale_after_120_s_without_a_good_sample() {
    let dir = TempDir::new("stale");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim::default();
    let s = sim.run(&mut m);
    let last_good = s.last_good.unwrap().mono_ns;
    // Every later sample is over the hard round-trip cap: thrown away on
    // timing, which is not an NSM error.
    sim.rtts_ns = [RTT_HARD_CAP_NS + 1; 3];
    let mut at = |end: i64| {
        let mut input = sim.input();
        input.end_mono_ns = end;
        m.cycle(input, &mut |_| Ok(())).unwrap()
    };
    let s = at(last_good + STALE_NS - 1);
    assert_eq!((s.state, s.reject), (State::Ok, Some(Reject::Rtt)));
    let s = at(last_good + STALE_NS);
    assert_eq!(s.state, State::NsmStale);
    assert!(!s.synced);
    assert!(read(&dir, STATE_FILE).contains(&format!("\"last_good_mono_ns\":{last_good},")));
    // A good sample brings it back.
    sim.rtts_ns = [2 * NS_PER_MS; 3];
    sim.t_ns = last_good + STALE_NS + CYCLE_NS;
    assert_eq!(sim.run(&mut m).state, State::Ok);
}

#[test]
fn starting_until_the_first_good_sample_then_stale_from_the_start() {
    let dir = TempDir::new("starting");
    let started = 5 * NS_PER_S;
    let mut m = Machine::open(&dir.0, started).unwrap();
    let mut sim = Sim { t_ns: started, rtts_ns: [RTT_HARD_CAP_NS + 1; 3], ..Sim::default() };
    let mut at = |end: i64| {
        let mut input = sim.input();
        input.end_mono_ns = end;
        m.cycle(input, &mut |_| Ok(())).unwrap()
    };
    assert_eq!(at(started + STALE_NS - 1).state, State::Starting);
    assert_eq!(at(started + STALE_NS).state, State::NsmStale);
    assert!(read(&dir, STATE_FILE).contains("\"last_good_mono_ns\":null,"));
}

#[test]
fn nsm_error_after_three_failing_cycles() {
    for failure in [Nsm::Error, Nsm::WrongNonce] {
        let dir = TempDir::new("nsm-error");
        let mut m = Machine::open(&dir.0, 0).unwrap();
        let mut sim = Sim::default();
        assert_eq!(sim.run(&mut m).state, State::Ok);
        sim.nsm = failure;
        for i in 1..=NSM_ERROR_CYCLES {
            let s = sim.run(&mut m);
            let want = if i < NSM_ERROR_CYCLES { State::Ok } else { State::NsmError };
            assert_eq!(s.state, want, "{failure:?} cycle {i}");
            assert!(!s.fed);
            assert!(s.reject.unwrap().is_integrity());
        }
        sim.nsm = Nsm::Good;
        assert_eq!(sim.run(&mut m).state, State::Ok);
    }
}

#[test]
fn a_different_pcr0_is_refused() {
    let dir = TempDir::new("pcr0");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim::default();
    assert!(sim.run(&mut m).fed);
    assert_eq!(read(&dir, "pcr0"), format!("{}\n", "ab".repeat(48)));
    sim.nsm = Nsm::OtherPcr0;
    let s = sim.run(&mut m);
    assert_eq!(s.reject, Some(Reject::Document(DocError::Pcr0)));
    // A restarted helper still holds this boot's PCR0.
    let mut m = Machine::open(&dir.0, sim.t_ns).unwrap();
    assert_eq!(sim.run(&mut m).reject, Some(Reject::Document(DocError::Pcr0)));
}

#[test]
fn a_step_during_every_attempt_rejects_the_cycle() {
    let dir = TempDir::new("step");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim::default();
    let mut input = sim.input();
    for a in &mut input.attempts {
        a.after.real_ns += 3 * NS_PER_MS;
    }
    let s = m.cycle(input, &mut |_| Ok(())).unwrap();
    assert_eq!((s.reject, s.fed, s.state), (Some(Reject::Step), false, State::Starting));
    // One clean attempt is enough.
    let mut input = sim.input();
    input.attempts[0].after.real_ns += 3 * NS_PER_MS;
    assert!(m.cycle(input, &mut |_| Ok(())).unwrap().fed);
}

#[test]
fn chronyd_gone_after_30_s_of_failed_sends() {
    let dir = TempDir::new("gone");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim::default();
    // No chronyd from the start: the grace runs from the helper's start.
    loop {
        let end = sim.t_ns + 6 * NS_PER_MS;
        let s = sim.run_refused(&mut m);
        let want = if end > CHRONYD_GRACE_NS { State::ChronydGone } else { State::Ok };
        assert_eq!(s.state, want, "at {end}");
        if want == State::ChronydGone {
            break;
        }
    }
    // chronyd is back.
    let s = sim.run(&mut m);
    assert_eq!((s.state, s.fed), (State::Ok, true));
    // It goes away again: 30 s from the last delivery.
    let delivered = sim.t_ns - CYCLE_NS + 6 * NS_PER_MS;
    loop {
        let end = sim.t_ns + 6 * NS_PER_MS;
        let s = sim.run_refused(&mut m);
        if end - delivered > CHRONYD_GRACE_NS {
            assert_eq!(s.state, State::ChronydGone);
            break;
        }
        assert_eq!(s.state, State::Ok);
    }
}

#[test]
fn cap_exceeded_is_sticky_and_stops_the_feed() {
    let dir = TempDir::new("cap");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim::default();
    for _ in 0..10 {
        assert!(sim.run(&mut m).fed);
    }
    // Someone steps the clock 6 s forward.
    sim.sys_err_ns = 6 * NS_PER_S;
    let s = sim.run(&mut m);
    assert_eq!((s.state, s.fed), (State::CapExceeded, false));
    assert_eq!(s.steps, 1);
    assert_eq!(s.corr_hour_ns, Some(6 * NS_PER_S));
    assert!(read(&dir, STATE_FILE).contains("\"corr_hour_ms\":6000,"));
    // Even with the clock put back, and across a restart.
    sim.sys_err_ns = 0;
    let mut m = Machine::open(&dir.0, sim.t_ns).unwrap();
    for _ in 0..3 {
        let s = sim.run(&mut m);
        assert_eq!((s.state, s.fed), (State::CapExceeded, false));
    }
}

#[test]
fn the_boot_step_does_not_count_against_the_caps() {
    let dir = TempDir::new("boot-step");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    // 300 s behind at boot; chronyd steps after the second sample.
    let mut sim = Sim { sys_err_ns: -300 * NS_PER_S, ..Sim::default() };
    assert!(sim.run(&mut m).fed);
    assert!(sim.run(&mut m).fed);
    sim.sys_err_ns = 0;
    for _ in 0..5 {
        let s = sim.run(&mut m);
        assert_eq!((s.state, s.fed), (State::Ok, true));
        assert_eq!(s.steps, 1);
        assert_eq!(s.corr_hour_ns, Some(0));
    }
}

#[test]
fn a_boot_step_between_the_cycle_start_and_the_chosen_attempt_is_left_out() {
    let dir = TempDir::new("boot-step-race");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    // 90 s behind at boot.
    let mut sim = Sim { sys_err_ns: -90 * NS_PER_S, ..Sim::default() };
    assert!(sim.run(&mut m).fed);
    assert!(sim.run(&mut m).fed);
    // chronyd steps after the cycle's start is read but before its attempts:
    // the start is on the old side of the step, every attempt on the new.
    sim.sys_err_ns = 0;
    let mut input = sim.input();
    input.start.real_ns -= 90 * NS_PER_S;
    let s = m.cycle(input, &mut |_| Ok(())).unwrap();
    assert_eq!((s.state, s.fed, s.steps), (State::Ok, true, 1));
    assert_eq!(s.corr_hour_ns, Some(0));
    for _ in 0..5 {
        let s = sim.run(&mut m);
        assert_eq!((s.state, s.fed), (State::Ok, true));
        assert_eq!(s.steps, 1);
        assert_eq!(s.corr_hour_ns, Some(0));
    }
}

#[test]
fn synced_after_two_polls_within_500_ms() {
    let dir = TempDir::new("synced");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim { sys_err_ns: 400 * NS_PER_MS, ..Sim::default() };
    let first = sim.run(&mut m).last_good.unwrap().mono_ns;
    loop {
        let s = sim.run(&mut m);
        let span = s.last_good.unwrap().mono_ns - first;
        assert_eq!(s.synced, span >= SYNC_SPAN_NS, "span {span}");
        if s.synced {
            break;
        }
    }
    // One sample over 500 ms starts the count again.
    sim.sys_err_ns = 600 * NS_PER_MS;
    assert!(!sim.run(&mut m).synced);
    sim.sys_err_ns = 0;
    assert!(!sim.run(&mut m).synced);
}

#[test]
fn an_nsm_jump_is_held_back_until_three_samples_agree() {
    let dir = TempDir::new("jump");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim::default();
    assert!(sim.run(&mut m).fed);
    sim.nsm_err_ns = -2 * NS_PER_S;
    assert_eq!(sim.run(&mut m).reject, Some(Reject::Inconsistent));
    assert_eq!(sim.run(&mut m).reject, Some(Reject::Inconsistent));
    let s = sim.run(&mut m);
    assert!(s.fed, "the third agreeing sample is the new level");
    #[cfg(not(feature = "fake-drift"))]
    assert!((s.last_good.unwrap().offset_ns + 2 * NS_PER_S).abs() <= NS_PER_MS);
}

// Probe builds: NSM time runs 200 ppm fast against MONOTONIC_RAW, so after
// 1000 s since boot the offset is +200 ms.
#[cfg(feature = "fake-drift")]
#[test]
fn fake_drift_adds_200_ppm_of_the_time_since_boot() {
    let dir = TempDir::new("fake-drift");
    let mut m = Machine::open(&dir.0, 0).unwrap();
    let mut sim = Sim { t_ns: 1_000 * NS_PER_S, ..Sim::default() };
    let s = sim.run(&mut m);
    let offset = s.last_good.unwrap().offset_ns;
    assert!((offset - 200 * NS_PER_MS).abs() <= NS_PER_MS, "{offset}");
}
