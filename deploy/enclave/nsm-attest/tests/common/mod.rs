// Test helpers: attestation documents made with nsm-api's own AttestationDoc
// (the struct the NSM's payload follows), and a simulated enclave whose
// system clock and NSM can be set apart.
#![allow(dead_code)]

use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use nsm_attest::timefeed::sample::{Attempt, Reading};
use nsm_attest::timefeed::state::{CycleInput, Machine, Snapshot};
use nsm_attest::timefeed::{BEST_OF, CYCLE_NS, NS_PER_MS};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// 2026-11-19T12:00:00Z, the fixtures' timestamp.
pub const T0_MS: u64 = 1_795_089_600_000;
pub const T0_NS: i64 = T0_MS as i64 * NS_PER_MS;

pub struct DocSpec {
    pub timestamp_ms: u64,
    pub nonce: Option<Vec<u8>>,
    pub pcr0: Option<Vec<u8>>,
    pub digest: Digest,
    pub module_id: String,
}

impl DocSpec {
    pub fn new(timestamp_ms: u64, nonce: &[u8]) -> Self {
        DocSpec {
            timestamp_ms,
            nonce: Some(nonce.to_vec()),
            pcr0: Some(vec![0xab; 48]),
            digest: Digest::SHA384,
            module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_owned(),
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut pcrs = BTreeMap::new();
        if let Some(p) = &self.pcr0 {
            pcrs.insert(0, p.clone());
        }
        pcrs.insert(1, vec![1; 48]);
        AttestationDoc::new(
            self.module_id.clone(),
            self.digest,
            self.timestamp_ms,
            pcrs,
            vec![0xce; 16],
            vec![vec![0xca; 16]],
            None,
            self.nonce.clone(),
            None,
        )
        .to_binary()
    }

    /// The COSE_Sign1 array, untagged as the NSM sends it.
    pub fn document(&self) -> Vec<u8> {
        sign1(&self.payload())
    }
}

pub fn sign1(payload: &[u8]) -> Vec<u8> {
    let protected = serde_cbor::to_vec(&BTreeMap::from([(1i64, -35i64)])).unwrap();
    let unprotected = serde_cbor::Value::Map(BTreeMap::new());
    serde_cbor::to_vec(&(ByteBuf::from(protected), unprotected, ByteBuf::from(payload.to_vec()), ByteBuf::from(vec![0u8; 96])))
        .unwrap()
}

/// A fresh directory under the system temp dir, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nsm-timefeed-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What the simulated NSM does with one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nsm {
    Good,
    Error,
    WrongNonce,
    OtherPcr0,
}

/// A simulated enclave. `t_ns` is true time since boot, which MONOTONIC_RAW
/// and MONOTONIC follow exactly. The system clock reads true time plus
/// `sys_err_ns`; the NSM reads true time plus `nsm_err_ns`, truncated to ms.
pub struct Sim {
    pub t_ns: i64,
    pub sys_err_ns: i64,
    pub nsm_err_ns: i64,
    /// Round trip of each attempt in a cycle.
    pub rtts_ns: [i64; BEST_OF],
    pub nsm: Nsm,
    pub nonces: u32,
}

impl Default for Sim {
    fn default() -> Self {
        Sim { t_ns: 0, sys_err_ns: 0, nsm_err_ns: 0, rtts_ns: [2 * NS_PER_MS; BEST_OF], nsm: Nsm::Good, nonces: 0 }
    }
}

impl Sim {
    pub fn reading(&self) -> Reading {
        Reading { real_ns: T0_NS + self.t_ns + self.sys_err_ns, raw_ns: self.t_ns, mono_ns: self.t_ns }
    }

    fn attempt(&mut self, rtt_ns: i64) -> Attempt {
        self.nonces += 1;
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&self.nonces.to_be_bytes());
        let before = self.reading();
        let mid_t = self.t_ns + rtt_ns / 2;
        self.t_ns += rtt_ns;
        let after = self.reading();
        let ts_ms = ((T0_NS + mid_t + self.nsm_err_ns) / NS_PER_MS) as u64;
        let mut spec = DocSpec::new(ts_ms, &nonce);
        let document = match self.nsm {
            Nsm::Error => None,
            Nsm::Good => Some(spec.document()),
            Nsm::WrongNonce => {
                spec.nonce = Some(vec![0xee; 32]);
                Some(spec.document())
            }
            Nsm::OtherPcr0 => {
                spec.pcr0 = Some(vec![0xcd; 48]);
                Some(spec.document())
            }
        };
        Attempt { before, after, nonce, document }
    }

    /// One cycle's input, starting at the current time; the time then moves
    /// to the start of the next cycle.
    pub fn input(&mut self) -> CycleInput {
        let cycle_start = self.t_ns;
        let start = self.reading();
        let attempts = self.rtts_ns.map(|rtt| self.attempt(rtt)).to_vec();
        let input = CycleInput { start, attempts, freq_ppm: Some(-17.0), end_mono_ns: self.t_ns };
        self.t_ns = cycle_start + CYCLE_NS;
        input
    }

    /// Runs one cycle with a chronyd that always receives.
    pub fn run(&mut self, m: &mut Machine) -> Snapshot {
        let input = self.input();
        m.cycle(input, &mut |_| Ok(())).unwrap()
    }

    /// Runs one cycle with no chronyd behind the socket.
    pub fn run_refused(&mut self, m: &mut Machine) -> Snapshot {
        let input = self.input();
        m.cycle(input, &mut |_| Err(io::Error::from_raw_os_error(libc::ECONNREFUSED))).unwrap()
    }
}
