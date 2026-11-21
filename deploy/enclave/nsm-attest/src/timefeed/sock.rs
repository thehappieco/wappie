// The sample chronyd's SOCK reference clock reads (refclock_sock.c):
//   struct sock_sample {
//     struct timeval tv;  /* system time of the measurement */
//     double offset;      /* true time - system time, seconds */
//     int pulse;          /* 0: not a PPS sample */
//     int leap;           /* 0: no leap second */
//     int _pad;
//     int magic;          /* 0x534f434b, "SOCK" */
//   };
// 40 bytes on aarch64 (and x86_64): a 16-byte timeval, an 8-byte double and
// four ints, with no padding. chronyd drops a datagram of any other size.
use super::NS_PER_S;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

pub const SOCK_MAGIC: libc::c_int = 0x534f_434b;
pub const SAMPLE_LEN: usize = 40;

/// The C struct, field for field, with the platform's own timeval.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockSample {
    pub tv: libc::timeval,
    pub offset: f64,
    pub pulse: libc::c_int,
    pub leap: libc::c_int,
    pub pad: libc::c_int,
    pub magic: libc::c_int,
}

const _: () = assert!(std::mem::size_of::<SockSample>() == SAMPLE_LEN);

impl SockSample {
    /// A sample taken at system time `at_real_ns` (CLOCK_REALTIME, ns) whose
    /// offset (NSM - system) is `offset_ns`.
    pub fn new(at_real_ns: i64, offset_ns: i64) -> Self {
        SockSample {
            tv: libc::timeval {
                tv_sec: at_real_ns.div_euclid(NS_PER_S) as _,
                tv_usec: (at_real_ns.rem_euclid(NS_PER_S) / 1_000) as _,
            },
            offset: offset_ns as f64 / NS_PER_S as f64,
            pulse: 0,
            leap: 0,
            pad: 0,
            magic: SOCK_MAGIC,
        }
    }

    /// The bytes as chronyd reads them (native byte order).
    pub fn to_bytes(&self) -> [u8; SAMPLE_LEN] {
        let mut out = [0u8; SAMPLE_LEN];
        // SAFETY: SockSample is repr(C), exactly SAMPLE_LEN bytes (checked at
        // compile time above) and has no padding, so every byte is initialised.
        let bytes = unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, SAMPLE_LEN) };
        out.copy_from_slice(bytes);
        out
    }
}

/// Sends samples to chronyd's socket. chronyd creates the socket; this end is
/// unbound. Non-blocking, so a chronyd that stops reading turns into a
/// failed send instead of a hung helper.
pub struct Feeder {
    socket: UnixDatagram,
    path: PathBuf,
}

impl Feeder {
    pub fn new(path: &Path) -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        Ok(Feeder { socket, path: path.to_path_buf() })
    }

    /// ECONNREFUSED (no chronyd behind the socket file) and ENOENT (no
    /// socket file) are the usual failures; every failure counts the same.
    pub fn send(&self, sample: &[u8; SAMPLE_LEN]) -> io::Result<()> {
        let sent = self.socket.send_to(sample, &self.path)?;
        if sent != SAMPLE_LEN {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short datagram"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn layout_is_chronys() {
        assert_eq!(size_of::<SockSample>(), 40);
        assert_eq!(size_of::<libc::timeval>(), 16);
        assert_eq!(offset_of!(SockSample, tv), 0);
        assert_eq!(offset_of!(SockSample, offset), 16);
        assert_eq!(offset_of!(SockSample, pulse), 24);
        assert_eq!(offset_of!(SockSample, leap), 28);
        assert_eq!(offset_of!(SockSample, pad), 32);
        assert_eq!(offset_of!(SockSample, magic), 36);
        assert_eq!(SOCK_MAGIC, 0x534f434b);
    }

    #[test]
    fn bytes_hold_each_field_in_place() {
        let at = 1_795_089_600 * NS_PER_S + 123_456_789;
        let bytes = SockSample::new(at, -1_500_000).to_bytes();
        let i64_at = |o: usize| i64::from_ne_bytes(bytes[o..o + 8].try_into().unwrap());
        let i32_at = |o: usize| i32::from_ne_bytes(bytes[o..o + 4].try_into().unwrap());
        assert_eq!(i64_at(0), 1_795_089_600);
        assert_eq!(i64_at(8), 123_456);
        assert_eq!(f64::from_ne_bytes(bytes[16..24].try_into().unwrap()), -0.0015);
        assert_eq!((i32_at(24), i32_at(28), i32_at(32)), (0, 0, 0));
        assert_eq!(i32_at(36), 0x534f434b);
        assert_eq!(&bytes[36..40], &0x534f434bu32.to_ne_bytes());
    }

    #[test]
    fn time_before_the_epoch_keeps_usec_positive() {
        let s = SockSample::new(-1, 0);
        assert_eq!((s.tv.tv_sec, s.tv.tv_usec), (-1, 999_999));
    }

    #[test]
    fn a_missing_socket_fails_the_send() {
        let feeder = Feeder::new(Path::new("/nonexistent-wappie/nsm.sock")).unwrap();
        let err = feeder.send(&SockSample::new(0, 0).to_bytes()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_listening_socket_receives_the_40_bytes() {
        let dir = std::env::temp_dir().join(format!("nsm-timefeed-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nsm.sock");
        let chronyd = UnixDatagram::bind(&path).unwrap();
        let sample = SockSample::new(5 * NS_PER_S, 250_000_000).to_bytes();
        Feeder::new(&path).unwrap().send(&sample).unwrap();
        let mut buf = [0u8; 64];
        let n = chronyd.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &sample[..]);
        drop(chronyd);
        // The file stays behind with nobody reading: ECONNREFUSED.
        let err = Feeder::new(&path).unwrap().send(&sample).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ECONNREFUSED));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
