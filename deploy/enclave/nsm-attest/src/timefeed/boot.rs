// The boot gate and the other facts fixed for one enclave boot. The state
// directory is a tmpfs under /run, so it lasts exactly one boot and survives
// a helper restart:
// - <state_dir>/boot: "ok" or "boot_refused", decided by the first good
//   sample of the boot. A restarted helper reads it instead of deciding again.
// - <state_dir>/pcr0: the PCR0 of the first good document, in hex. Every
//   later document must carry the same.
use super::{read_optional, write_atomic, BOOT_MAX_NS};
use std::io;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    Ok,
    Refused,
}

impl Boot {
    /// The gate: at most BOOT_MAX_NS either way.
    pub fn decide(offset_ns: i64) -> Boot {
        if offset_ns.unsigned_abs() <= BOOT_MAX_NS as u64 {
            Boot::Ok
        } else {
            Boot::Refused
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Boot::Ok => "ok",
            Boot::Refused => "boot_refused",
        }
    }
}

const BOOT_FILE: &str = "boot";
const PCR0_FILE: &str = "pcr0";

/// The recorded decision, if any. Anything other than the two words counts as
/// refused, so a damaged file fails closed.
pub fn load(dir: &Path) -> io::Result<Option<Boot>> {
    Ok(read_optional(&dir.join(BOOT_FILE))?.map(|bytes| match bytes.trim_ascii() {
        b"ok" => Boot::Ok,
        _ => Boot::Refused,
    }))
}

pub fn store(dir: &Path, boot: Boot) -> io::Result<()> {
    write_atomic(&dir.join(BOOT_FILE), format!("{}\n", boot.as_str()).as_bytes())
}

/// The recorded PCR0. A file that is not hex fails with InvalidData.
pub fn load_pcr0(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    match read_optional(&dir.join(PCR0_FILE))? {
        None => Ok(None),
        Some(bytes) => hex::decode(bytes.trim_ascii())
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pcr0: not hex")),
    }
}

pub fn store_pcr0(dir: &Path, pcr0: &[u8]) -> io::Result<()> {
    write_atomic(&dir.join(PCR0_FILE), format!("{}\n", hex::encode(pcr0)).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timefeed::NS_PER_S;

    #[test]
    fn ten_minutes_either_way() {
        assert_eq!(Boot::decide(599 * NS_PER_S), Boot::Ok);
        assert_eq!(Boot::decide(-599 * NS_PER_S), Boot::Ok);
        assert_eq!(Boot::decide(600 * NS_PER_S), Boot::Ok);
        assert_eq!(Boot::decide(601 * NS_PER_S), Boot::Refused);
        assert_eq!(Boot::decide(-601 * NS_PER_S), Boot::Refused);
        assert_eq!(Boot::decide(i64::MIN), Boot::Refused);
    }

    #[test]
    fn files_round_trip_and_damage_fails_closed() {
        let dir = std::env::temp_dir().join(format!("nsm-timefeed-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load(&dir).unwrap(), None);
        store(&dir, Boot::Ok).unwrap();
        assert_eq!(load(&dir).unwrap(), Some(Boot::Ok));
        store(&dir, Boot::Refused).unwrap();
        assert_eq!(load(&dir).unwrap(), Some(Boot::Refused));
        std::fs::write(dir.join(BOOT_FILE), "maybe").unwrap();
        assert_eq!(load(&dir).unwrap(), Some(Boot::Refused));

        assert_eq!(load_pcr0(&dir).unwrap(), None);
        store_pcr0(&dir, &[0xab; 48]).unwrap();
        assert_eq!(load_pcr0(&dir).unwrap(), Some(vec![0xab; 48]));
        std::fs::write(dir.join(PCR0_FILE), "zz").unwrap();
        assert_eq!(load_pcr0(&dir).unwrap_err().kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
