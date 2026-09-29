// The compiled-in worker table (docs/mcp-enclave.md §16.6). `--worker` names
// a row; the row fixes the exact argv that is exec'd, the seccomp profile and
// the ceilings no invocation may exceed. There is no free-form program: the
// reader's Node can only choose a row and ask for limits at or below it.
//
// The `max` values are §16.8's WORKERS, which the reader checks at boot
// against `media-jail --table` (and check-image.sh at build), so the two can
// never drift apart unnoticed. The table is measured into PCR0 with the
// binary.

use crate::json::Val;

/// The most a row allows: memcg MiB, wall seconds, pids and /tmp MiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Max {
    pub mem_mb: u64,
    pub wall_s: u64,
    pub pids: u64,
    pub tmp_mb: u64,
}

#[derive(Debug)]
pub struct Worker {
    pub id: &'static str,
    /// argv[0] is the program execve'd; the rest are its arguments, exactly.
    pub argv: &'static [&'static str],
    /// The seccomp allowlist and bind set (profile.rs).
    pub profile: &'static str,
    pub max: Max,
}

pub const NODE: &str = "/usr/local/bin/node";

pub const WORKERS: &[Worker] = &[
    Worker {
        id: "image",
        argv: &[
            NODE,
            "--max-old-space-size=128",
            "--disallow-code-generation-from-strings",
            "/opt/media/worker/image.mjs",
        ],
        profile: "node-worker",
        max: Max {
            mem_mb: 256,
            wall_s: 10,
            pids: 64,
            tmp_mb: 16,
        },
    },
    Worker {
        id: "pdf",
        argv: &[
            NODE,
            "--max-old-space-size=256",
            "--disallow-code-generation-from-strings",
            "/opt/media/worker/pdf.mjs",
        ],
        profile: "node-worker",
        max: Max {
            mem_mb: 384,
            wall_s: 20,
            pids: 64,
            tmp_mb: 16,
        },
    },
    Worker {
        id: "office",
        argv: &[
            NODE,
            "--max-old-space-size=256",
            "--disallow-code-generation-from-strings",
            "--no-addons",
            "/opt/media/worker/office.mjs",
        ],
        profile: "node-worker",
        max: Max {
            mem_mb: 384,
            wall_s: 15,
            pids: 64,
            tmp_mb: 16,
        },
    },
];

pub fn find(id: &str) -> Option<&'static Worker> {
    WORKERS.iter().find(|w| w.id == id)
}

/// What `media-jail --table` prints: {"workers":{"<id>":{"argv":[…],
/// "profile":"node-worker","max":{"mem_mb":…,"wall_s":…,"pids":…,"tmp_mb":…}}}}.
pub fn table() -> Val {
    let rows = WORKERS
        .iter()
        .map(|w| {
            let max = Val::Obj(vec![
                ("mem_mb".into(), Val::Int(w.max.mem_mb as i64)),
                ("wall_s".into(), Val::Int(w.max.wall_s as i64)),
                ("pids".into(), Val::Int(w.max.pids as i64)),
                ("tmp_mb".into(), Val::Int(w.max.tmp_mb as i64)),
            ]);
            let row = Val::Obj(vec![
                (
                    "argv".into(),
                    Val::Arr(w.argv.iter().map(|a| Val::s(*a)).collect()),
                ),
                ("profile".into(), Val::s(w.profile)),
                ("max".into(), max),
            ]);
            (w.id.to_string(), row)
        })
        .collect();
    Val::Obj(vec![("workers".into(), Val::Obj(rows))])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;

    #[test]
    fn the_table_is_section_16_8() {
        let got: Vec<(&str, Max)> = WORKERS.iter().map(|w| (w.id, w.max)).collect();
        assert_eq!(
            got,
            vec![
                (
                    "image",
                    Max {
                        mem_mb: 256,
                        wall_s: 10,
                        pids: 64,
                        tmp_mb: 16
                    }
                ),
                (
                    "pdf",
                    Max {
                        mem_mb: 384,
                        wall_s: 20,
                        pids: 64,
                        tmp_mb: 16
                    }
                ),
                (
                    "office",
                    Max {
                        mem_mb: 384,
                        wall_s: 15,
                        pids: 64,
                        tmp_mb: 16
                    }
                ),
            ]
        );
    }

    #[test]
    fn every_row_runs_node_on_its_own_worker_under_a_known_profile() {
        for w in WORKERS {
            assert_eq!(w.argv[0], NODE);
            assert_eq!(
                *w.argv.last().unwrap(),
                format!("/opt/media/worker/{}.mjs", w.id)
            );
            assert!(w.argv.contains(&"--disallow-code-generation-from-strings"));
            assert!(profile::load(w.profile).is_ok(), "{} has no profile", w.id);
            assert!(profile::binds(w.profile).unwrap().contains(&"/opt/media"));
        }
        assert!(find("office").unwrap().argv.contains(&"--no-addons"));
        assert!(find("ffmpeg").is_none() && find("whisper").is_none() && find("").is_none());
    }

    #[test]
    fn table_json_is_the_documented_shape() {
        let text = table().to_string();
        assert!(text.starts_with(
            r#"{"workers":{"image":{"argv":["/usr/local/bin/node","--max-old-space-size=128","#
        ));
        assert!(text.contains(r#""office":{"argv":["/usr/local/bin/node","--max-old-space-size=256","--disallow-code-generation-from-strings","--no-addons","/opt/media/worker/office.mjs"],"profile":"node-worker","max":{"mem_mb":384,"wall_s":15,"pids":64,"tmp_mb":16}}"#));
    }
}
