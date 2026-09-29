"""Tests for assemble-report.py, the parent side of the streamed probe report:
python3 -m unittest discover -s deploy/enclave/probe -p 'test_*.py'"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("assemble_report", HERE / "assemble-report.py")
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)


def record(seq, section, data, t=1.0):
    body = json.dumps({"section": section, "t": t, "data": data}, separators=(",", ":"))
    return f"A1R {seq} {len(body.encode())} {body}"


# The first Nitro run's two kernel lines for one SIGILL, trimmed.
SIGILL = [
    "[    0.326174] Bad EL0 synchronous exception detected on CPU0, code 0x66000000 -- UNRECOGNIZED EC",
    "[    0.326672] CPU: 0 PID: 570 Comm: node Tainted: G           OE   4.14.256-209.484.amzn2.aarch64 #1",
    "[    0.327735] pc : 0x5573db8e48",
]


# The runner's go parts for a run whose seccomp-killed corpus PDF was a
# worker's kill: the jail check fails, and so does the kernel log's part.
PARTS = {"jail_check": False, "media_e2e": True, "reader_bench": True, "no_worker_seccomp_kills": False}


def console(*lines):
    return "\r\n".join(lines) + "\r\n"


class AssembleTest(unittest.TestCase):
    def full_run(self):
        return [
            "Connecting to the console for enclave 30...",
            ar.BEGIN,
            "A1 STEP 1 t=0.33 entrypoint: pid 560",
            "A1 PID 570 runner: node /probe/probe-report.mjs",
            *SIGILL,
            record(1, "begin", {"pid": 570}),
            record(2, "meta", {"node": "v22.23.3"}),
            record(3, "spawn", {"pid": 617, "argv": ["/usr/local/bin/node", "/opt/jailcheck/jail-check.mjs"]}),
            record(4, "jail_result", {"pass": True, "name": "escape: nsm", "detail": {}}),
            record(5, "jail_result", {"pass": False, "name": "corpus pdf: pdf-1gb-stream", "detail": {"outcome": "seccomp"}}),
            record(6, "jail_check", {"go": False, "failed": ["corpus pdf: pdf-1gb-stream"]}),
            record(7, "bench", {"phase": "document", "name": "pdf-32mib", "ms": 4200, "outcome": "complete"}),
            record(8, "kernel_log", {"worker_seccomp_kills": [{"pid": 640, "comm": "node", "syscall": 441}]}),
            record(9, "done", {"fatal_errors": 0, "go": False, "parts": PARTS}),
            "A1 EXIT 570 runner: exit 0",
            ar.END,
        ]

    def test_a_whole_run_is_complete(self):
        report, ordered = ar.assemble(console(*self.full_run()))
        self.assertTrue(report["complete"])
        self.assertEqual(report["records"], 9)
        self.assertEqual(report["missing_seqs"], [])
        self.assertEqual(
            [r["section"] for r in ordered],
            ["begin", "meta", "spawn", "jail_result", "jail_result", "jail_check", "bench", "kernel_log", "done"],
        )
        self.assertEqual(len(report["sections"]["jail_result"]), 2)
        self.assertEqual(report["sections"]["bench"][0]["data"]["name"], "pdf-32mib")
        self.assertEqual(len(report["sections"]["spawn"]), 1)

    def test_the_verdict_names_what_failed(self):
        report, _ = ar.assemble(console(*self.full_run()))
        self.assertEqual(
            report["verdict"],
            {
                "go": False,
                "parts": PARTS,
                "jail_checks": 2,
                "jail_failed": ["corpus pdf: pdf-1gb-stream"],
            },
        )

    def test_a_record_split_by_kernel_lines_is_put_back_together(self):
        whole = record(2, "meta", {"node": "v22.23.3", "hwcaps": {"sve": False}})
        cut = len(whole) // 2
        broken = [whole[:cut] + SIGILL[0], SIGILL[1], SIGILL[2], whole[cut:]]
        report, _ = ar.assemble(console(ar.BEGIN, *broken, ar.END))
        self.assertEqual(report["sections"]["meta"]["data"]["hwcaps"], {"sve": False})
        self.assertEqual(report["broken_record_lines"], 0)
        # The kernel lines are still read as a SIGILL report.
        self.assertEqual(report["console_sigills"][0]["pid"], 570)

    def test_the_final_dump_replaces_a_copy_broken_beyond_repair(self):
        whole = record(2, "meta", {"node": "v22.23.3"})
        report, _ = ar.assemble(
            console(ar.BEGIN, whole[:20], "A1 FILE /run/probe/report.jsonl BEGIN", whole, ar.END)
        )
        self.assertEqual(report["sections"]["meta"]["data"], {"node": "v22.23.3"})
        self.assertEqual(report["records"], 1)

    def test_duplicates_count_once(self):
        lines = self.full_run()
        report, ordered = ar.assemble(console(*lines, *[l for l in lines if l.startswith("A1R ")]))
        self.assertEqual(report["records"], 9)
        self.assertEqual(len(ordered), 9)
        self.assertEqual(len(report["sections"]["spawn"]), 1)

    def test_a_run_that_died_is_partial_but_keeps_its_sections(self):
        lines = self.full_run()[:10]  # through the spawn record, no END
        report, _ = ar.assemble(console(*lines))
        self.assertFalse(report["complete"])
        self.assertFalse(report["end_marker"])
        self.assertEqual(report["last_section"], "spawn")
        self.assertIn("meta", report["sections"])

    def test_sigills_are_traced_to_the_process_that_raised_them(self):
        report, _ = ar.assemble(console(*self.full_run()))
        ev = report["console_sigills"][0]
        self.assertEqual((ev["pid"], ev["comm"], ev["esr"]), (570, "node", "0x66000000"))
        self.assertEqual(ev["pc_page_offset"], "0xe48")
        self.assertEqual(ev["source"], "entrypoint runner: node /probe/probe-report.mjs")

    def test_back_to_back_sigills_keep_their_own_pids(self):
        second = [
            SIGILL[0].replace("0.326174", "1.204874"),
            "[    1.206909] CPU: 0 PID: 617 Comm: node Tainted: G           OE   4.14.256-209.484.amzn2.aarch64 #1",
            "[    1.211085] pc : 0x5567ef4e48",
        ]
        # The first dump cut short: its PID line comes after the second event.
        report, _ = ar.assemble(console(SIGILL[0], *second))
        self.assertEqual([e["pid"] for e in report["console_sigills"]], [None, 617])

    def test_the_first_nitro_console_yields_no_record(self):
        # 2026-09-28: kernel lines only.
        report, _ = ar.assemble(console("Connecting to the console for enclave 30...", *SIGILL))
        self.assertEqual(report["records"], 0)
        self.assertFalse(report["begin_marker"])
        self.assertEqual(len(report["console_sigills"]), 1)

    def test_cli_writes_both_files_and_exits_by_completeness(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d)
            (out / "console.log").write_text(console(*self.full_run()))
            done = subprocess.run(
                [sys.executable, str(HERE / "assemble-report.py"), str(out / "console.log"), str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn("complete", done.stdout)
            self.assertIn("go=False", done.stdout)
            self.assertIn("failed: corpus pdf: pdf-1gb-stream", done.stdout)
            self.assertIn('"no_worker_seccomp_kills": false', done.stdout)
            self.assertEqual(len((out / "report.jsonl").read_text().splitlines()), 9)
            self.assertTrue(json.loads((out / "report.json").read_text())["complete"])

            (out / "console.log").write_text(console(*self.full_run()[:10]))
            partial = subprocess.run(
                [sys.executable, str(HERE / "assemble-report.py"), str(out / "console.log"), str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(partial.returncode, 2, partial.stdout + partial.stderr)
            self.assertIn("PARTIAL", partial.stdout)


if __name__ == "__main__":
    unittest.main()
