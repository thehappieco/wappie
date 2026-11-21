"""Unit tests for the clock probe's parent side (deploy/enclave/clockprobe):
control.py's requests against a fake system, and assemble.py on a made-up
console. Nothing here touches a clock, a unit or a socket."""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


control = load("clockprobe_control", "control.py")
assemble = load("clockprobe_assemble", "assemble.py")


class FakeHolder:
    def __init__(self):
        self.started = self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.steps = []
        self.holders = []
        self.fail = set()
        self.listening = None

    def run(self, argv, timeout=60):
        self.calls.append(argv)
        return (1, "nope") if tuple(argv) in self.fail else (0, "")

    def step_clock(self, delta_ns):
        self.steps.append(delta_ns)

    def holder(self):
        h = FakeHolder()
        self.holders.append(h)
        return h

    def kms_listening(self, unit):
        return next(self.listening) if self.listening is not None else True

    def sleep(self, s):
        pass


def make(*extra):
    args = control.parse(["--run", "main", "--log", "/dev/null", "--kms-unit", "kms-proxy", *extra])
    system = FakeSystem()
    return control.Control(args, system=system), system


class ControlTest(unittest.TestCase):
    def test_hello_names_the_run_and_its_settings(self):
        c, _ = make("--s5-s", "60", "--scenarios", "S1,S5")
        a = c.handle("hello")
        self.assertTrue(a["ok"])
        self.assertEqual((a["run"], a["s5_s"], a["scenarios"]), ("main", 60, "S1,S5"))
        self.assertEqual(a["parent_real_ns"] - a["shift_ns"], a["parent_true_ns"])

    def test_kms_blocking_needs_its_flag(self):
        c, s = make()
        self.assertFalse(c.handle("kms block refuse")["ok"])
        self.assertEqual(s.calls, [])

    def test_refuse_stops_the_unit_and_unblock_starts_it(self):
        c, s = make("--allow-kms-block")
        self.assertTrue(c.handle("kms block refuse")["ok"])
        self.assertEqual(s.calls, [["systemctl", "stop", "kms-proxy"]])
        self.assertEqual(s.holders, [])
        self.assertTrue(c.handle("kms unblock")["ok"])
        self.assertEqual(s.calls[1:], [["systemctl", "reset-failed", "kms-proxy"], ["systemctl", "start", "kms-proxy"]])

    def test_unblock_retries_until_the_proxy_listens_twice(self):
        c, s = make("--allow-kms-block")
        c.handle("kms block hold")
        # try 1: not listening; try 2: listening then gone (a crash loop); try 3: listening twice
        s.listening = iter([False, True, False, True, True])
        self.assertTrue(c.handle("kms unblock")["ok"])
        self.assertEqual(sum(1 for a in s.calls if a[:2] == ["systemctl", "start"]), 3)
        self.assertEqual(sum(1 for a in s.calls if a[:2] == ["systemctl", "reset-failed"]), 3)
        self.assertFalse(c.kms_blocked)

    def test_unblock_reports_a_unit_that_never_comes_back(self):
        c, s = make("--allow-kms-block")
        c.handle("kms block refuse")
        s.fail.add(("systemctl", "start", "kms-proxy"))
        a = c.handle("kms unblock")
        self.assertFalse(a["ok"])
        self.assertIn("does not listen", a["error"])
        self.assertEqual(sum(1 for x in s.calls if x[:2] == ["systemctl", "start"]), control.UNBLOCK_TRIES)


class HolderTest(unittest.TestCase):
    def free_port(self):
        import socket
        p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p.bind(("127.0.0.1", 0))
        port = p.getsockname()[1]
        p.close()
        return port

    def test_stop_frees_the_port_with_a_connection_held(self):
        import socket
        import struct
        port = self.free_port()
        h = control.Holder(port=port, family=socket.AF_INET, host="127.0.0.1")
        h.start()
        self.assertTrue(h.alive())
        held = socket.create_connection(("127.0.0.1", port), timeout=2)
        held.settimeout(0.5)
        with self.assertRaises(socket.timeout):
            held.recv(1)  # held: no answer, no close
        # Reset it from the client side, so TCP leaves no TIME_WAIT on the
        # port (vsock has none): only a listener still bound can refuse the
        # bind below.
        held.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        held.close()
        proc = h.proc
        h.stop()
        self.assertIsNotNone(proc.poll())
        again = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        again.bind(("127.0.0.1", port))  # the proxy's bind
        again.listen(1)
        again.close()

    def test_a_port_in_use_is_an_error(self):
        import socket
        port = self.free_port()
        busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy.bind(("127.0.0.1", port))
        busy.listen(1)
        try:
            with self.assertRaises(OSError):
                control.Holder(port=port, family=socket.AF_INET, host="127.0.0.1").start()
        finally:
            busy.close()




def record(seq, section, data):
    body = json.dumps({"section": section, "t": 1.0, "data": data})
    return f"CPR {seq} {len(body.encode())} {body}", body


class AssembleTest(unittest.TestCase):
    def console(self, end=True, dump=True, split=False):
        recs = [
            record(0, "run", {"run": "main"}),
            record(1, "scenario", {"id": "S1", "pass": True, "checks": [{"name": "one_step", "pass": True}]}),
            record(2, "scenario", {"id": "S3", "pass": False, "checks": [{"name": "no_step", "pass": False}, {"name": "x", "pass": True}]}),
            record(3, "done", {"run": "main"}),
        ]
        lines = ["===WAPPIE-CLOCKPROBE-BEGIN===", "CP STEP 1 t=0.5 entrypoint"]
        for i, (line, _) in enumerate(recs):
            if split and i == 1:
                cut = len(line) // 2
                lines += [line[:cut] + "[   12.345678] kernel says hello", line[cut:]]
            else:
                lines.append(line)
        if dump:
            lines.append("CP FILE /run/clockprobe/report.jsonl BEGIN")
            lines += [body for _, body in recs]
            lines.append("CP FILE /run/clockprobe/report.jsonl END")
        if end:
            lines.append("===WAPPIE-CLOCKPROBE-END===")
        return "\n".join(lines) + "\n"

    def test_a_complete_console(self):
        r = assemble.assemble(self.console())
        self.assertTrue(r["complete"])
        self.assertEqual(r["run"], "main")
        self.assertEqual(sorted(r["scenarios"]), ["S1", "S3"])
        self.assertEqual(assemble.failed(r["scenarios"]["S3"]), ["no_step"])
        self.assertEqual(r["missing_seqs"], [])

    def test_a_split_record_is_repaired(self):
        r = assemble.assemble(self.console(dump=False, split=True))
        self.assertIn("S1", r["scenarios"])
        self.assertEqual(r["broken_lines"], 0)

    def test_the_dump_fills_a_lost_record(self):
        text = self.console().replace(record(1, "scenario", {"id": "S1", "pass": True, "checks": [{"name": "one_step", "pass": True}]})[0] + "\n", "")
        r = assemble.assemble(text)
        self.assertIn("S1", r["scenarios"])

    def test_without_the_end_marker_it_is_partial(self):
        self.assertFalse(assemble.assemble(self.console(end=False))["complete"])

    def test_summary_over_runs(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            c = d / "console.log"
            c.write_text(self.console())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(assemble.one(c, d / "main"), 0)
                self.assertEqual(assemble.summary(d), 1)
            result = json.loads((d / "results.json").read_text())
            self.assertEqual(result["scenarios"]["S3"]["failed"], ["no_step"])
            self.assertTrue(result["any_failed"])
            self.assertIn("S8", result["missing"])


if __name__ == "__main__":
    unittest.main()
