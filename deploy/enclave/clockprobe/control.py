#!/usr/bin/env python3
"""The parent's side of the clock probe (deploy/enclave/clockprobe): the
control server the probe enclave asks to act as a hostile parent.
clockprobe.sh starts it, as root, before each probe enclave boots, and stops
it after. NEVER part of production.

    control.py --run main|s8|s9boot --log <file> [--port 9103] [--cid 30]
               [--kms-unit <unit>] [--chrony-unit chronyd]
               [--shift-at-start <s>] [--block-at-start refuse|hold]
               [--s5-s N] [--s6-s N] [--scenarios A,B] [--allow-parent-clock]
               [--allow-kms-block] [--lifetime <s>] [--ready-file <file>]

One request line in, one JSON line out, over AF_VSOCK, from the probe's CID
only. The requests are a fixed list:

    hello                  which run this is, its settings, the parent's clocks
    time                   the parent's clocks
    kms block refuse       stop the KMS vsock-proxy unit: connections to vsock
                           8000 are refused
    kms block hold         stop it and listen on vsock 8000 here, accepting
                           connections and never answering
    kms unblock            stop holding and start the unit again
    parent shift <s>       stop the parent's chronyd and step its clock by <s>
    parent restore         start chronyd again and step the clock back to it
    done                   the run is over

The parent's clocks: parent_real_ns is CLOCK_REALTIME now; shift_ns is how
far it has been moved since this server started (measured as the change in
REALTIME - MONOTONIC, which no slewing chronyd touches while it is stopped);
parent_true_ns is parent_real_ns - shift_ns. Whatever it changed is put
back when it exits (the KMS unit started, chronyd started and stepped),
and clockprobe.sh's EXIT trap does the same again in case it was killed.

The port is 9103: production uses 5443-5445, 7000-7002, 8000-8007 and 9000;
the A1 probe 9100 and 9101."""
import argparse
import json
import signal
import socket
import subprocess
import sys
import threading
import time

PORT = 9103
KMS_PORT = 8000
PROBE_CID = 30
VMADDR_CID_ANY = 0xFFFFFFFF
UNBLOCK_TRIES = 5


def offset_ns():
    """CLOCK_REALTIME - CLOCK_MONOTONIC: what a step of the clock moves."""
    return time.time_ns() - time.monotonic_ns()


# The holder runs in a child process. A listener closed from Python while a
# thread is blocked in accept() on it stays bound on AF_VSOCK (shutdown() does
# not wake it there), so the KMS proxy could not bind vsock 8000 again until
# the control server exited (probe runs 20261121T000250Z and T023345Z).
# Killing the child frees its listener and every held connection.
HOLD_CODE = r"""
import socket, sys
family, port, host = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket(family, socket.SOCK_STREAM)
s.bind((int(host), port) if family == getattr(socket, "AF_VSOCK", -1) else (host, port))
s.listen(64)
print("listening", flush=True)
held = []
while True:
    c, _ = s.accept()
    held.append(c)
"""


class Holder:
    """Listens on vsock 8000 and holds every connection open, silent: KMS
    neither answers nor refuses."""

    def __init__(self, port=KMS_PORT, family=None, host=None):
        self.port = port
        self.family = family if family is not None else getattr(socket, "AF_VSOCK", None)
        self.host = host if host is not None else str(VMADDR_CID_ANY)
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([sys.executable, "-c", HOLD_CODE, str(int(self.family)), str(self.port), self.host],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline().strip()
        if line != "listening":
            self.stop()
            raise OSError(f"the holder did not listen on {self.port}: {line or 'no answer'}")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc is None:
            return
        try:
            self.proc.kill()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for f in (self.proc.stdout, self.proc.stderr):
            try:
                f.close()
            except (OSError, AttributeError):
                pass
        self.proc = None


class System:
    """What the server does to the parent. Replaced by a fake in the tests."""

    def run(self, argv, timeout=60):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout + p.stderr).strip()[-500:]
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, str(e)

    def step_clock(self, delta_ns):
        now = time.clock_gettime_ns(time.CLOCK_REALTIME)
        time.clock_settime_ns(time.CLOCK_REALTIME, now + delta_ns)

    def holder(self):
        return Holder()

    def kms_listening(self, unit):
        """The unit's own main process listens on vsock 8000 (from ss)."""
        rc, pid = self.run(["systemctl", "show", "-p", "MainPID", "--value", unit])
        if rc != 0 or not pid.strip().isdigit() or pid.strip() == "0":
            return False
        rc, out = self.run(["ss", "-Hlp", "--vsock"])
        return rc == 0 and any(f":{KMS_PORT} " in line and f"pid={pid.strip()}," in line for line in out.splitlines())

    def sleep(self, s):
        time.sleep(s)


class Control:
    def __init__(self, args, system=None, log=None):
        self.args = args
        self.sys = system or System()
        self.log = log or (lambda line: None)
        self.base = offset_ns()
        self.shifted = False
        self.kms_blocked = False
        self.holder = None
        self.done = False

    # -- the parent's clocks
    def clocks(self):
        shift = offset_ns() - self.base
        real = time.time_ns()
        return {"parent_real_ns": real, "shift_ns": shift, "parent_true_ns": real - shift}

    # -- KMS
    def kms_block(self, how):
        if not self.args.allow_kms_block:
            return {"ok": False, "error": "kms blocking not allowed on this parent (--allow-kms-block)"}
        if how not in ("refuse", "hold"):
            return {"ok": False, "error": "refuse or hold"}
        if self.holder is not None:
            self.holder.stop()
            self.holder = None
        rc, out = (0, "") if not self.args.kms_unit else self.sys.run(["systemctl", "stop", self.args.kms_unit])
        if rc != 0:
            return {"ok": False, "error": f"systemctl stop {self.args.kms_unit}: {out}"}
        self.kms_blocked = True
        if how == "hold":
            self.sys.sleep(1)
            try:
                self.holder = self.sys.holder()
                self.holder.start()
            except OSError as e:
                return {"ok": False, "error": f"hold vsock {KMS_PORT}: {e}"}
        return {"ok": True, "how": how}

    def kms_unblock(self):
        if self.holder is not None:
            self.holder.stop()
            self.holder = None
        if self.kms_blocked and self.args.kms_unit:
            # A start that fails to bind counts against the unit's start
            # limit: clear it and start again until the unit's own process
            # listens on vsock 8000 on two looks a second apart (a unit that
            # crash-loops is "active" for an instant), else report the
            # unblock as failed rather than leave KMS down for the run.
            unit = self.args.kms_unit
            for attempt in range(UNBLOCK_TRIES):
                self.sys.sleep(1)
                self.sys.run(["systemctl", "reset-failed", unit])
                rc, out = self.sys.run(["systemctl", "start", unit])
                self.sys.sleep(2)
                if rc == 0 and self.sys.kms_listening(unit):
                    self.sys.sleep(1)
                    if self.sys.kms_listening(unit):
                        break
            else:
                return {"ok": False, "error": f"{unit} does not listen on vsock {KMS_PORT} after {UNBLOCK_TRIES} tries"}
        self.kms_blocked = False
        return {"ok": True}

    # -- the parent's clock
    def parent_shift(self, seconds):
        if not self.args.allow_parent_clock:
            return {"ok": False, "error": "moving the parent's clock is not allowed on this parent (--allow-parent-clock)"}
        if not -600 <= seconds <= 600:
            return {"ok": False, "error": "at most 600 s"}
        rc, out = self.sys.run(["systemctl", "stop", self.args.chrony_unit])
        if rc != 0:
            return {"ok": False, "error": f"systemctl stop {self.args.chrony_unit}: {out}"}
        self.shifted = True
        self.sys.step_clock(int(seconds * 1e9))
        return {"ok": True, **self.clocks()}

    def parent_restore(self):
        if not self.shifted:
            return {"ok": True, "already": True, **self.clocks()}
        # Step straight back by the measured shift, then let chronyd take over
        # (and step again with makestep if the first step missed).
        self.sys.step_clock(-(offset_ns() - self.base))
        rc, out = self.sys.run(["systemctl", "start", self.args.chrony_unit])
        if rc != 0:
            return {"ok": False, "error": f"systemctl start {self.args.chrony_unit}: {out}"}
        self.sys.sleep(5)
        self.sys.run(["chronyc", "-a", "makestep"], timeout=20)
        self.shifted = False
        return {"ok": True, **self.clocks()}

    def hello(self):
        a = self.args
        return {
            "ok": True, "run": a.run, "s5_s": a.s5_s, "s6_s": a.s6_s, "scenarios": a.scenarios,
            "kms_blocked": self.kms_blocked, "parent_shifted": self.shifted, **self.clocks(),
        }

    def handle(self, line):
        words = line.strip().split()
        try:
            if words == ["hello"]:
                answer = self.hello()
            elif words == ["time"]:
                answer = {"ok": True, **self.clocks()}
            elif words[:2] == ["kms", "block"] and len(words) == 3:
                answer = self.kms_block(words[2])
            elif words == ["kms", "unblock"]:
                answer = self.kms_unblock()
            elif words[:2] == ["parent", "shift"] and len(words) == 3:
                answer = self.parent_shift(float(words[2]))
            elif words == ["parent", "restore"]:
                answer = self.parent_restore()
            elif words == ["done"]:
                self.done = True
                answer = {"ok": True}
            else:
                answer = {"ok": False, "error": "unknown request"}
        except (ValueError, IndexError) as e:
            answer = {"ok": False, "error": str(e)}
        self.log(json.dumps({"t": time.time(), "request": line.strip()[:80], "answer": answer}))
        return answer

    def cleanup(self):
        if self.holder is not None or self.kms_blocked:
            self.log(json.dumps({"t": time.time(), "cleanup": "kms unblock", "answer": self.kms_unblock()}))
        if self.shifted:
            self.log(json.dumps({"t": time.time(), "cleanup": "parent restore", "answer": self.parent_restore()}))


def serve(control, port, cid, lifetime, ready_file=None):
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((VMADDR_CID_ANY, port))
    srv.listen(4)
    srv.settimeout(5)
    if ready_file:
        with open(ready_file, "w") as f:
            f.write("ready\n")
    deadline = time.monotonic() + lifetime
    while time.monotonic() < deadline:
        try:
            conn, (peer, _) = srv.accept()
        except socket.timeout:
            continue
        with conn:
            if cid is not None and peer != cid:
                control.log(json.dumps({"t": time.time(), "refused_cid": peer}))
                continue
            conn.settimeout(10)
            data = b""
            try:
                while b"\n" not in data and len(data) < 256:
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                continue
            answer = control.handle(data.decode("utf-8", "replace").split("\n")[0])
            try:
                conn.sendall((json.dumps(answer) + "\n").encode())
            except OSError:
                pass
        if control.done:
            break
    srv.close()


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--run", required=True, choices=["main", "s8", "s9boot"])
    p.add_argument("--log", required=True)
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--cid", default=str(PROBE_CID), help="the probe's CID, or 'any'")
    p.add_argument("--kms-unit", default="")
    p.add_argument("--chrony-unit", default="chronyd")
    p.add_argument("--shift-at-start", type=float, default=0)
    p.add_argument("--block-at-start", choices=["refuse", "hold"], default=None)
    p.add_argument("--s5-s", type=int, default=1800)
    p.add_argument("--s6-s", type=int, default=3600)
    p.add_argument("--scenarios", default="")
    p.add_argument("--allow-parent-clock", action="store_true")
    p.add_argument("--allow-kms-block", action="store_true")
    p.add_argument("--lifetime", type=int, default=6 * 3600)
    p.add_argument("--ready-file", default=None)
    return p.parse_args(argv)


def main(argv):
    args = parse(argv)
    out = open(args.log, "a", buffering=1)
    control = Control(args, log=lambda line: out.write(line + "\n"))

    def stop(signum, frame):
        raise SystemExit(128 + signum)

    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, stop)
    try:
        if args.shift_at_start:
            r = control.parent_shift(args.shift_at_start)
            out.write(json.dumps({"t": time.time(), "start": "parent shift", "answer": r}) + "\n")
            if not r.get("ok"):
                return 1
        if args.block_at_start:
            r = control.kms_block(args.block_at_start)
            out.write(json.dumps({"t": time.time(), "start": "kms block", "answer": r}) + "\n")
            if not r.get("ok"):
                return 1
        serve(control, args.port, None if args.cid == "any" else int(args.cid), args.lifetime, args.ready_file)
    finally:
        control.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
