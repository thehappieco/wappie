#!/usr/bin/env python3
"""Parent side of the A0 vsock throughput probe (deploy/enclave/probe). Streams
16 MiB then 32 MiB to the probe enclave's vsock-sink, which times each transfer.
Run by probe.sh on the parent (AL2023) after the probe enclave boots; it retries
the connect until the sink is listening, since the runner starts the sink only
near the end of its sequence.

    vsock-send.py <enclave-cid> <port>

Uses AF_VSOCK directly (Linux 3.9+), so no socat on the parent. The port is the
probe's 9100, which does not collide with production (5443-5445, 7000-7002,
8000-8002, 9000)."""
import socket
import sys
import time

MIB = 1024 * 1024


def send_once(cid, port, total_bytes, connect_deadline):
    """Connect (retrying until connect_deadline) and stream total_bytes of
    zeros, then close so the sink sees EOF. Returns True on success."""
    chunk = b"\0" * MIB
    while time.time() < connect_deadline:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        try:
            s.connect((cid, port))
        except OSError:
            s.close()
            time.sleep(0.5)
            continue
        try:
            sent = 0
            while sent < total_bytes:
                n = min(len(chunk), total_bytes - sent)
                s.sendall(chunk[:n])
                sent += n
            return True
        finally:
            s.close()
    return False


def main():
    if len(sys.argv) != 3:
        print("usage: vsock-send.py <enclave-cid> <port>", file=sys.stderr)
        return 2
    cid = int(sys.argv[1])
    port = int(sys.argv[2])
    # The sink accepts two connections in order: 16 MiB then 32 MiB.
    deadline = time.time() + 180
    for label, size in (("16MiB", 16 * MIB), ("32MiB", 32 * MIB)):
        ok = send_once(cid, port, size, deadline)
        print(f"{label}: {'sent' if ok else 'FAILED (no listener)'}", flush=True)
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
