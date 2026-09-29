#!/usr/bin/env python3
"""Parent side of the A1 probe's document timings (deploy/enclave/probe). The
probe enclave's reader stand-in (reader-bench.mjs) builds each document,
encrypts it as WhatsApp does, and PUTs the ciphertext here; then it opens the
attachment end to end, and the reader's fetch reads it back from here, so the
bytes cross vsock and the enclave's socat bridge as an archive answer does in
production. probe.sh runs it on the parent (AL2023) before the enclave boots.

    vsock-serve.py <port> [lifetime-seconds]

HTTP/1.1 over AF_VSOCK, on any CID: PUT, GET and DELETE of /objects/<name>,
<name> 1 to 64 lowercase hex characters. It holds at most 8 objects and
256 MiB in memory, each at most 64 MiB, and exits after its lifetime (3,600 s
by default) if nobody stops it first. One line per request on stdout: the
method, the name, the bytes and the milliseconds. The port is the probe's
9101, which does not collide with production (5443-5445, 7000-7002,
8000-8002, 9000) or the throughput probe (9100)."""
import http.server
import re
import socket
import socketserver
import sys
import threading
import time

MIB = 1024 * 1024
MAX_OBJECT = 64 * MIB
MAX_TOTAL = 256 * MIB
MAX_OBJECTS = 8
NAME = re.compile(r"^/objects/([0-9a-f]{1,64})$")


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.objects = {}

    def put(self, name, data):
        with self.lock:
            others = {k: v for k, v in self.objects.items() if k != name}
            if len(others) >= MAX_OBJECTS or sum(map(len, others.values())) + len(data) > MAX_TOTAL:
                return False
            self.objects[name] = data
            return True

    def get(self, name):
        with self.lock:
            return self.objects.get(name)

    def delete(self, name):
        with self.lock:
            return self.objects.pop(name, None) is not None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    store = None

    def log_message(self, fmt, *args):
        pass

    def note(self, name, size, started):
        print(f"{self.command} {name} {size} {round((time.monotonic() - started) * 1000)}ms", flush=True)

    def answer(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def named(self):
        m = NAME.match(self.path)
        if not m:
            # A body left unread would be taken for the next request.
            self.close_connection = True
            self.answer(404)
        return m and m.group(1)

    def do_PUT(self):
        started = time.monotonic()
        name = self.named()
        if not name:
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_OBJECT:
            self.close_connection = True
            return self.answer(413)
        data = self.rfile.read(length)
        if len(data) != length:
            self.close_connection = True
            return self.answer(400)
        if not self.store.put(name, data):
            return self.answer(507)
        self.answer(201)
        self.note(name, length, started)

    def do_GET(self):
        started = time.monotonic()
        name = self.named()
        if not name:
            return
        data = self.store.get(name)
        if data is None:
            return self.answer(404)
        self.answer(200, data)
        self.note(name, len(data), started)

    def do_DELETE(self):
        name = self.named()
        if name:
            self.answer(204 if self.store.delete(name) else 404)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer's own server_bind looks the host name up, which an
        # AF_VSOCK address (a CID) does not have.
        socketserver.TCPServer.server_bind(self)
        vsock = self.address_family == getattr(socket, "AF_VSOCK", None)
        self.server_name = "vsock" if vsock else str(self.server_address[0])
        self.server_port = self.server_address[1]


def make_server(family, address, store=None):
    """The object server on `family` at `address`; the tests use AF_INET."""
    handler = type("BoundHandler", (Handler,), {"store": store or Store()})
    server_class = type("BoundServer", (Server,), {"address_family": family})
    return server_class(address, handler)


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: vsock-serve.py <port> [lifetime-seconds]", file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    lifetime = float(sys.argv[2]) if len(sys.argv) == 3 else 3600.0
    server = make_server(socket.AF_VSOCK, (socket.VMADDR_CID_ANY, port))
    timer = threading.Timer(lifetime, server.shutdown)
    timer.daemon = True
    timer.start()
    print(f"serving vsock port {port} for {lifetime:.0f}s", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
