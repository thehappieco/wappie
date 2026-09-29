"""Tests for vsock-serve.py, the parent side of the probe's document timings,
over AF_INET on loopback (the same server class the parent runs on
AF_VSOCK): python3 -m unittest discover -s deploy/enclave/probe -p 'test_*.py'"""
import http.client
import importlib.util
import pathlib
import socket
import threading
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("vsock_serve", HERE / "vsock-serve.py")
vs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vs)


class VsockServeTest(unittest.TestCase):
    def setUp(self):
        self.server = vs.make_server(socket.AF_INET, ("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body)
            response = conn.getresponse()
            return response.status, response.read(), response.getheader("Content-Length")
        finally:
            conn.close()

    def test_an_object_goes_in_comes_back_whole_and_goes_away(self):
        data = bytes(range(256)) * 40_000
        self.assertEqual(self.request("PUT", "/objects/0123abcd", data)[0], 201)
        status, body, length = self.request("GET", "/objects/0123abcd")
        self.assertEqual((status, body, length), (200, data, str(len(data))))
        self.assertEqual(self.request("DELETE", "/objects/0123abcd")[0], 204)
        self.assertEqual(self.request("GET", "/objects/0123abcd")[0], 404)
        self.assertEqual(self.request("DELETE", "/objects/0123abcd")[0], 404)

    def test_names_are_short_lowercase_hex_under_objects(self):
        for path in ("/objects/", "/objects/ABCD", "/objects/../x", "/objects/" + "a" * 65, "/other/abcd", "/objects/ab/cd"):
            self.assertEqual(self.request("PUT", path, b"x")[0], 404, path)
            self.assertEqual(self.request("GET", path)[0], 404, path)

    def test_the_store_is_bounded(self):
        store = vs.Store()
        self.assertTrue(store.put("a", b"x" * 10))
        self.assertTrue(store.put("a", b"y" * 20), "a replacement is not a new object")
        for n in range(1, vs.MAX_OBJECTS):
            self.assertTrue(store.put(f"{n:x}0", b"z"))
        self.assertFalse(store.put("ff", b"z"), "one object past the count")
        with mock.patch.object(vs, "MAX_TOTAL", 100):
            store = vs.Store()
            for n in range(4):
                self.assertTrue(store.put(f"{n}", bytes(25)))
            self.assertFalse(store.put("9", b"z"), "one byte past the total")
            self.assertTrue(store.delete("0"))
            self.assertTrue(store.put("9", b"z"))

    def test_an_object_past_its_cap_is_refused_before_it_is_read(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest("PUT", "/objects/abcd")
            conn.putheader("Content-Length", str(vs.MAX_OBJECT + 1))
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, 413)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
