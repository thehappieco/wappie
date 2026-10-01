"""Tests for the measurements.json writer and the dependency manifest inside
build.sh (the rest needs an arm64 parent with nitro-cli):
python3 -m unittest discover -s deploy/enclave -p 'test_*.py'"""
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROLE = "arn:aws:iam::000000000000:role/ci"
PREVIOUS, THIS = "a" * 96, "b" * 96


def heredoc(marker):
    for body in re.findall(r"<<'PY'\n(.*?)\nPY\n", (HERE / "build.sh").read_text(), re.S):
        if marker in body:
            return body
    raise AssertionError(f"build.sh has no heredoc with {marker}")


def measurements_program():
    # The heredoc that writes measurements.json: the one that reads the PCRs.
    return heredoc('"measurements.json"')


def dependencies_program():
    return heredoc("REGISTRY")


MANIFEST = {"locks": [{"file": "packages/mcp-http/enclave/package-lock.json", "sha256": "0" * 64, "packages": []}], "tarballs": []}
TABLES = {"tested_clients": [{"id": "claude", "kind": "cimd", "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata", "name": "Claude",
                              "local": False, "profile": "claude.ai", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]}],
          "client_limits": {tier: {"calls_per_minute": 20} for tier in ("web_tested", "local_tested", "unknown", "token")}}


class MeasurementsTest(unittest.TestCase):
    def build(self, previous, policy_pcr0s=None, capabilities=None, manifest=MANIFEST, tables=None):
        out = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        blobs = out / "blobs"
        blobs.mkdir()
        (blobs / "bzImage").write_bytes(b"kernel")
        (out / "wappie-reader-0.2.0.eif").write_bytes(b"eif")
        (out / "build-enclave.json").write_text(json.dumps({"Measurements": {"PCR0": THIS, "PCR1": "c" * 96, "PCR2": "d" * 96}}))
        transition = policy_pcr0s or ([previous, THIS] if previous else [THIS])
        for phase, pcr0s in (("transition", transition), ("steady", [THIS])):
            args = [sys.executable, str(HERE / "kms/render.py"), str(HERE / "kms/reader-key-policy.template.json"), "--role-arn", ROLE]
            for value in pcr0s:
                args += ["--pcr0", value]
            (out / f"reader-key-policy.{phase}.json").write_text(subprocess.run(args, check=True, capture_output=True, text=True).stdout)
        constants = json.dumps({"version": "0.2.0", "reader_id": "enclave", "origin": "https://mcp.example", "region": "eu-west-1",
                                "reader_key_arn": "arn:r", "boot_key_arn": "arn:b", "capabilities": capabilities, **(tables or {})})
        (out / "dependencies.json").write_text(json.dumps(manifest))
        result = subprocess.run(
            [sys.executable, "-", str(out), "wappie-reader-0.2.0.eif", "0.2.0", "0" * 40, "", "node@sha256:x", "rust@sha256:y",
             "1.4.2", constants, "e" * 64, "f" * 64, previous, THIS, str(out / "dependencies.json")],
            input=measurements_program(), text=True, capture_output=True, env={**os.environ, "NITRO_CLI_BLOBS": str(blobs)})
        if result.returncode:
            return result.stderr
        return json.loads((out / "measurements.json").read_text())

    def test_transition_pins_previous_and_this(self):
        policies = self.build(PREVIOUS)["policies"]
        self.assertEqual([p["phase"] for p in policies], ["transition", "steady"])
        self.assertEqual(policies[0]["pins_pcr0"], [PREVIOUS, THIS])
        self.assertEqual(policies[1]["pins_pcr0"], [THIS])
        self.assertEqual(policies[0]["sha256"], "e" * 64)

    def test_first_release_pins_this_only(self):
        policies = self.build("")["policies"]
        self.assertEqual(policies[0]["pins_pcr0"], [THIS])
        self.assertEqual(policies[1]["pins_pcr0"], [THIS])

    def test_rebuild_of_the_same_image_pins_it_once(self):
        # render.py drops the duplicate, so the policy pins one value.
        self.assertEqual(self.build(THIS)["policies"][0]["pins_pcr0"], [THIS])

    def test_refuses_a_policy_that_pins_something_else(self):
        error = self.build(PREVIOUS, policy_pcr0s=[THIS])
        self.assertIsInstance(error, str)
        self.assertIn("does not pin exactly", error)


    def test_capabilities_are_the_image_constant(self):
        self.assertEqual(self.build(PREVIOUS, capabilities=["consent_v2", "media"])["capabilities"], ["consent_v2", "media"])

    def test_a_reader_without_the_constant_declares_none(self):
        self.assertEqual(self.build(PREVIOUS, capabilities=None)["capabilities"], [])

    def test_refuses_malformed_capabilities(self):
        for bad in (["media", "media"], ["Media!"], "media", [1], [["media"]]):
            error = self.build(PREVIOUS, capabilities=bad)
            self.assertIsInstance(error, str, bad)
            self.assertIn("READER_CAPABILITIES", error)

    def test_any_client_release_carries_its_tested_clients_and_limits_unchanged(self):
        built = self.build(PREVIOUS, capabilities=["consent_v2", "any_client_v1"], tables=TABLES)
        self.assertEqual(built["tested_clients"], TABLES["tested_clients"])
        self.assertEqual(built["client_limits"], TABLES["client_limits"])

    def test_other_releases_carry_no_client_tables(self):
        built = self.build(PREVIOUS, capabilities=["consent_v2"])
        self.assertNotIn("tested_clients", built)
        self.assertNotIn("client_limits", built)
        error = self.build(PREVIOUS, capabilities=["consent_v2"], tables=TABLES)
        self.assertIsInstance(error, str)
        self.assertIn("without any_client_v1", error)

    def test_refuses_an_any_client_release_without_well_formed_tables(self):
        for tables in ({}, {"tested_clients": TABLES["tested_clients"]}, {**TABLES, "tested_clients": []},
                       {**TABLES, "tested_clients": TABLES["tested_clients"] * 2},
                       {**TABLES, "client_limits": {"unknown": {}}}):
            error = self.build(PREVIOUS, capabilities=["any_client_v1"], tables=tables)
            self.assertIsInstance(error, str, tables)

    def test_carries_the_dependency_manifest(self):
        self.assertEqual(self.build(PREVIOUS)["dependencies"], MANIFEST)


class DependenciesTest(unittest.TestCase):
    """The manifest step: both locks, and every tarball from outside the npm
    registry fetched and checked against the lock (file:// stands in for the
    CDN here; build.sh refuses anything but https)."""

    def run_step(self, worker_packages, allow_file_urls=True):
        context = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name, packages in (("packages/mcp-http/enclave/package-lock.json", {"": {}, "node_modules/asn1js": {
                "version": "3.0.10", "resolved": "https://registry.npmjs.org/asn1js/-/asn1js-3.0.10.tgz", "integrity": "sha512-x"}}),
                               ("packages/mcp-http/enclave/media/worker/package-lock.json", worker_packages)):
            (context / name).parent.mkdir(parents=True, exist_ok=True)
            (context / name).write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
        program = dependencies_program()
        if allow_file_urls:
            program = program.replace('url.startswith("https://")', '(url.startswith("https://") or url.startswith("file://"))')
        result = subprocess.run([sys.executable, "-", str(context), str(context / "out.json")], input=program, text=True,
                                capture_output=True)
        if result.returncode:
            return result.stderr
        return json.loads((context / "out.json").read_text())

    def tarball(self, data):
        path = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "xlsx-0.20.3.tgz"
        path.write_bytes(data)
        return path.as_uri(), "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    def test_records_both_locks_and_the_cdn_tarball(self):
        url, integrity = self.tarball(b"sheetjs")
        manifest = self.run_step({"": {}, "node_modules/xlsx": {"version": "0.20.3", "resolved": url, "integrity": integrity}})
        self.assertEqual([l["file"] for l in manifest["locks"]],
                         ["packages/mcp-http/enclave/package-lock.json", "packages/mcp-http/enclave/media/worker/package-lock.json"])
        self.assertEqual(manifest["locks"][0]["packages"][0]["path"], "node_modules/asn1js")
        self.assertEqual(manifest["tarballs"], [{"package": "xlsx", "version": "0.20.3", "url": url, "integrity": integrity,
                                                 "sha256": hashlib.sha256(b"sheetjs").hexdigest()}])

    def test_refuses_a_tarball_that_does_not_match_the_lock(self):
        url, _ = self.tarball(b"sheetjs")
        _, other = self.tarball(b"something else")
        error = self.run_step({"": {}, "node_modules/xlsx": {"version": "0.20.3", "resolved": url, "integrity": other}})
        self.assertIsInstance(error, str)
        self.assertIn("does not match", error)

    def test_refuses_a_tarball_without_https_or_integrity(self):
        url, _ = self.tarball(b"sheetjs")
        error = self.run_step({"": {}, "node_modules/xlsx": {"version": "0.20.3", "resolved": url}}, allow_file_urls=False)
        self.assertIsInstance(error, str)
        self.assertIn("without https and an integrity", error)

    def test_the_worker_lock_pins_sheetjs_by_integrity(self):
        lock = json.loads((HERE.parent.parent / "packages/mcp-http/enclave/media/worker/package-lock.json").read_text())
        entry = lock["packages"]["node_modules/xlsx"]
        self.assertEqual(entry["resolved"], "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz")
        self.assertTrue(entry["integrity"].startswith("sha512-"))
        outside = [p for p, e in lock["packages"].items() if p and not (e.get("resolved") or "").startswith("https://registry.npmjs.org/")]
        self.assertEqual(outside, ["node_modules/xlsx"])


if __name__ == "__main__":
    unittest.main()
