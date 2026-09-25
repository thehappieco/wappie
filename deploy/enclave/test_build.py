"""Tests for the measurements.json writer inside build.sh (the rest needs an
arm64 parent with nitro-cli): python3 -m unittest discover -s deploy/enclave -p 'test_*.py'"""
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


def measurements_program():
    # The heredoc that writes measurements.json: the one that reads the PCRs.
    for body in re.findall(r"<<'PY'\n(.*?)\nPY\n", (HERE / "build.sh").read_text(), re.S):
        if '"measurements.json"' in body:
            return body
    raise AssertionError("build.sh has no measurements.json writer")


class MeasurementsTest(unittest.TestCase):
    def build(self, previous, policy_pcr0s=None):
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
                                "reader_key_arn": "arn:r", "boot_key_arn": "arn:b"})
        result = subprocess.run(
            [sys.executable, "-", str(out), "wappie-reader-0.2.0.eif", "0.2.0", "0" * 40, "", "node@sha256:x", "rust@sha256:y",
             "1.4.2", constants, "e" * 64, "f" * 64, previous, THIS],
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


if __name__ == "__main__":
    unittest.main()
