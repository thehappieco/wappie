"""Tests for render.py and the two key policy templates:
python3 -m unittest discover -s deploy/enclave/kms"""
import importlib.util
import io
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("render", HERE / "render.py")
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)

ROLE = "arn:aws:iam::000000000000:role/ci"
ROOT = "arn:aws:iam::000000000000:root"
SSO = "arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_Owner_0123456789abcdef"
PCR_A, PCR_B = "a" * 96, "b" * 96
ADMIN = {"kms:CancelKeyDeletion", "kms:DisableKey", "kms:EnableKey", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"}
TEMPLATES = {name: HERE / f"{name}-key-policy.template.json" for name in ("reader", "boot")}


def rendered(name, *args):
    out = io.StringIO()
    render.main([str(TEMPLATES[name]), "--role-arn", ROLE, *args], out=out)
    return json.loads(out.getvalue())


def statements(policy):
    return {s["Sid"]: s for s in policy["Statement"]}


def as_set(value):
    # A policy value is a string or, after KMS's normal form, a list of two or more.
    return {value} if isinstance(value, str) else set(value)


def actions(statement):
    return as_set(statement["Action"])


def allowed(policy, principal_arn, action):
    """Whether the key policy alone leaves `action` open to an IAM principal of
    the account (with an IAM policy allowing it), ignoring every condition but
    aws:PrincipalArn. Enough for the owner rule; not a KMS evaluator."""
    allow = False
    for s in policy["Statement"]:
        if action not in actions(s):
            continue
        condition = s.get("Condition", {})
        if s["Effect"] == "Deny":
            if not condition:
                return False
            if set(condition) == {"StringNotEquals"} and set(condition["StringNotEquals"]) == {"aws:PrincipalArn"}:
                if principal_arn not in as_set(condition["StringNotEquals"]["aws:PrincipalArn"]):
                    return False
        elif s["Principal"] == {"AWS": ROOT} and not condition:
            allow = True
    return allow


class OwnerTest(unittest.TestCase):
    def test_default_owner_is_the_account_root(self):
        for name in TEMPLATES:
            deny = statements(rendered(name, "--pcr0", PCR_A))["OnlyOwnerAdministers"]
            self.assertEqual(deny["Effect"], "Deny")
            self.assertEqual(deny["Principal"], "*")
            self.assertEqual(actions(deny), ADMIN)
            self.assertEqual(deny["Condition"], {"StringNotEquals": {"aws:PrincipalArn": ROOT}})

    def test_only_owners_administer(self):
        for name in TEMPLATES:
            policy = rendered(name, "--pcr0", PCR_A, "--owner-arn", SSO, "--owner-arn", ROOT, "--owner-arn", SSO)
            self.assertEqual(statements(policy)["OnlyOwnerAdministers"]["Condition"]["StringNotEquals"]["aws:PrincipalArn"], [SSO, ROOT])
            for action in sorted(ADMIN):
                # KMS's lockout check: the owner applying the policy must still
                # be able to PutKeyPolicy afterwards.
                self.assertTrue(allowed(policy, SSO, action), (name, action))
                self.assertTrue(allowed(policy, ROOT, action), (name, action))
                self.assertFalse(allowed(policy, "arn:aws:iam::000000000000:role/operator", action), (name, action))
                self.assertFalse(allowed(policy, ROLE, action), (name, action))
            # Nobody creates grants, the owner included.
            self.assertFalse(allowed(policy, SSO, "kms:CreateGrant"))

    def test_no_mfa_condition(self):
        # Optional hardening only (docs): an MFA condition could lock out a
        # root user without MFA.
        for name in TEMPLATES:
            self.assertNotIn("MultiFactor", json.dumps(rendered(name, "--pcr0", PCR_A)))

    def test_only_the_owner_encrypts_under_the_boot_key(self):
        policy = rendered("boot", "--pcr0", PCR_A, "--owner-arn", SSO)
        deny = statements(policy)["OnlyOwnerEncrypts"]
        self.assertEqual(actions(deny), {"kms:Encrypt"})
        self.assertEqual(deny["Condition"], {"StringNotEquals": {"aws:PrincipalArn": SSO}})
        self.assertFalse(allowed(policy, ROLE, "kms:Encrypt"))
        self.assertFalse(allowed(policy, "arn:aws:iam::000000000000:role/operator", "kms:Encrypt"))
        # The owner's Allow carries the relay context; the Deny must not add
        # another path to Encrypt.
        allow = statements(policy)["OwnerEncryptsRelaySecret"]
        self.assertEqual(allow["Condition"]["StringEquals"]["kms:EncryptionContext:purpose"], "wappie-mcp-relay")
        # Nobody encrypts under the reader key.
        self.assertFalse(allowed(rendered("reader", "--pcr0", PCR_A), ROOT, "kms:Encrypt"))

    def test_rejects_bad_owners(self):
        for bad in (
            "arn:aws:iam::111111111111:root",                                  # another account
            "arn:aws:sts::000000000000:assumed-role/Owner/session",            # a session, not aws:PrincipalArn
            "arn:aws:iam::000000000000:group/owners",
            "000000000000",
            ROLE,                                                              # the parent itself
        ):
            with self.assertRaises(SystemExit, msg=bad):
                rendered("reader", "--pcr0", PCR_A, "--owner-arn", bad)

    def test_pcr0s_still_render_in_order(self):
        policy = rendered("reader", "--pcr0", PCR_B, "--pcr0", PCR_A, "--pcr0", PCR_B)
        use = statements(policy)["EnclaveUse"]["Condition"]["StringEqualsIgnoreCase"]
        self.assertEqual(use["kms:RecipientAttestation:ImageSha384"], [PCR_B, PCR_A])

    def test_every_placeholder_is_filled(self):
        for name in TEMPLATES:
            self.assertNotIn("@", json.dumps(rendered(name, "--pcr0", PCR_A)))

    def test_misplaced_list_placeholder_fails(self):
        with self.assertRaises(SystemExit):
            render.render({"a": "x @OWNER_ARNS@"}, {}, {"@OWNER_ARNS@": [ROOT]})


if __name__ == "__main__":
    unittest.main()


class KmsNormalFormTest(unittest.TestCase):
    """KMS stores one-element arrays as their single value; the published policy
    must be that form, or its hash never equals the one the enclave reads back."""

    def test_reader_0_2_0_matches_what_kms_returned(self):
        # The live reader key policy of release 0.2.0, read back with
        # GetKeyPolicy after the owner applied the published transition policy.
        live = json.loads((HERE / "testdata/reader-policy-0.2.0-from-kms.json").read_text())
        pcr0 = "be920347aa10867b596120b85be1a6c66316f318812142f1c273056ae0867f4c2e7d98b5215c5650dcd5493ce82ba086"
        out = io.StringIO()
        render.main([str(TEMPLATES["reader"]), "--role-arn", "arn:aws:iam::768406580484:role/wappie-enclave-spike-parent", "--pcr0", pcr0], out=out)
        self.assertEqual(json.loads(out.getvalue()), live)

    def test_one_element_arrays_become_values_and_longer_ones_stay(self):
        one = statements(rendered("reader", "--pcr0", PCR_A))
        self.assertEqual(one["EnclaveUse"]["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:ImageSha384"], PCR_A)
        self.assertEqual(one["OnlyOwnerAdministers"]["Condition"]["StringNotEquals"]["aws:PrincipalArn"], ROOT)
        two = statements(rendered("reader", "--pcr0", PCR_A, "--pcr0", PCR_B, "--owner-arn", ROOT, "--owner-arn", SSO))
        self.assertEqual(two["EnclaveUse"]["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:ImageSha384"], [PCR_A, PCR_B])
        self.assertEqual(two["OnlyOwnerAdministers"]["Condition"]["StringNotEquals"]["aws:PrincipalArn"], [ROOT, SSO])

    def test_normal_form_is_idempotent(self):
        policy = rendered("boot", "--pcr0", PCR_A)
        self.assertEqual(render.aws_normal_form(policy), policy)
