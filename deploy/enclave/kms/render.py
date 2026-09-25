#!/usr/bin/env python3
"""Render a KMS key policy template for one reader release.

    render.py TEMPLATE --role-arn ARN --pcr0 HEX [--pcr0 HEX] [--owner-arn ARN ...]

Placeholders: "@ACCOUNT_ID@" (taken from the role ARN), "@PARENT_ROLE_ARN@",
"@PCR3@" (computed from the role ARN) and two array elements: "@PCR0S@", which
becomes the list of released PCR0 values in the order given, and
"@OWNER_ARNS@", the principals the key policy lets administer the key (and
encrypt under the boot key). --owner-arn is repeatable and defaults to the
account root (arn:aws:iam::<account>:root, the root user only): the Deny
"OnlyOwnerAdministers" holds whatever an IAM policy in the account allows.
An owner is the account root, an IAM user or an IAM role ARN (for an IAM
Identity Center permission set, the role with its aws-reserved/... path, which
is what aws:PrincipalArn carries), in the parent role's account. The result is
written with sorted keys and two-space indentation; the policy hash is not
computed here: packages/mcp-http/enclave/policy.mjs is the one implementation
of the canonical form (docs/mcp-enclave.md section 7), and build.sh runs it.
"""
import argparse
import hashlib
import json
import re
import sys

ROLE_ARN = re.compile(r"^arn:aws:iam::(\d{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$")
PCR = re.compile(r"^[0-9a-f]{96}$")
# aws:PrincipalArn is the role's ARN for an assumed role, never the
# arn:aws:sts::…:assumed-role/… session ARN, so only IAM ARNs can match.
OWNER_ARN = re.compile(r"^arn:aws:iam::(\d{12}):(root|(?:role|user)/[A-Za-z0-9+=,.@_/-]{1,512})$")


def pcr3(role_arn):
    # PCR3 extends 48 zero bytes with the parent's role ARN (spike Day 3: the
    # role ARN, not the instance profile's).
    return hashlib.sha384(b"\0" * 48 + role_arn.encode()).hexdigest()


def render(node, values, lists):
    """values: string placeholders, replaced anywhere in a string; lists:
    placeholders that stand alone as an array element and become that list."""
    if isinstance(node, dict):
        return {key: render(value, values, lists) for key, value in node.items()}
    if isinstance(node, list):
        out = []
        for item in node:
            if isinstance(item, str) and item in lists:
                out.extend(lists[item])
            else:
                out.append(render(item, values, lists))
        return out
    if isinstance(node, str):
        for key, value in values.items():
            node = node.replace(key, value)
        if "@" in node and re.search(r"@[A-Z0-9_]+@", node):
            raise SystemExit(f"render: unknown or misplaced placeholder in {node!r}")
        return node
    return node


def main(argv=None, out=sys.stdout):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("template")
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--pcr0", action="append", required=True)
    parser.add_argument("--owner-arn", action="append", default=[],
                        help="a principal allowed to administer the key (repeatable; default: the account root)")
    args = parser.parse_args(argv)
    match = ROLE_ARN.match(args.role_arn)
    if not match:
        raise SystemExit(f"render: not an IAM role ARN: {args.role_arn}")
    account = match.group(1)
    pcr0s = []
    for value in args.pcr0:
        if not PCR.match(value):
            raise SystemExit("render: --pcr0 must be 96 lowercase hex characters")
        if value not in pcr0s:
            pcr0s.append(value)
    owners = []
    for value in args.owner_arn or [f"arn:aws:iam::{account}:root"]:
        owner = OWNER_ARN.match(value)
        if not owner:
            raise SystemExit(f"render: --owner-arn must be an IAM root, user or role ARN: {value}")
        # The key policy delegates to this account's root; an owner elsewhere
        # would hold no Allow, and PutKeyPolicy's lockout check would refuse.
        if owner.group(1) != account:
            raise SystemExit(f"render: --owner-arn is not in the role's account {account}: {value}")
        # The operator runs the parent; it must never administer the keys.
        if value == args.role_arn:
            raise SystemExit("render: --owner-arn must not be the parent role")
        if value not in owners:
            owners.append(value)
    with open(args.template, encoding="utf-8") as fh:
        template = json.load(fh)
    values = {"@ACCOUNT_ID@": account, "@PARENT_ROLE_ARN@": args.role_arn, "@PCR3@": pcr3(args.role_arn)}
    lists = {"@PCR0S@": pcr0s, "@OWNER_ARNS@": owners}
    json.dump(render(template, values, lists), out, indent=2, sort_keys=True)
    out.write("\n")


if __name__ == "__main__":
    main()
