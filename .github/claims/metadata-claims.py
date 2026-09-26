#!/usr/bin/env python3
"""Gate on "metadata-only" claims (docs/mcp-enclave.md section 15.1, plan 2b.22).

Wappie has two hosted MCP connectors. The one at api.wappie.thehappie.co/mcp
(the pilot's reader) and every connection of kind 'metadata' never open
content. The attested reader at mcp.wappie.thehappie.co/mcp can open message
text for a 'content' connection. A sentence that calls "the hosted connector"
metadata-only was true before milestone 2b and is false after it, so every
such phrase in the tree must be on the allowlist next to this file, where a
reviewer has checked that it names which connector it means, or that it is
about something else entirely.

The phrases are matched case-insensitively, also across one line break
(Markdown wraps prose): metadata-only, metadata only, somente metadados,
solo metadatos, solo metadatos with an accent.

Allowlist lines (metadata-claims.allow, '#' starts a comment):
    <path>                   every hit in that file (code whose strings serve
                             the metadata kind; the reason goes in a comment)
    <path> :: <fragment>     only hits whose line contains <fragment>
An entry that no longer matches any hit is an error too, so the list cannot
rot into a blanket exemption.

Standard library only. Scans the files git tracks plus untracked files that
are not ignored, so it also runs before a commit:
    python3 .github/claims/metadata-claims.py
Exit 0 when every hit is allowed and every entry is used, 1 otherwise.
"""
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ALLOWLIST = HERE / "metadata-claims.allow"
PHRASE = re.compile(r"metadata[\s-]+only|somente\s+metadados|s[oó]lo\s+metadatos", re.IGNORECASE)
MAX_BYTES = 4 * 1024 * 1024


def tracked_files(root):
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, capture_output=True).stdout
    return sorted({name for name in out.decode().split("\0") if name})


def hits(text):
    """Yields (line number, text to match fragments against) for each phrase."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if PHRASE.search(line):
            yield index + 1, line
        if index + 1 < len(lines):
            head = line.rstrip()
            joined = head + " " + lines[index + 1].lstrip()
            for match in PHRASE.finditer(joined):
                # Only a match that spans the break; the others are found on
                # their own line.
                if match.start() < len(head) < match.end():
                    yield index + 1, joined


def read_allowlist(path):
    entries = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, fragment = line.partition(" :: ")
        name, fragment = name.strip(), fragment.strip()
        if not name or (sep and not fragment):
            raise SystemExit(f"{path.name}:{number}: expected '<path>' or '<path> :: <fragment>'")
        entries.append({"line": number, "path": name, "fragment": fragment or None, "used": False})
    return entries


def main(argv):
    root = pathlib.Path(argv[1]).resolve() if len(argv) > 1 else ROOT
    allowlist = ALLOWLIST if len(argv) <= 2 else pathlib.Path(argv[2]).resolve()
    entries = read_allowlist(allowlist)
    skip = {str(p.relative_to(root)) for p in (pathlib.Path(__file__).resolve(), allowlist.resolve())
            if p.is_relative_to(root)}
    failures = []
    for name in tracked_files(root):
        if name in skip:
            continue
        path = root / name
        try:
            if not path.is_file() or path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in hits(text):
            allowed = False
            for entry in entries:
                if entry["path"] == name and (entry["fragment"] is None or entry["fragment"] in line):
                    entry["used"] = True
                    allowed = True
            if not allowed:
                failures.append(f"{name}:{number}: {line.strip()[:160]}")
    stale = [f"{allowlist.name}:{e['line']}: no hit for {e['path']}" + (f" :: {e['fragment']}" if e["fragment"] else "")
             for e in entries if not e["used"]]
    for line in failures:
        print(line)
    for line in stale:
        print(line)
    sys.stdout.flush()
    if failures:
        print(f"\n{len(failures)} metadata-only claim(s) not on the allowlist. Say which connector the sentence means:"
              " the hosted metadata connector (api.…/mcp, 'metadata' connections) or the attested reader"
              " (mcp.…/mcp), which opens text for 'content' connections. Then add the line to"
              f" {allowlist.relative_to(root) if allowlist.is_relative_to(root) else allowlist}.", file=sys.stderr)
    if stale:
        print(f"\n{len(stale)} allowlist entr(y/ies) match nothing: remove them.", file=sys.stderr)
    return 1 if failures or stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
