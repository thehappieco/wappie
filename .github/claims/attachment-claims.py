#!/usr/bin/env python3
"""Gate on "attachments are never opened" claims (docs/mcp-enclave.md section 16.1).

Since stage A the attested reader at mcp.wappie.thehappie.co/mcp opens
attachment contents inside the enclave for a connection whose consent
includes attachments (a 'media' connection). The hosted metadata connector at
api.wappie.thehappie.co/mcp, every connection of kind 'metadata', every text
connection (content consent version 1, or version 2 without attachments) and
the local stdio reader still never open them. A sentence that says attachment
contents are unavailable, that attachments are never (or not) opened,
downloaded or read, or that attachment bytes or file contents are out of reach
was true of every connection before A1 and is false for a media connection
after it. So every such phrase in the tree must be on the allowlist next to
this file, under the scope a reviewer checked it is true for.

The phrases are matched case-insensitively, also across one line break
(Markdown wraps prose; a blockquote's '>' or a comment's '//', '#' or '*' on
the next line is skipped), in English, Portuguese, Spanish, French and German:
see PATTERNS below.

Allowlist lines (attachment-claims.allow, '#' starts a comment):
    <scope> <path>                  every hit in that file (code; the reason
                                    goes in a comment)
    <scope> <path> :: <fragment>    only hits whose line contains <fragment>
<scope> is one of, or several joined by ',':
    metadata    the hosted metadata connector (api.…/mcp, the pilot's
                wappie-mcp, self-hosted containers), 'metadata' connections
                and the local reader without plaintext
    text        text connections of the attested reader (no 'media' in the
                consent) and the local reader with plaintext
    media       media connections: what they still never open (view-once,
                gone, keyless or unhashed media, audio and voice notes until
                transcription exists)
    unrelated   a sentence about something else entirely
A sentence true of every connection (search never looks into file contents)
names all three. An entry that no longer matches any hit is an error too, so the list cannot
rot into a blanket exemption.

Standard library only. Scans the files git tracks plus untracked files that
are not ignored, so it also runs before a commit:
    python3 .github/claims/attachment-claims.py
Exit 0 when every hit is allowed and every entry is used, 1 otherwise.
"""
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ALLOWLIST = HERE / "attachment-claims.allow"
SCOPES = ("metadata", "text", "media", "unrelated")
PATTERNS = (
    # English.
    r"attachment\s+contents?\s+(?:are|is)\s+(?:unavailable|never|not)\b",
    r"never\s+(?:opens?|downloads?|reads?)\s+(?:any\s+|the\s+)?attachments?\b",
    r"\battachments?\b[^.\n]{0,60}?\b(?:are|is)\s+never\s+(?:opened|downloaded|read)\b",
    r"attachment\s+downloads?\s+(?:are|is)\s+(?:not\s+)?available",
    r"\bdownloads?\s+(?:media|attachments?)\b",
    r"\bnever\s+attachment\s+(?:contents?|bytes|files?)\b",
    r"\battachment\s+bytes\b",
    r"\bno\b[^.\n]{0,40}?\bopens?\s+attachments?\b",
    # A claim, not a report of one failure ("Could not open the attachment").
    r"(?:\b(?:does|do|will|may|can|must|should)\s+not|\b(?:doesn|don|won|can|mustn|shouldn)['’]t|\bcannot)"
    r"\s+(?:open|download|read)\s+(?:the\s+|any\s+)?attachments?\b",
    r"file\s+contents",
    # Portuguese.
    r"conte[úu]do\s+d[eo]s?\s+(?:anexos|arquivos)",
    r"(?:nunca|n[ãa]o)\s+(?:abre|baixa|l[êe])\s+(?:os\s+)?anexos",
    r"\banexos?\b[^.\n]{0,60}?\bnunca\s+(?:s[ãa]o|[ée])\s+(?:abert|baixad|lid)",
    # Spanish.
    r"contenido\s+de\s+(?:los\s+)?(?:archivos\s+)?(?:adjuntos|archivos)",
    r"(?:nunca|\bno)\s+(?:abre|descarga|lee)\s+(?:los\s+)?(?:archivos\s+)?adjuntos",
    r"\badjuntos?\b[^.\n]{0,60}?\bnunca\s+se\s+(?:abren|abre|descargan|descarga|leen|lee)\b",
    # French.
    r"contenu\s+des\s+(?:pi[èe]ces\s+jointes|fichiers)",
    r"(?:n['’]ouvre|ne\s+lit|ne\s+t[ée]l[ée]charge)\s+(?:jamais|pas)\s+(?:les\s+)?pi[èe]ces\s+jointes",
    r"\bpi[èe]ces?\s+jointes?\b[^.\n]{0,60}?\bne\s+(?:sont|est)\s+(?:jamais|pas)\s+(?:ouvert|t[ée]l[ée]charg|lu)",
    # German.
    r"Inhalte?\s+der\s+(?:Anh[äa]nge|Dateien)",
    r"Dateiinhalte?\b",
    r"(?:öffnet|lädt|liest)\s+(?:nie(?:mals)?|keine)\s+Anh[äa]nge",
    r"\bAnh[äa]nge\b[^.\n]{0,60}?\b(?:nie(?:mals)?|nicht)\s+(?:geöffnet|heruntergeladen|gelesen)",
)
PHRASE = re.compile("|".join(f"(?:{pattern})" for pattern in PATTERNS), re.IGNORECASE)
MAX_BYTES = 4 * 1024 * 1024
# What starts a continued blockquote or comment line.
WRAP_MARKER = re.compile(r"^\s*(?:>+|//+|#+|\*+)?\s*")


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
            # A blockquote or a comment wraps like prose: its next line's
            # marker is not part of the sentence.
            joined = head + " " + WRAP_MARKER.sub("", lines[index + 1], count=1)
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
        scope, _, rest = line.partition(" ")
        name, sep, fragment = rest.partition(" :: ")
        name, fragment = name.strip(), fragment.strip()
        scopes = scope.split(",")
        if not name or (sep and not fragment) or not all(s in SCOPES for s in scopes) or len(set(scopes)) != len(scopes):
            raise SystemExit(f"{path.name}:{number}: expected '<scope> <path>' or '<scope> <path> :: <fragment>',"
                             f" <scope> one or more of {', '.join(SCOPES)} joined by ','")
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
        print(f"\n{len(failures)} attachment claim(s) not on the allowlist. Since A1 the attested reader (mcp.…/mcp)"
              " opens attachment contents for media connections. Say which connections the sentence is true for:"
              " the hosted metadata connector and 'metadata' connections, text connections, or what a media"
              " connection still never opens. Then add the line, with that scope, to"
              f" {allowlist.relative_to(root) if allowlist.is_relative_to(root) else allowlist}.", file=sys.stderr)
    if stale:
        print(f"\n{len(stale)} allowlist entr(y/ies) match nothing: remove them.", file=sys.stderr)
    return 1 if failures or stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
