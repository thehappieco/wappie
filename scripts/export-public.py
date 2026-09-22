#!/usr/bin/env python3
"""Create a public source release from explicit roots, without Git history."""
import argparse
import pathlib
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROOTS = ("cmd", "internal", "packages/client", "packages/cli", "packages/mcp", "packages/mcp-http", "docs", "site", "deploy", "scripts", ".github")
FILES = ("go.mod", "go.sum", "README.md", "LICENSE", "NOTICE", "CONTRIBUTING.md", "SECURITY.md", "Makefile", ".env.example", ".gitignore", ".dockerignore", ".golangci.yml", ".gitleaks.toml", "docker-compose.dev.yml")
OPERATIONAL_DOCS = {"docs/testing-awsa.md", "docs/testing-aws-to-awsa.md", "docs/implementation-2026-09-15.md"}
EXCLUDED = {"node_modules", "dist", ".git", ".superpowers", "__pycache__", ".DS_Store", "superpowers"}

def public_files():
    for root in ROOTS:
        for p in sorted((ROOT / root).rglob("*")):
            relative = p.relative_to(ROOT)
            if relative.as_posix() in OPERATIONAL_DOCS or any(part in EXCLUDED for part in relative.parts) or p.name.endswith((".pyc", ".out")):
                continue
            if p.is_symlink():
                raise SystemExit(f"Refusing symlink in public source: {relative}")
            if p.is_file():
                if p.suffix == ".vue" or p.name.startswith(".env") and p.name != ".env.example":
                    raise SystemExit(f"Refusing private UI or configuration: {relative}")
                yield p
    for name in FILES:
        p = ROOT / name
        if p.is_file():
            yield p

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    entries = list(public_files())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.output, "w:gz") as out:
        for p in entries:
            info = out.gettarinfo(str(p), str(p.relative_to(ROOT)))
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            with p.open("rb") as data:
                out.addfile(info, data)
    print(f"Public source: {args.output} ({len(entries)} files)")

if __name__ == "__main__":
    main()
