#!/usr/bin/env python3
"""Assembles the A0 probe report from the enclave console, on the parent
(deploy/enclave/probe; probe.sh runs it). The runner streams one line per
finished section,

    A0R <seq> <bytes> {"section": ..., "t": ..., "data": ...}

where <bytes> is the UTF-8 length of the JSON, and the entrypoint prints every
record again from /run/probe/report.jsonl at the end. So a record survives a
kernel message that splits one copy of it (the kernel writes to the console
without regard for a half-written user line), and a run that dies mid-way still
yields every section it finished. The entrypoint's own lines (A0 STEP, PID,
EXIT, NODE, ALIVE) and the kernel's SIGILL reports are collected too, so the
report explains a run even if the runner never started.

    assemble-report.py <console.log> <out-dir>

Writes <out-dir>/report.jsonl (each valid record once, in seq order) and
<out-dir>/report.json, and prints one summary line. Exit 0 when the report is
complete (the END marker and the runner's `done` record are both there), 2 when
it is partial, 1 when the console holds no record at all."""
import json
import pathlib
import re
import sys

BEGIN = "===WAPPIE-A0-PROBE-BEGIN==="
END = "===WAPPIE-A0-PROBE-END==="
RECORD = re.compile(r"A0R (\d+) (\d+) (.*)")
# A kernel console line starts with its timestamp, e.g. "[    0.326174] ".
KERNEL = re.compile(r"\[\s*\d+\.\d+\] ")
# Sections the runner emits more than once; every other name appears once.
REPEATED = {"spawn", "exit", "jail_test", "fatal"}


def console_lines(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _decode(text, size):
    """The record whose JSON is the first `size` bytes of `text`, or None."""
    raw = text.encode()
    if len(raw) < size:
        return None
    try:
        rec = json.loads(raw[:size].decode())
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def repair(body, size, lines, nxt):
    """The record in `body`, or, when a kernel message was written into the
    middle of it, the record put back together: `body` up to the kernel
    timestamp, then the following console lines with whole kernel lines
    skipped, until there are `size` bytes that parse. None if that fails."""
    rec = _decode(body, size)
    if rec is not None:
        return rec
    k = KERNEL.search(body)
    text = body[: k.start()] if k else body
    for line in lines[nxt : nxt + 400]:
        if len(text.encode()) >= size:
            break
        if KERNEL.match(line):
            continue
        k = KERNEL.search(line)
        text += line[: k.start()] if k else line
    return _decode(text, size)


def parse_records(lines):
    """The valid records by seq (the first valid copy wins), and how many
    record lines could not be repaired."""
    records = {}
    broken = 0
    for i, line in enumerate(lines):
        m = RECORD.search(line)
        if not m:
            continue
        seq, size = int(m.group(1)), int(m.group(2))
        rec = repair(m.group(3), size, lines, i + 1)
        if rec is None:
            broken += 1
        elif seq not in records:
            records[seq] = rec
    return records, broken


def kernel_sigills(lines):
    """Every "Bad EL0 synchronous exception" the kernel printed, with the pid,
    comm and pc from the register dump that follows it."""
    events = []
    for i, line in enumerate(lines):
        bad = re.search(r"Bad EL0 synchronous exception detected on CPU\d+, code (0x[0-9a-f]+)", line)
        if not bad:
            continue
        ev = {"esr": bad.group(1), "pid": None, "comm": None, "pc": None}
        for follow in lines[i + 1 : i + 10]:
            if "Bad EL0 synchronous exception" in follow:
                break
            who = re.search(r"PID: (\d+) Comm: (\S+)", follow)
            if who and ev["pid"] is None:
                ev["pid"], ev["comm"] = int(who.group(1)), who.group(2)
            pc = re.search(r"\] pc : (?:0x)?([0-9a-f]+)", follow)
            if pc and ev["pc"] is None:
                ev["pc"] = "0x" + pc.group(1)
                ev["pc_page_offset"] = hex(int(pc.group(1), 16) & 0xFFF)
        events.append(ev)
    return events


def entrypoint_lines(lines):
    """The entrypoint's own markers, and pid -> label from its A0 PID lines."""
    out = {"steps": [], "pids": [], "exits": [], "node": [], "last_alive": None}
    labels = {}
    for line in lines:
        for tag, key in (("A0 STEP ", "steps"), ("A0 PID ", "pids"), ("A0 EXIT ", "exits")):
            at = line.find(tag)
            if at >= 0:
                out[key].append(line[at:])
        m = re.search(r"A0 PID (\d+) (\S+): (.*)", line)
        if m:
            labels[int(m.group(1))] = f"entrypoint {m.group(2)}: {m.group(3)}"
        at = line.find("A0 NODE ")
        if at >= 0:
            try:
                out["node"].append(json.loads(line[at + len("A0 NODE ") :]))
            except ValueError:
                out["node"].append({"raw": line[at:]})
        m = re.search(r"A0 ALIVE t=(\S+)", line)
        if m:
            out["last_alive"] = m.group(1)
    return out, labels


def process_labels(sections):
    """pid -> what it was, from the runner's spawn records and every jailed
    job's child_pid."""
    labels = {}
    for entry in sections.get("spawn", []):
        d = entry.get("data") or {}
        if d.get("pid"):
            labels[d["pid"]] = f"runner spawn: {' '.join(d.get('argv') or [])}"

    def jailed(name, data):
        jail = (data or {}).get("jail") or {}
        if jail.get("child_pid"):
            labels[jail["child_pid"]] = f"jailed job {name}"

    for entry in sections.get("jail_test", []):
        d = entry.get("data") or {}
        jailed(d.get("test"), d)
    for name in ("image_job", "pdf_job"):
        if name in sections:
            jailed(name, sections[name].get("data"))
    return labels


def assemble(text):
    lines = console_lines(text)
    records, broken = parse_records(lines)
    sections = {}
    for seq in sorted(records):
        rec = records[seq]
        name = rec.get("section", "?")
        entry = {"seq": seq, "t": rec.get("t"), "data": rec.get("data")}
        if name in REPEATED:
            sections.setdefault(name, []).append(entry)
        elif name in sections:
            sections[name + "#" + str(seq)] = entry
        else:
            sections[name] = entry
    entry, labels = entrypoint_lines(lines)
    labels.update(process_labels(sections))
    begin_data = (sections.get("begin") or {}).get("data") or {}
    if begin_data.get("pid"):
        labels.setdefault(begin_data["pid"], "the runner")
    sigills = kernel_sigills(lines)
    for ev in sigills:
        ev["source"] = labels.get(ev["pid"], "unknown")
    end = any(END in line for line in lines)
    done = "done" in sections
    last = max(records) if records else 0
    return {
        "schema": "wappie-media-a0-probe-report/v2",
        "complete": end and done,
        "begin_marker": any(BEGIN in line for line in lines),
        "end_marker": end,
        "runner_done": done,
        "records": len(records),
        "broken_record_lines": broken,
        "missing_seqs": [s for s in range(1, last + 1) if s not in records][:50],
        "last_section": records[last].get("section") if records else None,
        "entrypoint": entry,
        "console_sigills": sigills,
        "sections": sections,
    }, [records[s] for s in sorted(records)]


def main():
    if len(sys.argv) != 3:
        print("usage: assemble-report.py <console.log> <out-dir>", file=sys.stderr)
        return 64
    console = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    report, ordered = assemble(console.read_bytes().decode("utf-8", "replace"))
    (out / "report.jsonl").write_text("".join(json.dumps(r) + "\n" for r in ordered))
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    jail = ((report["sections"].get("jail") or {}).get("data")) or {}
    if report["complete"]:
        print(f"report: complete, {report['records']} records, jail go={jail.get('go')}")
        return 0
    if report["records"]:
        print(
            f"report: PARTIAL, {report['records']} records, last section {report['last_section']!r}, "
            f"END marker {'seen' if report['end_marker'] else 'missing'}, "
            f"broken lines {report['broken_record_lines']}"
        )
        return 2
    print(f"report: NONE (no record on the console; {len(report['entrypoint']['steps'])} entrypoint steps)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
