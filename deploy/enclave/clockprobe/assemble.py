#!/usr/bin/env python3
"""Assembles the clock probe's report from a probe enclave's console, on the
parent (deploy/enclave/clockprobe; clockprobe.sh runs it). The runner
(clockprobe-run.mjs) streams one line per finished section,

    CPR <seq> <bytes> {"section": ..., "t": ..., "data": ...}

and the entrypoint prints /run/clockprobe/report.jsonl again at the end
between `CP FILE ... BEGIN` and `CP FILE ... END`, one JSON per line in seq
order. A record a kernel message split is put back together the way the A1
probe's assembler does it (deploy/enclave/probe/assemble-report.py `repair`).

    assemble.py <console.log> <out-dir>
        writes <out-dir>/report.jsonl and report.json and prints one line per
        scenario: exit 0 when complete (the END marker and the runner's `done`
        record are there), 2 when partial, 1 when there is no record at all
    assemble.py --summary <stamp-dir>
        reads <stamp-dir>/<run>/report.json for every run and writes
        <stamp-dir>/results.json: every scenario's pass (true, false or null:
        not run) and its failed checks. Prints one line per scenario. Exit 0
        when no scenario failed, 1 otherwise."""
import importlib.util
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("a1_assemble", HERE.parent / "probe" / "assemble-report.py")
_a1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_a1)
repair, console_lines = _a1.repair, _a1.console_lines

END = "===WAPPIE-CLOCKPROBE-END==="
RECORD = re.compile(r"CPR (\d+) (\d+) (.*)")
FILE_BEGIN = "CP FILE /run/clockprobe/report.jsonl BEGIN"
FILE_END = "CP FILE /run/clockprobe/report.jsonl END"
ORDER = ["P0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S9-boot"]


def streamed(lines):
    """Records by seq from the CPR lines (the first valid copy wins), and how
    many could not be repaired."""
    records, broken = {}, 0
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


def dumped(lines):
    """Records by seq from the report.jsonl the entrypoint printed at the end
    (line n is seq n). A line a kernel message cut is left out."""
    try:
        start = next(i for i, l in enumerate(lines) if l.strip().endswith(FILE_BEGIN))
    except StopIteration:
        return {}
    records, seq = {}, 0
    for line in lines[start + 1 :]:
        if line.strip().endswith(FILE_END):
            break
        if _a1.KERNEL.match(line) or not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            seq += 1
            continue
        if isinstance(rec, dict) and "section" in rec:
            records[seq] = rec
        seq += 1
    return records


def assemble(text):
    lines = console_lines(text)
    stream, broken = streamed(lines)
    dump = dumped(lines)
    merged = dict(stream)
    for seq, rec in dump.items():
        merged.setdefault(seq, rec)
    records = [merged[k] for k in sorted(merged)]
    top = max(merged) if merged else -1
    missing = [k for k in range(top + 1) if k not in merged]
    scenarios = {}
    for rec in records:
        if rec.get("section") == "scenario":
            d = rec.get("data") or {}
            scenarios[d.get("id")] = d
    run = next((r.get("data", {}).get("run") for r in records if r.get("section") == "run"), None)
    done = any(r.get("section") == "done" for r in records)
    ended = any(l.strip().endswith(END) for l in lines)
    steps = [l[l.find("CP STEP ") :] for l in lines if "CP STEP " in l]
    exits = [l[l.find("CP EXIT ") :] for l in lines if "CP EXIT " in l]
    return {
        "complete": done and ended,
        "run": run,
        "records": records,
        "scenarios": scenarios,
        "missing_seqs": missing,
        "broken_lines": broken,
        "entrypoint": {"steps": steps, "exits": exits},
        "fatal": [r for r in records if r.get("section") == "fatal"],
    }


def failed(scenario):
    return [c.get("name") for c in scenario.get("checks", []) if c.get("pass") is False]


def word(p):
    return "not run" if p is None else "PASS" if p else "FAIL"


def line_for(sid, sc):
    bad = failed(sc)
    return f"{sid}: {word(sc.get('pass'))}" + (f" [{', '.join(bad)}]" if bad else "")


def one(console, out):
    report = assemble(pathlib.Path(console).read_text(errors="replace"))
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "report.jsonl", "w") as f:
        for rec in report["records"]:
            f.write(json.dumps(rec) + "\n")
    (out / "report.json").write_text(json.dumps(report, indent=1) + "\n")
    if not report["records"]:
        print("no record in the console")
        return 1
    state = "complete" if report["complete"] else "PARTIAL"
    print(f"run {report['run']}: {state}, {len(report['records'])} records"
          + (f", missing {report['missing_seqs']}" if report["missing_seqs"] else ""))
    for sid, sc in report["scenarios"].items():
        print("  " + line_for(sid, sc))
    return 0 if report["complete"] else 2


def summary(stamp_dir):
    stamp_dir = pathlib.Path(stamp_dir)
    runs, scenarios = {}, {}
    for path in sorted(stamp_dir.glob("*/report.json")):
        report = json.loads(path.read_text())
        runs[path.parent.name] = {"complete": report.get("complete"), "run": report.get("run"),
                                  "missing_seqs": report.get("missing_seqs")}
        for sid, sc in report.get("scenarios", {}).items():
            scenarios[sid] = {"pass": sc.get("pass"), "run": path.parent.name, "failed": failed(sc),
                              "checks": sc.get("checks", [])}
    ids = sorted(scenarios, key=lambda s: (ORDER.index(s) if s in ORDER else len(ORDER), s))
    result = {
        "runs": runs,
        "scenarios": {sid: scenarios[sid] for sid in ids},
        "missing": [s for s in ORDER if s not in scenarios],
        "any_failed": any(sc["pass"] is False for sc in scenarios.values()),
    }
    (stamp_dir / "results.json").write_text(json.dumps(result, indent=1) + "\n")
    for name, r in runs.items():
        print(f"run {name}: {'complete' if r['complete'] else 'PARTIAL'}")
    for sid in ids:
        print("  " + line_for(sid, scenarios[sid]))
    if result["missing"]:
        print(f"  no result for: {', '.join(result['missing'])}")
    return 1 if result["any_failed"] else 0


def main(argv):
    if len(argv) == 2 and argv[0] == "--summary":
        return summary(argv[1])
    if len(argv) == 2:
        return one(argv[0], argv[1])
    print(__doc__, file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
