#!/usr/bin/env python3
"""
CA-Lab Phase 5: summarize Hayabusa high/critical detections by technique and time.
Usage: python hayabusa-summary.py <hayabusa-timeline.csv> [out.md]
"""
import csv, sys, re
from collections import defaultdict

src = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else None
MITRE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

rows = []
by_rule = defaultdict(lambda: {"n": 0, "level": "", "first": "", "last": "", "mitre": set(), "eid": set()})
counts = defaultdict(int)
with open(src, encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        lvl = (r.get("Level") or "").lower()
        counts[lvl] += 1
        if lvl not in ("critical", "high"):
            continue
        title = r.get("RuleTitle", "")
        ts = r.get("Timestamp", "")
        e = by_rule[(lvl, title)]
        e["n"] += 1; e["level"] = lvl
        if not e["first"] or ts < e["first"]: e["first"] = ts
        if ts > e["last"]: e["last"] = ts
        for m in MITRE.findall(title + " " + r.get("Details", "")): e["mitre"].add(m)
        if r.get("EventID"): e["eid"].add(r.get("EventID"))
        rows.append((ts, lvl, title, r.get("Channel",""), r.get("EventID","")))

lines = []
def p(s=""): lines.append(s); print(s)

p("# CA-Lab Hayabusa summary (high + critical)")
p()
p("Level totals: " + ", ".join(f"{k}={counts[k]}" for k in ("critical","high","medium","low","informational") if counts.get(k)))
p()
p("## Critical and High detections by rule (most frequent first)")
p()
p("| Level | Count | Rule | MITRE | First (UTC) | Last (UTC) |")
p("|---|---|---|---|---|---|")
order = {"critical": 0, "high": 1}
for (lvl, title), e in sorted(by_rule.items(), key=lambda kv: (order[kv[1]["level"]], -kv[1]["n"])):
    mitre = ", ".join(sorted(e["mitre"])) or "-"
    p(f"| {lvl} | {e['n']} | {title[:70]} | {mitre} | {e['first'][:19]} | {e['last'][:19]} |")

crit = sorted([r for r in rows if r[1] == "critical"])
p()
p(f"## Critical detections in time order ({len(crit)})")
p()
for ts, lvl, title, chan, eid in crit:
    p(f"- {ts[:19]}  [{chan} EID {eid}]  {title[:90]}")

if out:
    open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
