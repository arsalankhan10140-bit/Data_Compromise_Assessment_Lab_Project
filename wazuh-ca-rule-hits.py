#!/var/ossec/framework/python/bin/python3
"""
CA-Lab: report which CA-Lab rules (1001xx) fired for an agent since a given time, from alerts.json.
Usage: sudo /var/ossec/framework/python/bin/python3 wazuh-ca-rule-hits.py <since: 'YYYY-MM-DDTHH:MM:SS' UTC> [agent=CA-WIN-01] [--all]
"""
import json, sys
from collections import OrderedDict

since = sys.argv[1]
agent = next((a.split("=", 1)[1] for a in sys.argv[2:] if a.startswith("agent=")), "CA-WIN-01")
show_all = "--all" in sys.argv
expected = ["100100", "100101", "100102", "100103", "100104", "100110", "100111", "100120", "100121", "100122",
            "100130", "100131", "100140", "100141", "100150", "100151", "100152", "100153", "100154", "100155",
            "100156", "100157", "100160", "100161", "100162", "100170", "100171", "100172"]
hits, other = OrderedDict(), OrderedDict()
with open("/var/ossec/logs/alerts/alerts.json", encoding="utf-8", errors="replace") as f:
    for raw in f:
        try:
            a = json.loads(raw)
        except ValueError:
            continue
        if a.get("agent", {}).get("name") != agent or a.get("timestamp", "")[:19] < since:
            continue
        r = a["rule"]
        key = r["id"]
        target = hits if key.startswith("1001") else other
        e = target.setdefault(key, {"n": 0, "level": r["level"], "desc": r["description"],
                                    "mitre": ",".join(r.get("mitre", {}).get("id", [])), "first": a["timestamp"][11:19]})
        e["n"] += 1

print(f"CA-Lab rule hits for {agent} since {since}")
for rid in expected:
    if rid in hits:
        h = hits[rid]
        print(f"  FIRED  {rid}  x{h['n']:<3} L{h['level']:<2} {h['mitre']:<18} {h['first']}  {h['desc'][:85]}")
    else:
        print(f"  ----   {rid}  not fired")
print(f"Fired {sum(1 for r in expected if r in hits)}/{len(expected)}")
if show_all:
    print("\nOther (built-in) rules level>=3 in the same window:")
    for rid, h in other.items():
        if h["level"] >= 3:
            print(f"  {rid:<7} x{h['n']:<3} L{h['level']:<2} {h['mitre']:<18} {h['desc'][:90]}")
