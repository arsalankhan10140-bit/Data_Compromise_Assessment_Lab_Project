#!/var/ossec/framework/python/bin/python3
"""Read-only: show alerts for CA-WIN-01 since a time whose eventID or syscheck path matches.
Usage: wazuh-find-alerts.py SINCE [eid=4720,4732] [path=CA-IOC-Test] [rule=92900]"""
import json, sys
since = sys.argv[1]
eids = paths = rules = []
for a in sys.argv[2:]:
    k, v = a.split("=", 1)
    if k == "eid": eids = v.split(",")
    if k == "path": paths = v.split(",")
    if k == "rule": rules = v.split(",")
for raw in open("/var/ossec/logs/alerts/alerts.json", encoding="utf-8", errors="replace"):
    try: a = json.loads(raw)
    except ValueError: continue
    if a.get("agent", {}).get("name") != "CA-WIN-01" or a["timestamp"][:19] < since: continue
    eid = a.get("data", {}).get("win", {}).get("system", {}).get("eventID", "")
    sc = a.get("syscheck", {})
    if (eids and eid in eids) or (paths and any(p.lower() in sc.get("path", "").lower() for p in paths)) or (rules and a["rule"]["id"] in rules):
        ed = a.get("data", {}).get("win", {}).get("eventdata", {})
        print(a["timestamp"][11:19], a["rule"]["id"], "L%s" % a["rule"]["level"], a["rule"]["description"][:70], "| eid", eid,
              "| path", sc.get("path"), "| sha256", sc.get("sha256_after"), "| src", ed.get("sourceImage"), ed.get("grantedAccess"), "| tgtSid", ed.get("targetSid"))
