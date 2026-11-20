#!/var/ossec/framework/python/bin/python3
"""Read-only: print rule + win.eventdata of the last alert with a given rule id (CA-WIN-01)."""
import json, sys
rid = sys.argv[1]
last = None
for raw in open("/var/ossec/logs/alerts/alerts.json", encoding="utf-8", errors="replace"):
    if f'"id":"{rid}"' in raw and "CA-WIN-01" in raw:
        last = raw
if last:
    a = json.loads(last)
    print(json.dumps({"rule": a["rule"], "eventdata": a["data"]["win"].get("eventdata")}, indent=1)[:2500])
