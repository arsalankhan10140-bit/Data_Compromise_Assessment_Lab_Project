#!/var/ossec/framework/python/bin/python3
"""
CA-Lab Phase 4: build detection-matrix.csv from Wazuh alerts.json for the atomic run.
Usage: sudo /var/ossec/framework/python/bin/python3 build-detection-matrix.py SINCE_UTC > detection-matrix.csv
"""
import json, sys, csv
from collections import defaultdict

since = sys.argv[1]

# technique -> (test label, expected evidence, CA-Lab rule ids, built-in corroborating ids)
PLAN = [
    ("T1059.001", "PowerShell Command Execution",      "Encoded/again-launched PowerShell; Sysmon EID1 + PS 4104", ["100120","100121","100122"], ["92057","92027"]),
    ("T1003.001", "LSASS dump via comsvcs.dll",        "rundll32 comsvcs MiniDump of lsass; Sysmon EID1/EID10",   ["100154","100111","100110"], ["92900"]),
    ("T1053.005", "Scheduled task (Local)",            "schtasks /create; Sysmon EID1 + Security 4698",           ["100130","100131"], ["92302"]),
    ("T1547.001", "Reg Key Run",                       "Run key value set; Sysmon EID13",                         ["100140","100141"], ["92302","92041"]),
    ("T1136.001", "Create a new user (cmd)",           "net user /add; Sysmon EID1 + Security 4720",              ["100156","100160"], ["92039"]),
    ("T1105",     "BITSAdmin download",                "bitsadmin /transfer; Sysmon EID1",                        ["100152"], ["92213"]),
    ("T1218.011", "Rundll32 pcwutl.dll",               "rundll32 proxy execution; Sysmon EID1",                   ["100153"], []),
    ("T1562.001", "Defender exclusion (custom)",       "Set-MpPreference exclusion; Defender 5007",               ["100104","100103","100155"], []),
]

fired = defaultdict(lambda: {"n": 0, "first": "", "level": 0, "desc": ""})
channels = defaultdict(set)
for raw in open("/var/ossec/logs/alerts/alerts.json", encoding="utf-8", errors="replace"):
    try: a = json.loads(raw)
    except ValueError: continue
    if a.get("agent", {}).get("name") != "CA-WIN-01" or a.get("timestamp","")[:19] < since: continue
    rid = a["rule"]["id"]
    e = fired[rid]
    e["n"] += 1; e["level"] = a["rule"]["level"]; e["desc"] = a["rule"]["description"]
    if not e["first"]: e["first"] = a["timestamp"][11:19]

w = csv.writer(sys.stdout)
w.writerow(["Technique","Test","Expected evidence","Wazuh rule fired (Y/N, ID)","Corroborating event","First alert (UTC)","Notes"])
for tech, test, ev, ca_ids, builtin in PLAN:
    hit = [r for r in ca_ids if r in fired]
    corr = [r for r in builtin if r in fired]
    if hit:
        ywn = "Y: " + ", ".join(hit)
        first = fired[hit[0]]["first"]
        note = "CA-Lab rule fired"
    elif corr:
        ywn = "Partial (built-in only)"
        first = fired[corr[0]]["first"]
        note = "Caught by built-in rule, custom rule missed"
    else:
        ywn = "N"
        first = ""
        note = "No alert in window"
    corr_txt = ", ".join(corr) if corr else "-"
    w.writerow([tech, test, ev, ywn, corr_txt, first, note])
