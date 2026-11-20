#!/bin/bash
R=/var/ossec/ruleset/rules
echo "== sysmon_event groups =="; grep -h -o 'group>sysmon_event[^<]*' $R/0595-win-sysmon_rules.xml | sort -u
echo "== file-level groups =="; grep -h -o '<group name="[^"]*"' $R/0575-win-base_rules.xml $R/0580-win-security_rules.xml $R/0595-win-sysmon_rules.xml $R/0600-win-wdefender_rules.xml $R/0915-win-powershell_rules.xml
echo "== defender rules for 1116/1117/5001/5007 =="
for e in 1116 1117 5001 5007; do grep -B6 "eventID\">^$e\$" $R/0600-win-wdefender_rules.xml | grep -E 'rule id|if_sid' | tr -s ' ' | tr '\n' ' '; echo " <- $e"; done
echo "== security rules for 4720/4732/1102/4698 (eventchannel) =="
for e in 4720 4732 1102 4698; do grep -B6 "eventID\">^$e\$" $R/0580-win-security_rules.xml | grep -E 'rule id|if_sid' | tr -s ' ' | tr '\n' ' '; echo " <- $e"; done
echo "== powershell 4104 rule =="; grep -B6 -A3 '4104' $R/0915-win-powershell_rules.xml | grep -E 'rule id|if_sid|field|description' | head -8
