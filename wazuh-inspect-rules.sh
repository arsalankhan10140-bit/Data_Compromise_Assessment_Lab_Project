#!/bin/bash
# Read-only: find built-in parent rule IDs and current manager config for Phase 3.
R=/var/ossec/ruleset/rules
echo "== Sysmon per-event base rules =="
grep -h -B1 -A4 '<rule id="6160[0-9]\|<rule id="6161[0-9]\|<rule id="6162[0-9]' $R/0595-win-sysmon_rules.xml 2>/dev/null | grep -E 'rule id|field name="win.system.eventID"|<description>' | head -80
echo "== Defender rule file / base =="
ls $R | grep -i -E 'defender|win'
grep -h -E '<rule id=|<description>|eventID|providerName' $R/*defender* 2>/dev/null | head -30
echo "== Security base (60000-60010, 60103) =="
grep -h -E '<rule id="600(0[0-9]|10|103)"' -A6 $R/0575-win-base_rules.xml | grep -E 'rule id|field|description|if_sid|decoded_as' | head -40
echo "== Existing rules for 4720/4732/1102 =="
grep -l -E '\^4720\$|\^4732\$|\^1102\$' $R/*.xml
grep -h -B3 -A6 -E '\^(4720|4732|1102)\$' $R/*.xml | grep -E 'rule id|level|description|if_sid' | head -20
echo "== PowerShell base rules =="
grep -h -E '<rule id="9(1[0-9]{3})"' $R/*powershell* 2>/dev/null | head -5
ls $R | grep -i powershell
grep -h -B2 -A6 'Microsoft-Windows-PowerShell' $R/*.xml | grep -E 'rule id|description|if_sid|field' | head -12
echo "== local_rules / lists / ruleset section =="
ls -la /var/ossec/etc/rules/ /var/ossec/etc/lists/
sed -n '/<ruleset>/,/<\/ruleset>/p' /var/ossec/etc/ossec.conf
echo "== vulnerability / sca / rootcheck / syscheck on manager =="
sed -n '/<vulnerability-detection>/,/<\/vulnerability-detection>/p' /var/ossec/etc/ossec.conf
grep -A3 '<sca>' /var/ossec/etc/ossec.conf | head -5
grep -A2 '<rootcheck>' /var/ossec/etc/ossec.conf | head -3
echo "== shared agent.conf (default group) =="
cat /var/ossec/etc/shared/default/agent.conf
echo "== agent 001 group =="
/var/ossec/bin/agent_groups -s -i 001 2>/dev/null
echo "== a real Sysmon EID10/EID1 alert sample field names =="
grep '"name":"CA-WIN-01"' /var/ossec/logs/alerts/alerts.json | grep -m1 '"eventID":"1"' | grep -o '"eventdata":{[^}]*}' | head -c 1500; echo
