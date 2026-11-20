#!/bin/bash
# CA-Lab Phase 3 deploy: rules, CDB IOC lists, centralized agent.conf. Run with sudo.
# Expects files staged in /tmp/ca-p3/  (local_ca_rules.xml, agent.conf, lists/*, logtest-samples.txt)
set -e
S=/tmp/ca-p3
O=/var/ossec
TS=$(date +%Y%m%d-%H%M%S)
BK=/root/ca-lab-backup-p3-$TS
mkdir -p "$BK"
cp -a $O/etc/ossec.conf $O/etc/rules $O/etc/lists $O/etc/shared/default/agent.conf "$BK/"
echo "[+] Backup: $BK"

# --- rules
install -o wazuh -g wazuh -m 660 $S/local_ca_rules.xml $O/etc/rules/local_ca_rules.xml
# --- CDB lists
install -d -o wazuh -g wazuh -m 770 $O/etc/lists/ca-ioc
for l in ca-ioc-hashes ca-ioc-ips ca-ioc-domains; do
  tr -d '\r' < $S/lists/$l > $O/etc/lists/ca-ioc/$l
  chown wazuh:wazuh $O/etc/lists/ca-ioc/$l; chmod 660 $O/etc/lists/ca-ioc/$l
  if ! grep -q "<list>etc/lists/ca-ioc/$l</list>" $O/etc/ossec.conf; then
    sed -i "0,/<list>etc\/lists\/malicious-ioc\/malicious-domains<\/list>/s//&\n    <list>etc\/lists\/ca-ioc\/$l<\/list>/" $O/etc/ossec.conf
  fi
done
echo "[+] Lists registered:"; grep -n 'ca-ioc' $O/etc/ossec.conf
# --- centralized agent config
tr -d '\r' < $S/agent.conf > $O/etc/shared/default/agent.conf
chown wazuh:wazuh $O/etc/shared/default/agent.conf; chmod 660 $O/etc/shared/default/agent.conf
echo "[+] verify-agent-conf:"; $O/bin/verify-agent-conf -f $O/etc/shared/default/agent.conf

# --- validate whole config + ruleset before restart
echo "[+] wazuh-analysisd -t (config/ruleset test):"
if ! $O/bin/wazuh-analysisd -t; then
  echo "[!] Validation FAILED - restoring backup"; cp -a "$BK/ossec.conf" $O/etc/ossec.conf
  rm -f $O/etc/rules/local_ca_rules.xml; exit 1
fi
echo "[+] Validation OK -> restarting wazuh-manager"
systemctl restart wazuh-manager
sleep 15
systemctl is-active wazuh-manager
ls -la $O/etc/lists/ca-ioc/

# NOTE: wazuh-logtest cannot validate Windows eventchannel rules in 4.14: the windows_eventchannel
# decoder is internal to analysisd and only applied to events from a real agent, so logtest decodes
# the JSON as plain 'json' and the 60000 tree never matches. Validation is done LIVE instead:
# scripts/phase3-live-test.ps1 in the VM + scripts/wazuh-ca-rule-hits.py on the manager.
echo "[+] Deployed. Validate live with phase3-live-test.ps1 + wazuh-ca-rule-hits.py"
