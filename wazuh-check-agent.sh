#!/bin/bash
# Read-only: agent status + what CA-WIN-01 is sending. Usage: sudo bash wazuh-check-agent.sh [agent-name]
AG=${1:-CA-WIN-01}
/var/ossec/bin/agent_control -l
echo "--- alert groups from $AG (last 3000 alerts) ---"
tail -n 3000 /var/ossec/logs/alerts/alerts.json | grep "\"name\":\"$AG\"" \
  | grep -o '"groups":\[[^]]*\]' | sort | uniq -c | sort -rn | head -15
echo "--- event channels seen from $AG (last 3000 alerts) ---"
tail -n 3000 /var/ossec/logs/alerts/alerts.json | grep "\"name\":\"$AG\"" \
  | grep -o '"channel":"[^"]*"' | sort | uniq -c | sort -rn
