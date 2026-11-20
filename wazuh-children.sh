#!/bin/bash
# Read-only: list built-in rules chained under given parent rule IDs. Usage: sudo bash wazuh-children.sh 61612 61615 554 550
cd /var/ossec/ruleset/rules
for p in "$@"; do
  echo "== children of $p =="
  grep -B4 -E "<if_sid>([0-9, ]*[ ,])?$p([ ,][0-9, ]*)?</if_sid>" *.xml | grep -o 'rule id="[0-9]*"' | tr '\n' ' '; echo
done
echo "== rule 554 definition =="
grep -h -A10 'rule id="554"' *.xml | head -12
