#!/bin/bash
# Read-only: show the Wazuh VM network configuration
for f in /etc/systemd/network/* /run/systemd/network/*; do echo "== $f"; cat "$f"; done
echo "== /usr/lib/systemd/network"; ls /usr/lib/systemd/network/
echo "== ifcfg-eth0"; cat /etc/sysconfig/network-scripts/ifcfg-eth0
echo "== MACs"; for i in eth0 eth1; do echo "$i $(cat /sys/class/net/$i/address)"; done
echo "== routes"; ip route
echo "== networkctl"; networkctl list --no-pager
