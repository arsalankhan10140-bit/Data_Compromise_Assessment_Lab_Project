#!/bin/bash
# CA-Lab Phase 1: static host-only IP + indexer heap 1g. Run with sudo.
set -e
TS=$(date +%Y%m%d-%H%M%S)
BK=/root/ca-lab-backup-$TS
mkdir -p "$BK"
cp -a /etc/systemd/network "$BK/"
cp -a /etc/wazuh-indexer/jvm.options "$BK/"
echo "[+] Backups in $BK"

# 1. Static IP on host-only NIC
install -m 0644 /tmp/10-hostonly.network /etc/systemd/network/10-hostonly.network
networkctl reload
networkctl reconfigure eth0
sleep 3
echo "[+] Addresses:"; ip -br a

# 2. Indexer heap 1g
sed -i -E 's/^-Xms[0-9]+[mgMG]?$/-Xms1g/; s/^-Xmx[0-9]+[mgMG]?$/-Xmx1g/' /etc/wazuh-indexer/jvm.options
echo "[+] Heap:"; grep -E '^-Xm[sx]' /etc/wazuh-indexer/jvm.options

# 3. Restart in dependency order
for s in wazuh-indexer wazuh-manager wazuh-dashboard; do
  echo "[+] Restarting $s"; systemctl restart "$s"
done
sleep 20
for s in wazuh-indexer wazuh-manager wazuh-dashboard; do
  printf '%-16s %s\n' "$s" "$(systemctl is-active $s)"
done
echo "[+] Indexer JVM heap flags:"; ps -o args= -C java | grep -o -- '-Xm[sx][0-9]*[mg]' | sort -u
free -m
