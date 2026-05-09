#!/bin/bash

echo "[*] Resetting firewall..."

# Flush all iptables rules
sudo iptables -F

# Flush NAT table
sudo iptables -t nat -F

# Delete custom chains
sudo iptables -X

# Restore default policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

echo "[+] Firewall reset complete"

#clear attacker database
> state/attackers.db

#clear logs
>logs/monitor.log

echo "[+] State database cleared"
echo "[+] Logs cleared"
