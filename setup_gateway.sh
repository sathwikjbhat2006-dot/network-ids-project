#!/bin/bash

echo "[+] Setting up gateway..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Bring interface up
ip link set eth1 up

# Remove old IP (avoid duplicates)
ip addr flush dev eth1

# Assign correct IP
ip addr add 192.168.100.1/24 dev eth1

# Verify assignment
ip a | grep 192.168.100.1 >/dev/null
if [ $? -ne 0 ]; then
    echo "[!] ERROR: IP not assigned to eth1"
    exit 1
fi

echo "[+] IP assigned to eth1"

# Reset firewall
sudo iptables -F
sudo iptables -t nat -F
iptables -X

# Set default policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow internal network
sudo iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT

echo "[+] Firewall configured"

echo "[✓] Gateway setup complete"
