# Network Intrusion Detection System (IDS)

A bash-based IDS built on a two-VM lab environment that monitors
network traffic and automatically blocks suspicious IPs using
tcpdump and iptables.

## Architecture
- VM1 — Gateway running the IDS (monitor.sh)
- VM2 — Attacker machine running nmap, hping3, ping

## Files
- monitor.sh — Main IDS engine
- setup_gateway.sh — Configures IP and firewall on VM1
- reset.sh — Flushes rules, clears logs and database
- whitelist.conf — Trusted IPs never blocked
- state/attackers.db — Tracks repeat offenders
- logs/monitor.log — Records all detected events

## Attacks Detected
- SYN Flood — escalating block (60s → 300s → 900s → permanent)
- UDP Flood — permanent block immediately
- ICMP Flood — permanent block immediately
- FIN/NULL/XMAS Scan — permanent block immediately
- Port Scan — permanent block immediately
- Slow Scan — tracked across cycles, permanent block after 5 hits

## Tools Used
bash, tcpdump, iptables, nmap, hping3

## How to Run

### VM1 — Gateway setup
sudo bash setup_gateway.sh
sudo bash monitor.sh

### VM2 — Attack simulation

SYN flood
nmap -sS -T5 192.168.100.1

UDP flood
sudo nmap -sU 192.168.100.1

ICMP flood
sudo ping -f 192.168.100.1

Port scan
nmap -p 1-100 192.168.100.1

FIN scan
sudo nmap -sF 192.168.100.1

NULL scan
sudo nmap -sN 192.168.100.1

XMAS scan
sudo nmap -sX 192.168.100.1

### Reset environment
sudo bash reset.sh

## Known Limitations
- Cannot detect nmap T0/T1 timing (too slow for capture window)
- Bash based, not suitable for production environments
- iptables rules lost on reboot

## What I Learned
- Packet capture and analysis using tcpdump
- Firewall management using iptables
- TCP/IP networking and TCP flag inspection
- Attack detection logic and threshold tuning
- Two VM lab network setup
- Repeat offender tracking and escalating punishment logic
