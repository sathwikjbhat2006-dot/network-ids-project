#!/bin/bash

# ============================================================
#  Simple Intrusion Detection System (IDS)
#  Monitors network traffic and blocks suspicious IPs
#  using iptables based on detected attack patterns
# ============================================================

# ── Configuration ───────────────────────────────────────────

# Network interface to monitor
INTERFACE="eth1"

# SYN packet threshold before triggering CRITICAL alert
THRESHOLD=20

# Number of cycles an IP must appear (low traffic) to be flagged as slow scan
SLOW_SCAN_THRESHOLD=5

# Path to slow scan tracking database
SLOW_SCAN_DB="state/slow_scan.db"

# ── Statistics Counters ──────────────────────────────────────

PACKETS_PROCESSED=0
ALERT_COUNT=0
BLOCKED_COUNT=0
TRUSTED_COUNT=0
CYCLE=0
UDP_DETECTED=0

# ── Initialize Required Files ────────────────────────────────

touch "$SLOW_SCAN_DB"

# ── Functions ────────────────────────────────────────────────

# Display current session statistics
show_stats() {
    echo ""
    echo "===== Security Statistics ====="
    echo "Packets Processed : $PACKETS_PROCESSED"
    echo "Alerts Triggered  : $ALERT_COUNT"
    echo "Blocked IPs       : $BLOCKED_COUNT"
    echo "Trusted Ignored   : $TRUSTED_COUNT"
    echo "================================"
    echo ""
}

# Validate that a string is a proper IPv4 address
# Returns 0 if valid, 1 if invalid
validate_ip() {
    local ip=$1

    # Check basic format: four octets separated by dots
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

        # Check each octet is within valid range 0-255
        if [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ]; then
            return 0  # valid IP
        fi
    fi

    return 1  # invalid IP
}

# ── Main Monitoring Loop ─────────────────────────────────────

echo "Monitoring started on $INTERFACE ..."

while true; do

    # Capture packets for 3 seconds — covers:
    # tcp-syn  : SYN flood detection
    # tcp-fin  : FIN scan detection (nmap -sF)
    # flags==0 : NULL scan detection (nmap -sN)
    # udp      : UDP flood detection (nmap -sU)
    # icmp     : ICMP/ping flood detection
    # XMAS scan (nmap -sX) sets FIN flag so tcp-fin catches it too
    data=$(timeout 3 tcpdump -i "$INTERFACE" -n -l \
        'tcp[tcpflags] & tcp-syn != 0 or
         tcp[tcpflags] & tcp-fin != 0 or
         tcp[tcpflags] == 0 or
         udp or icmp' 2>/dev/null)

    # Count total packets captured this cycle and add to running total
    total=$(echo "$data" | grep -c '.' 2>/dev/null)
    total=${total:-0}
    PACKETS_PROCESSED=$((PACKETS_PROCESSED + total))

    # Extract unique source IPs from captured traffic
    ips=$(echo "$data" | awk '{print $3}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq)

    # ── Per-IP Analysis ──────────────────────────────────────

    for ip in $ips; do

        # Reset all per-IP variables at the start of each iteration
        count=0
        UDP_DETECTED=0
        icmp_count=0
        port_count=0
        fin_count=0
        null_count=0
        REASON="SYN Flood"

        # Validate IP format before using it in any command
        if ! validate_ip "$ip"; then
            echo "[WARN] Skipping invalid IP: $ip"
            continue
        fi

        # Skip IPs in the whitelist — trusted sources
        if grep -q "^$ip$" whitelist.conf 2>/dev/null; then
            TRUSTED_COUNT=$((TRUSTED_COUNT + 1))
            continue
        fi

        # Skip IPs already blocked in iptables — avoid duplicate rules
        if sudo iptables -C INPUT -s "$ip" -j REJECT 2>/dev/null; then
            continue
        fi

        # ── Packet Type Counts ───────────────────────────────

        udp_count=$(echo "$data" | grep "$ip" | grep -c "UDP")
        icmp_count=$(echo "$data" | grep "$ip" | grep -c "ICMP")
        fin_count=$(echo "$data" | grep "$ip" | grep -c "F ")
        null_count=$(echo "$data" | grep "$ip" | grep -c "flags \[.\]")
        port_count=$(echo "$data" | grep "$ip" | grep -oE '\.[0-9]+:' | sort -u | wc -l)

        # ── Detection Logic ──────────────────────────────────
        # Each branch sets count=999 and UDP_DETECTED=1
        # to force the CRITICAL block and permanent ban path

        if [ "$udp_count" -gt 0 ]; then
            # UDP flood detected — permanent block
            UDP_DETECTED=1
            count=999
            REASON="UDP Flood"

        elif [ "$icmp_count" -gt 0 ]; then
            # ICMP flood detected — permanent block
            UDP_DETECTED=1
            count=999
            REASON="ICMP Flood"

        elif [ "$fin_count" -gt 0 ] || [ "$null_count" -gt 0 ]; then
            # FIN/NULL/XMAS scan detected — permanent block
            echo "[CRITICAL] FIN/NULL/XMAS scan detected from $ip"
            UDP_DETECTED=1
            count=999
            REASON="FIN/NULL/XMAS Scan"

        elif [ "$port_count" -gt 10 ]; then
            # Port scan detected — hitting too many different ports
            echo "[CRITICAL] Port scan detected from $ip | Ports hit: $port_count"
            UDP_DETECTED=1
            count=999
            REASON="Port Scan"

        else
            # Default — count SYN packets for threshold comparison
            UDP_DETECTED=0
            count=$(echo "$data" | grep "$ip" | wc -l)
            REASON="SYN Flood"
        fi

        # ── Count Sanitization ───────────────────────────────
        # Guard against empty or non-numeric values from wc -l

        count=${count:-0}
        count=$(echo "$count" | tr -d '[:space:]')
        if ! [[ "$count" =~ ^[0-9]+$ ]]; then
            count=0
        fi

        port_count=${port_count:-0}
        port_count=$(echo "$port_count" | tr -d '[:space:]')
        if ! [[ "$port_count" =~ ^[0-9]+$ ]]; then
            port_count=0
        fi

        # ── Slow Scan Detection ──────────────────────────────
        # Track IPs that consistently send low traffic across
        # multiple cycles — catches stealthy nmap -T1/-T0 scans

        if [ "$count" -gt 0 ] && [ "$count" -lt 11 ]; then

            # IP is active but below alert threshold — track it
            current_hits=$(grep "^$ip " "$SLOW_SCAN_DB" 2>/dev/null | awk '{print $2}')

            if [ -z "$current_hits" ]; then
                # First time seeing this IP — add to tracker
                echo "$ip 1" >> "$SLOW_SCAN_DB"
            else
                # Increment hit counter for this IP
                new_hits=$((current_hits + 1))
                sed -i "s/^$ip .*/$ip $new_hits/" "$SLOW_SCAN_DB"

                # Check if IP has crossed the slow scan threshold
                if [ "$new_hits" -ge "$SLOW_SCAN_THRESHOLD" ]; then
                    echo "[CRITICAL] Slow scan detected from $ip | Cycles: $new_hits"
                    REASON="Slow Scan"
                    UDP_DETECTED=1
                    count=999

                    # Remove from tracker after catching — clean slate
                    sed -i "/^$ip /d" "$SLOW_SCAN_DB"
                fi
            fi

        else
            # IP not active this cycle — decay its counter
            # Prevents false positives from occasional low traffic
            current_hits=$(grep "^$ip " "$SLOW_SCAN_DB" 2>/dev/null | awk '{print $2}')

            if [ -n "$current_hits" ] && [ "$current_hits" -gt 0 ]; then
                new_hits=$((current_hits - 1))

                if [ "$new_hits" -le 0 ]; then
                    # Counter hit zero — remove IP from tracker
                    sed -i "/^$ip /d" "$SLOW_SCAN_DB"
                else
                    sed -i "s/^$ip .*/$ip $new_hits/" "$SLOW_SCAN_DB"
                fi
            fi
        fi

        # ── Alert Levels ─────────────────────────────────────

        # Show raw packet count for any notable activity
        if [ "$count" -ge 3 ]; then
            echo "IP: $ip -> Packets: $count | Reason: $REASON"
        fi

        # INFO — low level activity, just logging
        if [ "$count" -ge 1 ] && [ "$count" -le 10 ]; then
            echo "[INFO] Low traffic activity from $ip"
            show_stats
            echo "[$(date)] INFO: $ip | Reason: $REASON | Packets: $count" >> logs/monitor.log
        fi

        # WARNING — suspicious but below block threshold
        if [ "$count" -ge 11 ] && [ "$count" -le 20 ]; then
            echo "[WARNING] Suspicious activity from $ip"
            show_stats
            echo "[$(date)] WARNING: $ip | Reason: $REASON | Packets: $count" >> logs/monitor.log
        fi

        # CRITICAL — block the IP
        if [ "$count" -gt 20 ]; then

            # Double check not already blocked to avoid duplicate rules and stats
            if ! sudo iptables -C INPUT -s "$ip" -j REJECT 2>/dev/null; then
                ALERT_COUNT=$((ALERT_COUNT + 1))
                sudo iptables -A INPUT -s "$ip" -j REJECT
                echo "[+] Blocked: $ip | Reason: $REASON"
                BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
                show_stats

                # Track repeat offenses in attackers database
                current=$(grep "^$ip " state/attackers.db 2>/dev/null | awk '{print $2}')

                if [ -z "$current" ]; then
                    echo "$ip 1" >> state/attackers.db
                else
                    new_count=$((current + 1))
                    sed -i "s/^$ip .*/$ip $new_count/" state/attackers.db
                fi

                # Write to log with correct reason
                echo "[$(date)] CRITICAL: $ip | Reason: $REASON | Packets: $count | BLOCKED" >> logs/monitor.log

                # ── Auto-Unblock Timer ───────────────────────
                # Runs in background so main loop keeps going
                # Block duration escalates with repeat offenses
                # UDP/ICMP/scan attacks always get permanent block
                (
                    offenses=$(grep "^$ip " state/attackers.db 2>/dev/null | awk '{print $2}')

                    # Default to 1 if not found
                    if [ -z "$offenses" ]; then
                        offenses=1
                    fi

                    # Determine block duration based on offense count
                    # UDP_DETECTED=1 means attack type always gets permanent block
                    if [ "$UDP_DETECTED" -eq 1 ] || [ "$offenses" -ge 4 ]; then
                        block_time="permanent"
                    elif [ "$offenses" -eq 1 ]; then
                        block_time=60      # 1 minute
                    elif [ "$offenses" -eq 2 ]; then
                        block_time=300     # 5 minutes
                    elif [ "$offenses" -eq 3 ]; then
                        block_time=900     # 15 minutes
                    else
                        block_time="permanent"
                    fi

                    echo "[INFO] $ip blocked for $block_time seconds"
                    echo "[$(date)] BLOCK_DURATION: $ip | ${block_time}" >> logs/monitor.log

                    if [ "$block_time" != "permanent" ]; then
                        # Wait then remove iptables rule
                        sleep "$block_time"
                        sudo iptables -D INPUT -s "$ip" -j REJECT
                        echo "[INFO] Unblocked $ip after ${block_time}s"
                        echo "[$(date)] UNBLOCKED: $ip" >> logs/monitor.log
                    else
                        echo "[CRITICAL] Permanent block applied to $ip"
                        echo "[$(date)] PERMANENT_BLOCK: $ip" >> logs/monitor.log
                    fi
                ) &

            fi
        fi

    done

    # ── Maintenance ──────────────────────────────────────────

    # Clean slow scan database every 100 cycles
    # Prevents file from growing indefinitely
    CYCLE=$((CYCLE + 1))
    if [ "$CYCLE" -ge 100 ]; then
        > "$SLOW_SCAN_DB"
        CYCLE=0
    fi

    # Short pause before next capture cycle
    sleep 0.5

done
