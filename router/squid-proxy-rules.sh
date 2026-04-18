#!/bin/sh
# /jffs/scripts/squid-proxy-rules.sh
# MANAGED-BY-SQUID-MGMT — regenerate with: squid-mgmt.sh router-deploy

SQUID_IP="192.168.1.90"
SQUID_HTTP_PORT="3129"
SQUID_HTTPS_PORT="3130"
CHAIN="SQUID_REDIRECT"

# Flush/recreate only our chain; all other chains are untouched
iptables -t nat -N "$CHAIN" 2>/dev/null
iptables -t nat -F "$CHAIN"
iptables -t nat -D PREROUTING -j "$CHAIN" 2>/dev/null
iptables -t nat -I PREROUTING 1 -j "$CHAIN"

# Exempt Squid proxy and QNAP server from redirection to prevent forwarding loops
iptables -t nat -A "$CHAIN" -s "$SQUID_IP" -j RETURN
iptables -t nat -A "$CHAIN" -s 192.168.1.2 -j RETURN

# Always MASQUERADE LAN traffic redirected to Squid proxy
iptables -t nat -D POSTROUTING -d "$SQUID_IP" -p tcp -m multiport --dports 80,443,4070 -j MASQUERADE 2>/dev/null
iptables -t nat -I POSTROUTING 1 -d "$SQUID_IP" -p tcp -m multiport --dports 80,443,4070 -j MASQUERADE

# Setup ipset for YouTube QUIC traffic if ipset tool is present
if command -v ipset >/dev/null 2>&1; then
    ipset create youtube_quic hash:net 2>/dev/null || true
    for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16 216.239.32.0/19 64.233.160.0/19 66.249.64.0/19 72.14.192.0/18 209.85.128.0/17; do
        ipset add youtube_quic "$cidr" 2>/dev/null || true
    done
fi

add_host() {
    # $1 = source host IP
    # Allow QUIC (UDP 443/80) for YouTube video traffic so YouTube playback uses QUIC protocol
    if command -v ipset >/dev/null 2>&1 && ipset list youtube_quic >/dev/null 2>&1; then
        iptables -D FORWARD -s "$1" -p udp -m multiport --dports 80,443 -m set --match-set youtube_quic dst -j ACCEPT 2>/dev/null || true
        iptables -I FORWARD 1 -s "$1" -p udp -m multiport --dports 80,443 -m set --match-set youtube_quic dst -j ACCEPT
    else
        for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16; do
            iptables -D FORWARD -s "$1" -d "$cidr" -p udp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null || true
            iptables -I FORWARD 1 -s "$1" -d "$cidr" -p udp -m multiport --dports 80,443 -j ACCEPT
        done
    fi

    # Block QUIC (UDP 443) for all other services so browsers fall back to TCP 443 for transparent proxy interception
    iptables -D FORWARD -s "$1" -p udp --dport 443 -j REJECT 2>/dev/null || true
    iptables -I FORWARD 2 -s "$1" -p udp --dport 443 -j REJECT

    iptables -t nat -A "$CHAIN" -s "$1" -d "$SQUID_IP" -j RETURN
    iptables -t nat -A "$CHAIN" -s "$1" -p tcp --dport 80   -j DNAT --to-destination "$SQUID_IP:80"
    iptables -t nat -A "$CHAIN" -s "$1" -p tcp --dport 443  -j DNAT --to-destination "$SQUID_IP:443"
    iptables -t nat -A "$CHAIN" -s "$1" -p tcp --dport 4070 -j DNAT --to-destination "$SQUID_IP:4070"
}

# --- Per-host rules ---
add_host "192.168.8.30"   # vm-ubuntu
