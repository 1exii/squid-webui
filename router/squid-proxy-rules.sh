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
iptables -t nat -D POSTROUTING -d "$SQUID_IP" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null
iptables -t nat -I POSTROUTING 1 -d "$SQUID_IP" -p tcp -m multiport --dports 80,443 -j MASQUERADE

add_host() {
    # $1 = source host IP
    # Block QUIC (UDP 443) so browsers fall back to TCP 443 for transparent proxy interception
    iptables -D FORWARD -s "$1" -p udp --dport 443 -j REJECT 2>/dev/null
    iptables -I FORWARD 1 -s "$1" -p udp --dport 443 -j REJECT
    iptables -t nat -A "$CHAIN" -s "$1" -d "$SQUID_IP" -j RETURN
    iptables -t nat -A "$CHAIN" -s "$1" -p tcp --dport 80  -j DNAT --to-destination "$SQUID_IP:80"
    iptables -t nat -A "$CHAIN" -s "$1" -p tcp --dport 443 -j DNAT --to-destination "$SQUID_IP:443"
}

# --- Per-host rules ---
add_host "192.168.8.30"   # vm-ubuntu
