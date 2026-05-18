#!/bin/sh
# /jffs/scripts/squid-proxy-rules.sh
# MANAGED-BY-SQUID-MGMT — regenerate and deploy with: squid-mgmt.sh router-deploy
#
# ==============================================================================
# SINGLE SOURCE OF TRUTH for the router-side transparent proxy rules.
#
# 'squid-mgmt.sh router-deploy' copies this file, substitutes SQUID_IP, appends
# one add_host line per entry in router/proxy-hosts.conf, and uploads the result
# to the router. Do not hand-edit the copy on the router — it is overwritten.
#
# MECHANISM: policy routing, NOT DNAT.
#
# Marked packets keep their ORIGINAL destination address and are routed to the
# Squid container, which recovers the intended destination via SO_ORIGINAL_DST
# from its own iptables REDIRECT rules. This is required for correctness:
#
#   * A DNAT + MASQUERADE approach rewrites the SOURCE address to the router's,
#     so every request reaches Squid from 192.168.0.1. All per-device 'src' ACLs
#     then collapse to a single client and parental controls silently stop
#     distinguishing between devices — filtering appears to work while applying
#     the wrong policy to everyone.
#   * Preserving the client IP is what makes rules.acl's
#     'acl src_dev_<ip> src <ip>' lines meaningful.
# ==============================================================================

SQUID_IP="192.168.1.90"

# --- Clean up the legacy DNAT chain, if an older revision left one behind ---
iptables -t nat -D PREROUTING -j SQUID_REDIRECT 2>/dev/null || true
iptables -t nat -F SQUID_REDIRECT 2>/dev/null || true
iptables -t nat -X SQUID_REDIRECT 2>/dev/null || true
# The old MASQUERADE rules must go too, or they keep rewriting client source IPs.
iptables -t nat -D POSTROUTING -d "$SQUID_IP" -p tcp -m multiport --dports 80,443,4070 -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -d "$SQUID_IP" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null || true

# --- Disable rp_filter so asymmetric return packets are not dropped ---
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
echo 0 > /proc/sys/net/ipv4/conf/br0/rp_filter 2>/dev/null || true

# --- Policy routing table 150: send marked packets to Squid, destination intact ---
ip rule del pref 10 2>/dev/null || true
ip rule del fwmark 0x5000/0x5000 2>/dev/null || true
ip rule add pref 10 fwmark 0x5000/0x5000 table 150 2>/dev/null || true
ip route flush table 150 2>/dev/null || true
ip route add default via "$SQUID_IP" dev br0 table 150 2>/dev/null || true

# --- mangle chain SQUID_MARK: flush/recreate ours only, leave other chains alone ---
iptables -t mangle -N SQUID_MARK 2>/dev/null || true
iptables -t mangle -F SQUID_MARK
iptables -t mangle -D PREROUTING -j SQUID_MARK 2>/dev/null || true
iptables -t mangle -I PREROUTING 1 -j SQUID_MARK

# --- Exempt Squid itself and the NAS to prevent forwarding loops ---
iptables -t mangle -A SQUID_MARK -s "$SQUID_IP" -j RETURN
iptables -t mangle -A SQUID_MARK -s 192.168.1.2 -j RETURN

# --- ipset of Google/YouTube ranges allowed to keep using QUIC ---
if command -v ipset >/dev/null 2>&1; then
    ipset create youtube_quic hash:net 2>/dev/null || true
    for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16 \
                216.239.32.0/19 64.233.160.0/19 66.249.64.0/19 72.14.192.0/18 209.85.128.0/17; do
        ipset add youtube_quic "$cidr" 2>/dev/null || true
    done
fi

add_host() {
    # $1 = source host IP
    #
    # QUIC handling is deliberately two-sided and BOTH halves are required:
    #   1. ACCEPT UDP 80/443 toward YouTube ranges — playback stays on QUIC and
    #      does not degrade.
    #   2. REJECT all other UDP 443 — without this, any HTTPS site can negotiate
    #      QUIC and bypass the proxy entirely, since Squid only ever sees TCP.
    # Rule 1 is inserted at position 1 and rule 2 at position 2, so the YouTube
    # allow is always evaluated before the blanket reject.
    if command -v ipset >/dev/null 2>&1 && ipset list youtube_quic >/dev/null 2>&1; then
        iptables -D FORWARD -s "$1" -p udp -m multiport --dports 80,443 -m set --match-set youtube_quic dst -j ACCEPT 2>/dev/null || true
        iptables -I FORWARD 1 -s "$1" -p udp -m multiport --dports 80,443 -m set --match-set youtube_quic dst -j ACCEPT
    else
        for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16; do
            iptables -D FORWARD -s "$1" -d "$cidr" -p udp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null || true
            iptables -I FORWARD 1 -s "$1" -d "$cidr" -p udp -m multiport --dports 80,443 -j ACCEPT
        done
    fi

    iptables -D FORWARD -s "$1" -p udp --dport 443 -j REJECT 2>/dev/null || true
    iptables -I FORWARD 2 -s "$1" -p udp --dport 443 -j REJECT

    # Mark TCP 80 / 443 / 4070 (Spotify AP) for policy routing to Squid.
    iptables -t mangle -A SQUID_MARK -s "$1" -p tcp -m multiport --dports 80,443,4070 -j MARK --set-mark 0x5000/0x5000
}

# --- Per-host rules ---
