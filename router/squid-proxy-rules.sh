#!/bin/sh
# /jffs/scripts/squid-proxy-rules.sh
# MANAGED-BY-SQUID-MGMT — regenerate and deploy with: squid-mgmt.sh router-deploy
#
# ==============================================================================
# SINGLE SOURCE OF TRUTH for the router-side transparent proxy rules.
#
# 'squid-mgmt.sh router-deploy' copies this file, substitutes deployment values, appends
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
#     so every request reaches Squid from the router. All per-device 'src' ACLs
#     then collapse to a single client and parental controls silently stop
#     distinguishing between devices — filtering appears to work while applying
#     the wrong policy to everyone.
#   * Preserving the client IP is what makes rules.acl's
#     'acl src_dev_<ip> src <ip>' lines meaningful.
# ==============================================================================

SQUID_IP="192.0.2.90"
NAS_IP="192.0.2.2"
LAN_INTERFACE="br0"
ROUTE_TABLE="150"
ROUTE_MARK="0x5000"

# --- Clean up the legacy DNAT chain, if an older revision left one behind ---
iptables -t nat -D PREROUTING -j SQUID_REDIRECT 2>/dev/null || true
iptables -t nat -F SQUID_REDIRECT 2>/dev/null || true
iptables -t nat -X SQUID_REDIRECT 2>/dev/null || true
# The old MASQUERADE rules must go too, or they keep rewriting client source IPs.
iptables -t nat -D POSTROUTING -d "$SQUID_IP" -p tcp -m multiport --dports 80,443,4070 -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -d "$SQUID_IP" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null || true

# --- Disable rp_filter so asymmetric return packets are not dropped ---
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
echo 0 > "/proc/sys/net/ipv4/conf/${LAN_INTERFACE}/rp_filter" 2>/dev/null || true

# --- Policy routing: send marked packets to Squid, destination intact ---
ip rule del pref 10 2>/dev/null || true
ip rule del fwmark "${ROUTE_MARK}/${ROUTE_MARK}" 2>/dev/null || true
ip rule add pref 10 fwmark "${ROUTE_MARK}/${ROUTE_MARK}" table "${ROUTE_TABLE}" 2>/dev/null || true
ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
ip route add default via "$SQUID_IP" dev "${LAN_INTERFACE}" table "${ROUTE_TABLE}" 2>/dev/null || true

# --- mangle chain SQUID_MARK: flush/recreate ours only, leave other chains alone ---
iptables -t mangle -N SQUID_MARK 2>/dev/null || true
iptables -t mangle -F SQUID_MARK
iptables -t mangle -D PREROUTING -j SQUID_MARK 2>/dev/null || true
iptables -t mangle -I PREROUTING 1 -j SQUID_MARK

# --- Exempt Squid itself and the NAS to prevent forwarding loops ---
iptables -t mangle -A SQUID_MARK -s "$SQUID_IP" -j RETURN
iptables -t mangle -A SQUID_MARK -s "$NAS_IP" -j RETURN

# --- Google/YouTube ranges that may use QUIC unless a client opts out ---
if command -v ipset >/dev/null 2>&1; then
    ipset create youtube_quic hash:net 2>/dev/null || true
    for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16 \
                216.239.32.0/19 64.233.160.0/19 66.249.64.0/19 72.14.192.0/18 209.85.128.0/17; do
        ipset add youtube_quic "$cidr" 2>/dev/null || true
    done
fi

add_host() {
    # $1 = source host IP
    # $2 = optional "no_quic" flag
    # $3 = optional "no_vpn" flag (currently blocks Cloudflare WARP)
    #
    # Always remove both possible forms of the YouTube exception first. This
    # makes changing a client between modes idempotent on an already configured
    # router and cleans up rules produced by older revisions.
    if command -v ipset >/dev/null 2>&1 && ipset list youtube_quic >/dev/null 2>&1; then
        while iptables -D FORWARD -s "$1" -p udp -m multiport --dports 80,443 -m set --match-set youtube_quic dst -j ACCEPT 2>/dev/null; do :; done
    fi
    for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16; do
        while iptables -D FORWARD -s "$1" -d "$cidr" -p udp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null; do :; done
    done

    while iptables -D FORWARD -s "$1" -p udp --dport 443 -j REJECT 2>/dev/null; do :; done

    if [ "${2:-}" = "no_quic" ]; then
        # Squid only handles TCP. Rejecting all UDP/443 makes browsers retry over
        # TCP/443 so category blocks can render ERR_ACCESS_DENIED over HTTPS.
        iptables -I FORWARD 1 -s "$1" -p udp --dport 443 -j REJECT
    else
        # Default mode preserves YouTube QUIC performance, while the following
        # catch-all reject prevents every other HTTP/3 destination bypassing Squid.
        # Insert the reject first, then place every exception above it. This also
        # keeps all CIDR fallback rules ahead of the reject when ipset is absent.
        iptables -I FORWARD 1 -s "$1" -p udp --dport 443 -j REJECT
        if command -v ipset >/dev/null 2>&1 && ipset list youtube_quic >/dev/null 2>&1; then
            iptables -I FORWARD 1 -s "$1" -p udp -m multiport --dports 80,443 -m set --match-set youtube_quic dst -j ACCEPT
        else
            for cidr in 172.217.0.0/16 142.250.0.0/16 173.194.0.0/16 216.58.0.0/16 74.125.0.0/16; do
                iptables -I FORWARD 1 -s "$1" -d "$cidr" -p udp -m multiport --dports 80,443 -j ACCEPT
            done
        fi
    fi

    # Remove any prior per-client WARP policy first so toggling no_vpn in
    # proxy-hosts.conf is idempotent. These are Cloudflare's documented consumer,
    # WireGuard, MASQUE and FedRAMP ingress ranges, the endpoint observed on this
    # network, and the two client orchestration API addresses.
    for vpn_cidr in \
        162.159.192.0/24 \
        162.159.193.0/24 \
        162.159.197.0/24 \
        162.159.198.0/24 \
        162.159.239.0/24 \
        162.159.137.105/32 \
        162.159.138.105/32; do
        while iptables -D FORWARD -s "$1" -d "$vpn_cidr" -j REJECT 2>/dev/null; do :; done
    done

    if [ "${3:-}" = "no_vpn" ]; then
        for vpn_cidr in \
            162.159.192.0/24 \
            162.159.193.0/24 \
            162.159.197.0/24 \
            162.159.198.0/24 \
            162.159.239.0/24 \
            162.159.137.105/32 \
            162.159.138.105/32; do
            iptables -I FORWARD 1 -s "$1" -d "$vpn_cidr" -j REJECT
            # Drop an already-established/offloaded WARP flow so the new policy
            # takes effect immediately instead of waiting for tunnel expiry.
            if [ -x /usr/sbin/conntrack ]; then
                /usr/sbin/conntrack -D -s "$1" -d "$vpn_cidr" >/dev/null 2>&1 || true
            fi
        done
    fi

    # Mark TCP 80 / 443 / 4070 (Spotify AP) for policy routing to Squid.
    iptables -t mangle -A SQUID_MARK -s "$1" -p tcp -m multiport --dports 80,443,4070 -j MARK --set-mark "${ROUTE_MARK}/${ROUTE_MARK}"
}

# --- Per-host rules ---
