#!/bin/sh
set -e

# 1. Ensure system writable directories exist with correct proxy:proxy ownership
mkdir -p /var/cache/squid /var/lib/squid /var/log/squid
chown -R proxy:proxy /var/cache/squid /var/lib/squid /var/log/squid

# 2. Configure system timezone from $TZ if specified
if [ -n "$TZ" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then
    ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
    echo "$TZ" > /etc/timezone
fi

# 3. Locate SSL certgen helper binary
SSL_DB="/var/lib/squid/ssl_db/db"
CERTGEN=""
if [ -x "/usr/lib/squid/security_file_certgen" ]; then
    CERTGEN="/usr/lib/squid/security_file_certgen"
elif [ -x "/usr/lib/squid/ssl_crtd" ]; then
    CERTGEN="/usr/lib/squid/ssl_crtd"
fi

# 4. Initialize SSL DB if not present
if [ ! -d "${SSL_DB}" ]; then
    echo "[entrypoint] Initializing SSL certificate database..."
    chown -R proxy:proxy /var/lib/squid/ssl_db
    if [ -n "$CERTGEN" ]; then
        "$CERTGEN" -c -s "${SSL_DB}" -M 16MB
    else
        echo "[entrypoint] ERROR: Neither security_file_certgen nor ssl_crtd found!"
        exit 1
    fi
    chown -R proxy:proxy /var/lib/squid/ssl_db
    echo "[entrypoint] SSL DB initialized."
fi

# Clean any stale PID files from previous abnormal shutdowns
rm -f /run/squid.pid /var/run/squid.pid

# Process blocklists into bump_domains.acl, domain_blocklists.acl, and url_blocklists.acl
if [ -f "/etc/squid/configs/process_blocklists.py" ]; then
    echo "[entrypoint] Processing blocklists into ACL files..."
    python3 /etc/squid/configs/process_blocklists.py /etc/squid/block-lists /etc/squid/configs || true
fi

# 5. Initialize Squid swap cache directories if running for first time
if [ ! -d "/var/cache/squid/0F/FF" ]; then
    echo "[entrypoint] Initializing cache directories (squid -z)..."
    chown -R proxy:proxy /var/cache/squid
    squid -z -N -F -f /etc/squid/squid.conf
    rm -f /run/squid.pid /var/run/squid.pid
    chown -R proxy:proxy /var/cache/squid
    echo "[entrypoint] Cache directories initialized."
fi

# Set up container-level iptables REDIRECT rules so SO_ORIGINAL_DST is preserved
echo "[entrypoint] Setting up container iptables REDIRECT rules (legacy + nft)..."
iptables-legacy -t nat -F PREROUTING 2>/dev/null || true
iptables-legacy -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 3129 2>/dev/null || true
iptables-legacy -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 3130 2>/dev/null || true
iptables-legacy -t nat -A PREROUTING -p tcp --dport 4070 -j REDIRECT --to-ports 3130 2>/dev/null || true

iptables-nft -t nat -F PREROUTING 2>/dev/null || true
iptables-nft -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3129 2>/dev/null || true
iptables-nft -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 3130 2>/dev/null || true
iptables-nft -t nat -A PREROUTING -p tcp -m tcp --dport 4070 -j REDIRECT --to-ports 3130 2>/dev/null || true

echo "[entrypoint] Starting Squid..."
rm -f /run/squid.pid /var/run/squid.pid
exec squid -NYCd 1 -f /etc/squid/squid.conf
