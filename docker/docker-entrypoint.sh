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

# Dynamically generate bump_domains.acl from raw blocklist files on container startup
if [ -f "/etc/squid/configs/generate_bump_domains.py" ]; then
    echo "[entrypoint] Generating /etc/squid/configs/bump_domains.acl..."
    python3 /etc/squid/configs/generate_bump_domains.py /etc/squid/block-lists /etc/squid/configs/bump_domains.acl || true
fi

# ------------------------------------------------------------------------------
# FAIL-CLOSED GUARD: rules.acl and ssl_bump.acl must agree.
#
# rules.acl scopes its denies to '!CONNECT' so that intercepted HTTPS is allowed
# to reach the ssl_bump stage, gets bumped, and can be shown the block page on the
# decrypted request. That is only safe while ssl_bump.acl actually contains the
# matching 'ssl_bump bump' rules. If the two ever desync — a stale volume, a
# partial deploy, a hand-edit — the CONNECT is allowed but never bumped, falls
# through to 'http_access allow localnet', and EVERY blocked HTTPS site becomes
# reachable. Parental controls must fail closed, never open.
#
# When a desync is detected, strip the '!CONNECT' scoping so the denies apply at
# the CONNECT stage again. Blocked sites then fail with a TLS error instead of a
# pretty block page — degraded, but blocked. The Web UI restores the full
# behaviour on its next compile.
# ------------------------------------------------------------------------------
RULES_ACL="/etc/squid/configs/rules.acl"
SSL_BUMP_ACL="/etc/squid/configs/ssl_bump.acl"

if [ -f "${RULES_ACL}" ] && grep -q '^http_access deny !CONNECT' "${RULES_ACL}" 2>/dev/null; then
    if ! grep -qE '^ssl_bump[[:space:]]+bump[[:space:]]' "${SSL_BUMP_ACL}" 2>/dev/null; then
        echo "[entrypoint] ***********************************************************"
        echo "[entrypoint] FAIL-CLOSED: rules.acl uses '!CONNECT' deny scoping but"
        echo "[entrypoint] ssl_bump.acl contains NO bump rules. Blocked HTTPS sites"
        echo "[entrypoint] would tunnel through unfiltered. Removing the scoping so"
        echo "[entrypoint] denies apply at the CONNECT stage."
        echo "[entrypoint] Re-run Save & Apply in the Web UI to restore block pages."
        echo "[entrypoint] ***********************************************************"
        sed -i 's/^http_access deny !CONNECT /http_access deny /' "${RULES_ACL}"
    else
        echo "[entrypoint] ACL pairing OK: '!CONNECT' denies are backed by bump rules."
    fi
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

# Squid only rotates logs when explicitly signalled. Run the rotation at local
# midnight; logfile_rotate in squid.conf controls how many numbered files stay
# available to the WebUI analytics reader.
rotate_logs_daily() {
    while :; do
        now_epoch=$(date +%s)
        next_midnight_epoch=$(date -d 'tomorrow 00:00:00' +%s)
        wait_seconds=$((next_midnight_epoch - now_epoch))
        [ "${wait_seconds}" -gt 0 ] || wait_seconds=60
        sleep "${wait_seconds}"

        if squid -k rotate -f /etc/squid/squid.conf; then
            echo "[entrypoint] Daily Squid log rotation completed."
        else
            echo "[entrypoint] WARNING: Daily Squid log rotation failed." >&2
        fi
    done
}

rotate_logs_daily &
exec squid -NYCd 1 -f /etc/squid/squid.conf
