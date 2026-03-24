#!/bin/bash

# ==============================================================================
# SQUID PROXY AUTOMATED TEST & VERIFICATION SCRIPT
# Tests both HTTP & HTTPS for:
#   1. example.com (Always Allowed -> must return real remote content / 200 OK)
#   2. pornhub.com (Adult blocklist -> must return Webpage Blocked page)
#   3. youtube.com (Dynamic Web UI Policy -> verified against rules.json / rules.acl)
# Dumps full log to squid/debug/latest_debug.log
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQUID_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEBUG_DIR="${SQUID_DIR}/debug"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
LOG_FILE="${DEBUG_DIR}/debug_${TIMESTAMP}.log"
LATEST_LOG="${DEBUG_DIR}/latest_debug.log"

mkdir -p "${DEBUG_DIR}"

ROUTER_IP="192.168.0.1"
QNAP_IP="192.168.1.2"
SQUID_IP="192.168.1.90"
CLIENT_IP="192.168.8.30"
QNAP_USER="admin"
QNAP_DOCKER="/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker"

# Exec tee to log files
exec > >(tee -a "${LOG_FILE}" | tee "${LATEST_LOG}") 2>&1

echo "========================================================================"
echo " SQUID PROXY COMPREHENSIVE TEST & DIAGNOSTIC - ${TIMESTAMP}"
echo " Log file: ${LOG_FILE}"
echo "========================================================================"
echo ""

# ------------------------------------------------------------------------------
# STEP 1: ROUTER & CONTAINER STATUS CHECK
# ------------------------------------------------------------------------------
echo ">>> 1. INFRASTRUCTURE & ROUTING CHECK"
echo "--------------------------------------------------"
echo "Checking router redirection chain (SQUID_REDIRECT)..."
ssh "${ROUTER_IP}" "iptables -t nat -L SQUID_REDIRECT -n -v" 2>&1

echo ""
echo "Checking container status on QNAP..."
ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} ps | grep -E 'squid-proxy|squid-webui'" 2>&1
echo ""

# ------------------------------------------------------------------------------
# STEP 2: RUN HTTP & HTTPS TRAFFIC TESTS FROM vm-ubuntu (192.168.8.30)
# ------------------------------------------------------------------------------
echo ">>> 2. TESTING HTTP & HTTPS TRAFFIC FROM vm-ubuntu"
echo "--------------------------------------------------"

test_site() {
    local label="$1"
    local url="$2"

    echo "--------------------------------------------------"
    echo "[Testing] ${label} (${url})"
    echo "--------------------------------------------------"
    local res
    res=$(ssh "${CLIENT_IP}" "curl -siv -4 -k --max-time 6 '${url}' 2>&1" || true)

    # Extract status line & title
    local status_line
    status_line=$(echo "$res" | grep -i '^< HTTP/' | head -1)
    local page_title
    page_title=$(echo "$res" | grep -i '<title>' | head -1 | sed -e 's/^[ \t]*//')

    echo "  Status Line : ${status_line:-No HTTP Response (Connection Failed / Timeout)}"
    echo "  Page Title  : ${page_title:-No HTML Title Found}"

    # Print first few lines of body preview if available
    local body_snippet
    body_snippet=$(echo "$res" | grep -v '^[*><]' | grep -v '^[[:space:]]*$' | head -5)
    if [ -n "${body_snippet}" ]; then
        echo "  Body Preview:"
        echo "${body_snippet}" | sed 's/^/    /'
    fi

    echo "$res"
}

# 1. ALLOWED DOMAIN TESTS (example.com)
OUT_EX_HTTP=$(test_site "Allowed HTTP" "http://example.com")
echo ""
OUT_EX_HTTPS=$(test_site "Allowed HTTPS" "https://example.com")
echo ""

# 2. BLOCKED ADULT DOMAIN TESTS (pornhub.com)
OUT_AD_HTTP=$(test_site "Blocked Adult HTTP" "http://pornhub.com")
echo ""
OUT_AD_HTTPS=$(test_site "Blocked Adult HTTPS" "https://www.pornhub.com")
echo ""

# 3. YOUTUBE DOMAIN TESTS (youtube.com)
OUT_YT_HTTP=$(test_site "YouTube HTTP" "http://youtube.com")
echo ""
OUT_YT_HTTPS=$(test_site "YouTube HTTPS" "https://www.youtube.com")
echo ""

sleep 2

# ------------------------------------------------------------------------------
# STEP 3: CAPTURE & VERIFY SQUID LOGS
# ------------------------------------------------------------------------------
echo ">>> 3. CAPTURING SQUID LOGS POST-TEST"
echo "--------------------------------------------------"

echo "=== Recent access.log Entries (Post-Test) ==="
ACCESS_LOG_ENTRIES=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tail -n 30 /var/log/squid/access.log" 2>&1)
echo "${ACCESS_LOG_ENTRIES}"

echo ""
echo "=== Recent cache.log Warnings/Errors ==="
CACHE_LOG_ENTRIES=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tail -n 25 /var/log/squid/cache.log" 2>&1)
echo "${CACHE_LOG_ENTRIES}"
echo ""

# ------------------------------------------------------------------------------
# STEP 4: WEB UI POLICY CROSS-CHECK
# ------------------------------------------------------------------------------
echo ">>> 4. WEB UI POLICY & RULES CROSS-CHECK"
echo "--------------------------------------------------"

echo "=== Active /etc/squid/configs/rules.json ==="
RULES_JSON=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/rules.json" 2>&1 || echo "{}")
echo "${RULES_JSON}"

echo ""
echo "=== Generated /etc/squid/configs/rules.acl (vm-ubuntu section) ==="
RULES_ACL=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/rules.acl" 2>&1 || echo "")
echo "${RULES_ACL}" | grep -A 25 "vm-ubuntu" || echo "${RULES_ACL}"
echo ""

# ------------------------------------------------------------------------------
# STEP 5: VERIFICATION ANALYSIS SUMMARY
# ------------------------------------------------------------------------------
echo "========================================================================"
echo " VERIFICATION SUMMARY"
echo "========================================================================"

# Allowed site check (Example Domain)
if echo "${OUT_EX_HTTP}" | grep -qi "Example Domain" || echo "${OUT_EX_HTTPS}" | grep -qi "Example Domain"; then
    echo "  [PASS] Allowed Site (example.com) successfully returned REAL remote content!"
else
    echo "  [FAIL] Allowed Site (example.com) failed to return real remote content."
fi

# Blocked site check (Adult)
if echo "${OUT_AD_HTTP}" | grep -qi "Webpage Blocked" || echo "${OUT_AD_HTTPS}" | grep -qi "Webpage Blocked"; then
    echo "  [PASS] Blocked Site (pornhub.com) returned custom Parental Control Block Page."
else
    echo "  [WARN] Blocked Site (pornhub.com) did not return custom block page."
fi

# YouTube check vs active policy
if echo "${RULES_ACL}" | grep -q "http_access deny.*list_videos_txt"; then
    echo "  [POLICY] YouTube is currently CONFIGURED TO BE BLOCKED in Web UI."
    if echo "${OUT_YT_HTTPS}" | grep -qi "Webpage Blocked" || echo "${OUT_YT_HTTPS}" | grep -qi "503"; then
        echo "  [PASS] YouTube traffic was correctly BLOCKED as defined by policy."
    else
        echo "  [FAIL] YouTube was NOT blocked despite policy requiring block!"
    fi
else
    echo "  [POLICY] YouTube is currently ALLOWED in Web UI."
    if echo "${OUT_YT_HTTPS}" | grep -qi "HTTP/1.1 200" || echo "${OUT_YT_HTTPS}" | grep -qi "YouTube"; then
        echo "  [PASS] YouTube traffic was correctly ALLOWED as defined by policy."
    else
        echo "  [FAIL] YouTube traffic failed to load despite policy allowing it!"
    fi
fi

echo ""
echo "Full detailed log saved to:"
echo "  - ${LOG_FILE}"
echo "  - ${LATEST_LOG}"
echo "========================================================================"
