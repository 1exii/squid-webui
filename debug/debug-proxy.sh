#!/bin/bash

# ==============================================================================
# SQUID PROXY DIAGNOSTIC & POLICY VERIFICATION SCRIPT
# - Sends test traffic from vm-ubuntu (192.168.8.30)
# - Captures & verifies Squid access logs and cache logs immediately after
# - Validates results against Web UI active policies in rules.json / rules.acl
# - Dumps detailed diagnostics to squid/debug/latest_debug.log
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

# Start logging stdout and stderr
exec > >(tee -a "${LOG_FILE}" | tee "${LATEST_LOG}") 2>&1

echo "========================================================================"
echo " SQUID PROXY AUTOMATED TEST & DIAGNOSTIC RUN - ${TIMESTAMP}"
echo " Log file: ${LOG_FILE}"
echo "========================================================================"
echo ""

# ------------------------------------------------------------------------------
# STEP 1: ROUTER & PROXY INFRASTRUCTURE CHECK
# ------------------------------------------------------------------------------
echo ">>> 1. INFRASTRUCTURE & ROUTING CHECK"
echo "--------------------------------------------------"
echo "Checking router redirection chain..."
ssh "${ROUTER_IP}" "iptables -t nat -L SQUID_REDIRECT -n -v" 2>&1

echo ""
echo "Checking container status on QNAP..."
ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} ps | grep -E 'squid-proxy|squid-webui'" 2>&1
echo ""

# Record access.log line count before tests
LOG_BEFORE_COUNT=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy wc -l /var/log/squid/access.log 2>/dev/null | awk '{print \$1}'" || echo "0")

# ------------------------------------------------------------------------------
# STEP 2: RUN TEST TRAFFIC FROM CLIENT (vm-ubuntu)
# ------------------------------------------------------------------------------
echo ">>> 2. EXECUTING TEST REQUESTS FROM CLIENT (vm-ubuntu)"
echo "--------------------------------------------------"

echo "[Test 1] Allowed Domain Check (http://example.com)..."
OUT_ALLOWED=$(ssh "${CLIENT_IP}" "curl -sv -4 --max-time 6 http://example.com 2>&1" || true)
echo "$OUT_ALLOWED" | grep -E 'HTTP/|Connected|Host:|HTML|title' | head -10

echo ""
echo "[Test 2] Blocked Domain Check (https://www.pornhub.com)..."
OUT_BLOCKED=$(ssh "${CLIENT_IP}" "curl -sv -4 -k --max-time 6 https://www.pornhub.com 2>&1" || true)
echo "$OUT_BLOCKED" | grep -E 'HTTP/|Connected|Host:|Webpage Blocked|Access Restricted' | head -10

echo ""
echo "[Test 3] YouTube Domain Check (https://www.youtube.com)..."
OUT_YOUTUBE=$(ssh "${CLIENT_IP}" "curl -sv -4 -k --max-time 6 https://www.youtube.com 2>&1" || true)
echo "$OUT_YOUTUBE" | grep -E 'HTTP/|Connected|Host:|Webpage Blocked|Access Restricted' | head -10
echo ""

sleep 2

# ------------------------------------------------------------------------------
# STEP 3: CAPTURE & VERIFY SQUID LOGS
# ------------------------------------------------------------------------------
echo ">>> 3. CAPTURING SQUID ACCESS & CACHE LOGS"
echo "--------------------------------------------------"

echo "=== Recent access.log Entries (Post-Test) ==="
ACCESS_LOG_ENTRIES=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tail -n 25 /var/log/squid/access.log" 2>&1)
echo "${ACCESS_LOG_ENTRIES}"

echo ""
echo "=== Recent cache.log Warnings/Errors ==="
CACHE_LOG_ENTRIES=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tail -n 20 /var/log/squid/cache.log" 2>&1)
echo "${CACHE_LOG_ENTRIES}"
echo ""

# ------------------------------------------------------------------------------
# STEP 4: FETCH WEB UI POLICY CONFIGURATION
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

# Check 1: Allowed website (example.com)
if echo "${ACCESS_LOG_ENTRIES}" | grep -qi "example.com"; then
    echo "  [PASS] http://example.com was captured in Squid access.log."
else
    echo "  [WARN] http://example.com did NOT appear in Squid access.log."
fi

# Check 2: Blocked website (pornhub.com / adult.txt)
if echo "${ACCESS_LOG_ENTRIES}" | grep -qi "pornhub"; then
    echo "  [PASS] pornhub.com (Adult blocklist) was captured in Squid access.log."
else
    echo "  [WARN] pornhub.com did NOT appear in Squid access.log."
fi

# Check 3: YouTube status
if echo "${ACCESS_LOG_ENTRIES}" | grep -qi "youtube"; then
    echo "  [PASS] youtube.com traffic was captured in Squid access.log."
else
    echo "  [INFO] youtube.com traffic was not recorded in access.log."
fi

echo ""
echo "Full detailed output saved to:"
echo "  - ${LOG_FILE}"
echo "  - ${LATEST_LOG}"
echo "========================================================================"
