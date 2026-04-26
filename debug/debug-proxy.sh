#!/bin/bash

# ==============================================================================
# SQUID PROXY & WEB UI COMPREHENSIVE AUTOMATED TEST & VERIFICATION SCRIPT
# Tests:
#   1. Deployment & Infrastructure (Router rules, QNAP containers status)
#   2. Squid Interception & Bumping (HTTP/HTTPS for allowed, blocked, policy sites)
#   3. Web UI Health, Endpoints, & Policy Auto-Reload via Docker Socket
#   4. Squid Management CLI (squid-mgmt.sh dump-config, catlogs, router-deploy)
# Log saved to squid/debug/latest_debug.log
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
WEBUI_IP="192.168.1.91"
CLIENT_IP="192.168.8.30"
QNAP_USER="admin"
QNAP_DOCKER="/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker"

# Exec tee to log files
exec > >(tee -a "${LOG_FILE}" | tee "${LATEST_LOG}") 2>&1

echo "========================================================================"
echo " SQUID PROXY & WEB UI COMPREHENSIVE TEST & DIAGNOSTIC - ${TIMESTAMP}"
echo " Log file: ${LOG_FILE}"
echo "========================================================================"
echo ""

SUDO_PASS=""
if [ -f "${SQUID_DIR}/.sudo_pass" ]; then
    SUDO_PASS=$(grep -E '^192.168.1.2' "${SQUID_DIR}/.sudo_pass" 2>/dev/null | awk '{print $2}')
fi

REDEPLOY=false

for arg in "$@"; do
    case "$arg" in
        redeploy|--redeploy|deploy|--deploy)
            REDEPLOY=true
            ;;
    esac
done

# Track pass/fail status
TESTS_PASSED=0
TESTS_FAILED=0

pass_test() {
    echo "  [PASS] $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo "  [FAIL] $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

warn_test() {
    echo "  [WARN] $1"
}

# ------------------------------------------------------------------------------
# STEP 0: OPTIONAL REDEPLOYMENT OF ROUTER RULES & CONTAINERS
# ------------------------------------------------------------------------------
if [ "${REDEPLOY}" = true ]; then
    echo ">>> 0. AUTO-DEPLOYING ROUTER RULES & DOCKER CONTAINERS..."
    echo "--------------------------------------------------"
    echo "--> Running squid-mgmt.sh router-deploy..."
    bash "${SQUID_DIR}/squid-mgmt.sh" router-deploy 2>&1

    echo "--> Running deploy-squid-docker.sh create squid-proxy squid-webui..."
    bash "${SQUID_DIR}/docker/deploy-squid-docker.sh" create squid-proxy squid-webui 2>&1
    echo ""

    echo "--> Waiting for containers & services to become fully ready..."
    WEBUI_READY=false
    for i in $(seq 1 20); do
        if curl -s -o /dev/null -w "%{http_code}" -m 2 "http://${WEBUI_IP}:3131/api/auth/status" 2>/dev/null | grep -q "200" || \
           curl -s -o /dev/null -w "%{http_code}" -m 2 "http://${QNAP_IP}:3131/api/auth/status" 2>/dev/null | grep -q "200"; then
            WEBUI_READY=true
            echo "  [+] Web UI service ready on attempt ${i}."
            break
        fi
        sleep 1
    done
    if [ "${WEBUI_READY}" = false ]; then
        echo "  [!] WARNING: Web UI did not respond within 20s. Proceeding with diagnostics..."
    fi
    echo ""
else
    echo ">>> 0. SKIPPING REDEPLOYMENT (Pass 'redeploy' or '--redeploy' to rebuild & redeploy)"
    echo "--------------------------------------------------"
    echo "--> Running diagnostics directly against active containers."
    echo ""
fi

# ------------------------------------------------------------------------------
# STEP 1: ROUTER & CONTAINER INFRASTRUCTURE CHECK
# ------------------------------------------------------------------------------
echo ">>> 1. INFRASTRUCTURE & ROUTING CHECK"
echo "--------------------------------------------------"
echo "Checking router policy rules & routing tables..."
ssh "${ROUTER_IP}" "ip rule show; echo '--- Table 150 ---'; ip route show table 150 2>/dev/null" 2>&1

echo ""
echo "Checking router mangle SQUID_MARK chain..."
ssh "${ROUTER_IP}" "iptables -t mangle -L SQUID_MARK -n -v 2>/dev/null || true" 2>&1

echo ""
echo "Checking QNAP Docker containers status..."
CONTAINERS_PS=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} ps | grep -E 'squid-proxy|squid-webui'" 2>&1 || true)
echo "${CONTAINERS_PS}"

PROXY_UP=false
WEBUI_UP=false
if echo "${CONTAINERS_PS}" | grep -q "squid-proxy"; then PROXY_UP=true; fi
if echo "${CONTAINERS_PS}" | grep -q "squid-webui"; then WEBUI_UP=true; fi

if [ "$PROXY_UP" = true ]; then
    pass_test "squid-proxy container is UP and running."
else
    fail_test "squid-proxy container is NOT running!"
fi

if [ "$WEBUI_UP" = true ]; then
    pass_test "squid-webui container is UP and running."
else
    fail_test "squid-webui container is NOT running!"
fi

echo ""
echo "Checking squid-proxy container iptables NAT rules..."
ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy iptables-legacy -t nat -L PREROUTING -n -v 2>/dev/null || true" 2>&1
echo ""

# ------------------------------------------------------------------------------
# STEP 2: SQUID WEB UI FUNCTIONALITY & API VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 2. SQUID WEB UI FUNCTIONALITY & API VERIFICATION"
echo "--------------------------------------------------"

WEBUI_URL=""
for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "%{http_code}" -m 2 "http://${WEBUI_IP}:3131/api/auth/status" 2>/dev/null | grep -q "200"; then
        WEBUI_URL="http://${WEBUI_IP}:3131"
        break
    elif curl -s -o /dev/null -w "%{http_code}" -m 2 "http://${QNAP_IP}:3131/api/auth/status" 2>/dev/null | grep -q "200"; then
        WEBUI_URL="http://${QNAP_IP}:3131"
        break
    fi
    sleep 1
done

if [ -z "${WEBUI_URL}" ]; then
    WEBUI_URL="http://${WEBUI_IP}:3131"
fi
echo "  [*] Target Web UI URL: ${WEBUI_URL}"

echo "=== 2a. Web UI Base Page Access (${WEBUI_URL}/) ==="
WEBUI_HOME_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${WEBUI_URL}/" 2>/dev/null || echo "000")
WEBUI_HOME_BODY=$(curl -s -m 5 "${WEBUI_URL}/" 2>/dev/null || true)
echo "  HTTP Response Code: ${WEBUI_HOME_CODE}"

if [ "${WEBUI_HOME_CODE}" = "200" ] && echo "${WEBUI_HOME_BODY}" | grep -qi "Squid Web UI\|Control Center\|<title>"; then
    pass_test "Web UI Dashboard page loaded successfully (HTTP 200)."
else
    fail_test "Web UI Dashboard page failed to respond (HTTP ${WEBUI_HOME_CODE})."
fi
echo ""

echo "=== 2b. Web UI API Endpoints Check ==="

# 1. GET /api/auth/status
AUTH_STATUS_RES=$(curl -s -m 5 "${WEBUI_URL}/api/auth/status" 2>&1 || echo "{}")
echo "  GET /api/auth/status -> ${AUTH_STATUS_RES}"
if echo "${AUTH_STATUS_RES}" | grep -q '"authenticated"'; then
    pass_test "API /api/auth/status returned valid JSON."
else
    fail_test "API /api/auth/status failed."
fi

# 2. GET /api/devices
DEVICES_RES=$(curl -s -m 5 "${WEBUI_URL}/api/devices" 2>&1 || echo "{}")
echo "  GET /api/devices -> ${DEVICES_RES}"
if echo "${DEVICES_RES}" | grep -q '"devices"'; then
    pass_test "API /api/devices returned device list."
else
    fail_test "API /api/devices failed."
fi

# 3. GET /api/policies
POLICIES_RES=$(curl -s -m 5 "${WEBUI_URL}/api/policies" 2>&1 || echo "{}")
echo "  GET /api/policies -> ${POLICIES_RES}"
if echo "${POLICIES_RES}" | grep -q '"policies"'; then
    pass_test "API /api/policies returned device policies."
else
    fail_test "API /api/policies failed."
fi

# 4. GET /api/blocklists
BLOCKLISTS_RES=$(curl -s -m 5 "${WEBUI_URL}/api/blocklists" 2>&1 || echo "{}")
echo "  GET /api/blocklists -> ${BLOCKLISTS_RES}"
if echo "${BLOCKLISTS_RES}" | grep -q '"blocklists"'; then
    pass_test "API /api/blocklists returned list of blocklists."
else
    fail_test "API /api/blocklists failed."
fi

# 5. GET /download/cert.crt & /download/cert.pem
CERT_CRT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${WEBUI_URL}/download/cert.crt" 2>&1 || echo "000")
CERT_PEM_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${WEBUI_URL}/download/cert.pem" 2>&1 || echo "000")
echo "  GET /download/cert.crt -> HTTP ${CERT_CRT_CODE}"
echo "  GET /download/cert.pem -> HTTP ${CERT_PEM_CODE}"
if [ "${CERT_CRT_CODE}" = "200" ] || [ "${CERT_PEM_CODE}" = "200" ]; then
    pass_test "Web UI Certificate Download endpoint verified (HTTP 200)."
else
    fail_test "Web UI Certificate Download endpoint returned HTTP ${CERT_CRT_CODE} / ${CERT_PEM_CODE}."
fi
echo ""

echo "=== 2c. Web UI Policy Save & Apply Pipeline Test ==="
echo "--> Triggering POST /api/policies to test policy save and compilation..."
POST_POLICIES_RES=$(curl -s -m 5 -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" -d '{"policies":{}}' 2>&1 || echo "{}")
echo "  POST /api/policies -> ${POST_POLICIES_RES}"

if echo "${POST_POLICIES_RES}" | grep -q '"success":\s*true'; then
    pass_test "Web UI policy save API (POST /api/policies) executed successfully."
else
    fail_test "Web UI policy save API (POST /api/policies) failed."
fi

echo "--> Triggering /api/apply to test rules compilation and Docker socket reload..."
APPLY_RES=$(curl -s -m 5 -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" 2>&1 || echo "{}")
echo "  POST /api/apply -> ${APPLY_RES}"

if echo "${APPLY_RES}" | grep -q '"success":\s*true'; then
    pass_test "Web UI policy apply API executed successfully."
else
    fail_test "Web UI policy apply API failed."
fi

# Verify rules.acl generation inside squid-proxy
echo ""
echo "=== Active /etc/squid/configs/rules.acl (vm-ubuntu section) ==="
RULES_ACL=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/rules.acl" 2>&1 || echo "")
echo "${RULES_ACL}" | grep -A 25 "vm-ubuntu" || echo "${RULES_ACL}"
echo ""

# ------------------------------------------------------------------------------
# STEP 3: TESTING HTTP & HTTPS TRAFFIC INTERCEPTION (CLIENT: vm-ubuntu)
# ------------------------------------------------------------------------------
echo ">>> 3. TESTING HTTP & HTTPS TRAFFIC INTERCEPTION (CLIENT: vm-ubuntu)"
echo "--------------------------------------------------"

test_site() {
    local label="$1"
    local url="$2"

    echo "--------------------------------------------------"
    echo "[Testing] ${label} (${url})"
    echo "--------------------------------------------------"
    local res
    res=$(ssh "${CLIENT_IP}" "curl -siv -4 -k --max-time 8 '${url}' 2>&1" || true)

    # Extract status line, title, and block message
    local status_line
    status_line=$(echo "$res" | grep -i '^< HTTP/' | head -1)
    local page_title
    page_title=$(echo "$res" | grep -i '<title>' | head -1 | sed -e 's/^[ \t]*//')
    local block_msg
    block_msg=$(echo "$res" | grep -i 'blocked by your parent' | head -1 | sed -e 's/^[ \t]*//')

    echo "  Status Line : ${status_line:-No HTTP Response (Connection Failed / Timeout)}"
    echo "  Page Title  : ${page_title:-No HTML Title Found}"
    if [ -n "${block_msg}" ]; then
        echo "  Block Banner: ${block_msg}"
    fi

    # Print first few lines of body preview
    local body_snippet
    body_snippet=$(echo "$res" | grep -v '^[*><]' | grep -v '^[[:space:]]*$' | head -5)
    if [ -n "${body_snippet}" ]; then
        echo "  Body Preview:"
        echo "${body_snippet}" | sed 's/^/    /'
    fi

    echo "$res"
}

# Start background tcpdump inside squid-proxy container
echo "[*] Starting background packet capture inside squid-proxy container..."
ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tcpdump -i eth0 host ${CLIENT_IP} -n -c 20 > /tmp/container_tcpdump.cap 2>&1" &
TCPDUMP_PID=$!
sleep 1

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

# 4. DEEP INSPECTION PATH RULE TESTS (steamcommunity.com/market vs steamcommunity.com)
OUT_STEAM_MARKET=$(test_site "Steam Community Market (Blocked Path)" "https://steamcommunity.com/market")
echo ""
OUT_STEAM_BASE=$(test_site "Steam Community Home (Allowed Base Domain)" "https://steamcommunity.com/")
echo ""

# 5. STRICT SSL CERTIFICATE TRUST TEST FROM CLIENT (WITHOUT -k)
echo "--------------------------------------------------"
echo "[Testing] Strict SSL Certificate Trust Verification on Client (without -k)"
echo "--------------------------------------------------"
OUT_STRICT_SSL=$(ssh "${CLIENT_IP}" "curl -siv -4 --max-time 8 'https://example.com' 2>&1" || true)
STRICT_STATUS=$(echo "${OUT_STRICT_SSL}" | grep -i '^< HTTP/' | head -1)
STRICT_ERR=$(echo "${OUT_STRICT_SSL}" | grep -i 'SSL certificate\|self-signed\|certificate' | head -1)
echo "  Status Line : ${STRICT_STATUS:-No HTTP Response}"
if [ -n "${STRICT_ERR}" ]; then
    echo "  SSL Warning : ${STRICT_ERR}"
fi
echo ""

wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

# ------------------------------------------------------------------------------
# STEP 4: SQUID MANAGEMENT CLI (squid-mgmt.sh) VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 4. SQUID MANAGEMENT CLI (squid-mgmt.sh) VERIFICATION"
echo "--------------------------------------------------"

echo "--> 4a. Testing 'squid-mgmt.sh dump-config'..."
DUMP_CFG_OUT=$(bash "${SQUID_DIR}/squid-mgmt.sh" dump-config 2>&1 || true)
echo "${DUMP_CFG_OUT}"
if echo "${DUMP_CFG_OUT}" | grep -qi "Config dumped\|parse OK\|Processing Configuration File"; then
    pass_test "squid-mgmt.sh dump-config succeeded."
else
    fail_test "squid-mgmt.sh dump-config failed!"
fi
echo ""

echo "--> 4b. Testing 'squid-mgmt.sh catlogs'..."
CATLOGS_OUT=$(bash "${SQUID_DIR}/squid-mgmt.sh" catlogs 2>&1 || true)
echo "=== Last 15 lines of catlogs output ==="
echo "${CATLOGS_OUT}" | tail -n 15
if echo "${CATLOGS_OUT}" | grep -qi "Displaying Squid Access Logs\|Saved local log snapshot"; then
    pass_test "squid-mgmt.sh catlogs retrieved access log successfully."
else
    fail_test "squid-mgmt.sh catlogs failed to retrieve access log."
fi
echo ""

echo "--> 4c. Checking Local & Remote SSL Certificates..."
if [ -f "${SQUID_DIR}/certs/squid-ca.pem" ] && [ -f "${SQUID_DIR}/certs/squid-ca.crt" ]; then
    pass_test "Local SSL CA certificates exist (squid-ca.pem, squid-ca.crt)."
else
    fail_test "Local SSL CA certificates missing!"
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 5: CAPTURE PACKET TRACES & SQUID LOGS
# ------------------------------------------------------------------------------
echo ">>> 5. CAPTURING PACKET TRACES & SQUID LOGS POST-TEST"
echo "--------------------------------------------------"

echo "=== Captured Network Packet Trace (Inside squid-proxy container) ==="
ssh "${QNAP_USER}@${QNAP_IP}" "cat /tmp/container_tcpdump.cap 2>/dev/null | head -n 30" 2>&1 || true
echo ""

echo "=== Recent access.log Entries (Post-Test) ==="
ACCESS_LOG_ENTRIES=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tail -n 60 /var/log/squid/access.log" 2>&1 || true)
echo "${ACCESS_LOG_ENTRIES}"

echo ""
echo "=== YouTube Traffic Log Entries (Double-Confirmation) ==="
YT_ACCESS_LOGS=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy grep -i "youtube" /var/log/squid/access.log 2>/dev/null | tail -n 20" || true)
if [ -n "${YT_ACCESS_LOGS}" ]; then
    echo "${YT_ACCESS_LOGS}"
else
    echo "  (No YouTube entries found in access.log)"
fi

echo ""
echo "=== Recent cache.log Warnings/Errors ==="
CACHE_LOG_ENTRIES=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy tail -n 25 /var/log/squid/cache.log" 2>&1 || true)
echo "${CACHE_LOG_ENTRIES}"
echo ""

# ------------------------------------------------------------------------------
# STEP 6: VERIFICATION ANALYSIS SUMMARY
# ------------------------------------------------------------------------------
echo "========================================================================"
echo " VERIFICATION SUMMARY & REPORT"
echo "========================================================================"

# Allowed site check (Example Domain)
if echo "${OUT_EX_HTTP}" | grep -qi "Example Domain" || echo "${OUT_EX_HTTPS}" | grep -qi "Example Domain"; then
    pass_test "Allowed Site (example.com) successfully returned REAL remote content!"
else
    fail_test "Allowed Site (example.com) failed to return real remote content."
fi

# Strict SSL Certificate check (without -k)
if echo "${OUT_STRICT_SSL}" | grep -qi "SSL certificate problem\|self-signed certificate\|certificate has expired\|issuer certificate"; then
    fail_test "Strict SSL Certificate Verification FAILED on client (vm-ubuntu)! Root CA cert is not trusted by client OS/browser."
    echo "  [i] FIX: Run 'bash squid-mgmt.sh linux-deploy' to install/trust the Root CA cert on vm-ubuntu."
else
    pass_test "Strict SSL Certificate Verification PASSED on client (vm-ubuntu)."
fi

# Blocked site check (Adult)
if echo "${OUT_AD_HTTP}" | grep -qi "Webpage Blocked" || echo "${OUT_AD_HTTPS}" | grep -qi "Webpage Blocked"; then
    pass_test "Blocked Site (pornhub.com) returned custom Parental Control Block Page."
else
    warn_test "Blocked Site (pornhub.com) did not return custom block page."
fi

# YouTube check vs active policy
YT_IS_BLOCKED=false
if echo "${OUT_YT_HTTPS}" | grep -qi "Webpage Blocked\|ERR_ACCESS_DENIED\|wrong version number\|TLS connect error" || echo "${OUT_YT_HTTPS}" | grep -q -E '^< HTTP/[12]\.[01] (403|503)'; then
    YT_IS_BLOCKED=true
fi

HAS_UNCONDITIONAL_DENY=false
if echo "${RULES_ACL}" | grep -q "http_access deny.*list_videos_txt" && ! echo "${RULES_ACL}" | grep -q "http_access allow.*list_videos_txt"; then
    HAS_UNCONDITIONAL_DENY=true
fi

if [ "$HAS_UNCONDITIONAL_DENY" = true ]; then
    echo "  [POLICY] YouTube is currently CONFIGURED TO BE UNCONDITIONALLY BLOCKED in Web UI."
    if [ "$YT_IS_BLOCKED" = true ]; then
        pass_test "YouTube traffic was correctly BLOCKED as defined by policy."
    else
        fail_test "YouTube was NOT blocked despite policy requiring block!"
    fi
else
    echo "  [POLICY] YouTube is currently ALLOWED (or within an active unblock window) in Web UI."
    if [ "$YT_IS_BLOCKED" = false ] && echo "${OUT_YT_HTTPS}" | grep -q -E '^< HTTP/[12]\.[01] (200|301|302)'; then
        pass_test "YouTube traffic was correctly ALLOWED (HTTP 200 OK) as defined by policy!"
    else
        fail_test "YouTube traffic failed to load (was BLOCKED or failed) despite policy allowing it!"
    fi
fi

# Deep Inspection URL Path check (Steam Community Market vs Base)
if echo "${OUT_STEAM_MARKET}" | grep -qi "Webpage Blocked\|ERR_ACCESS_DENIED\|wrong version number\|403 Access Denied\|403 Forbidden"; then
    pass_test "Deep Inspection Path Rule: steamcommunity.com/market was correctly BLOCKED (HTTP 403 / Block Page)."
else
    fail_test "Deep Inspection Path Rule: steamcommunity.com/market failed to block!"
fi

if echo "${OUT_STEAM_BASE}" | grep -qi "^< HTTP/\|<title>\|200 OK\|302 Found"; then
    pass_test "Selective Bumping Path Exception: steamcommunity.com (base domain) remains ACCESSIBLE."
else
    warn_test "steamcommunity.com (base domain) connection check did not complete."
fi

# Selective Bumping ACL check inside container
BUMP_ACL_CONTENT=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/bump_domains.acl 2>/dev/null" || true)
if echo "${BUMP_ACL_CONTENT}" | grep -q "steamcommunity.com" && ! echo "${BUMP_ACL_CONTENT}" | grep -q "pornhub.com"; then
    pass_test "Selective Bumping ACL Verification: bump_domains.acl contains ONLY path-rule domains (steamcommunity.com) and NOT plain blocklists (pornhub.com)."
else
    fail_test "Selective Bumping ACL Verification FAILED! bump_domains.acl missing path domain or contains plain domain."
fi

# Spotify Port 4070 redirection check
ROUTER_SQUID_MARK=$(ssh ${ROUTER_SSH_OPTS} "${ROUTER_SERVER}" "iptables -t mangle -L SQUID_MARK 2>/dev/null" || true)
CONTAINER_PREROUTING=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy iptables -t nat -L PREROUTING 2>/dev/null" || true)
if echo "${ROUTER_SQUID_MARK}" | grep -q "4070" && echo "${CONTAINER_PREROUTING}" | grep -q "4070.*3130"; then
    pass_test "Spotify Port 4070 Redirection: Router mangle & container NAT REDIRECT rules active."
else
    fail_test "Spotify Port 4070 Redirection: Missing port 4070 iptables rules on router or container!"
fi

# YouTube QUIC router rules check
ROUTER_FORWARD=$(ssh ${ROUTER_SSH_OPTS} "${ROUTER_SERVER}" "iptables -L FORWARD -n 2>/dev/null" || true)
if echo "${ROUTER_FORWARD}" | grep -q "youtube_quic" || echo "${ROUTER_FORWARD}" | grep -q "142.250."; then
    pass_test "YouTube QUIC Protocol Support: Router FORWARD chain ACCEPT rules for YouTube video IPs active."
else
    fail_test "YouTube QUIC Protocol Support: Router FORWARD chain rule missing!"
fi

echo ""
echo "------------------------------------------------------------------------"
echo " TOTAL TESTS PASSED: ${TESTS_PASSED}"
echo " TOTAL TESTS FAILED: ${TESTS_FAILED}"
echo "------------------------------------------------------------------------"
echo "Full detailed log saved to:"
echo "  - ${LOG_FILE}"
echo "  - ${LATEST_LOG}"
echo "========================================================================"
