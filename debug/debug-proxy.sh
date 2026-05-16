#!/bin/bash

# ==============================================================================
# SQUID PROXY & WEB UI COMPREHENSIVE AUTOMATED TEST & VERIFICATION SCRIPT
# Tests:
#   1. Deployment & Infrastructure (Router rules, QNAP containers status)
#   2. Web UI Health, Endpoints, & Policy Auto-Reload via Docker Socket
#   3. Configuration Integrity (`squid -k parse`, `rules.acl`, `ssl_bump.acl`)
#   4. Squid Interception & Bumping (HTTP/HTTPS for allowed, blocked, policy sites)
#   5. Squid Management CLI (squid-mgmt.sh dump-config, catlogs)
#   6. Advanced Router & Firewall Rules (Spotify 4070, YouTube QUIC)
#
# Usage:
#   ./debug-proxy.sh                     # Default: tests via remote client (192.168.8.30)
#   ./debug-proxy.sh --local             # Uses local machine IP as client
#   ./debug-proxy.sh --client-ip 1.2.3.4 # Tests with custom client IP
#   ./debug-proxy.sh --redeploy          # Rebuilds & redeploys before testing
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
DEFAULT_CLIENT_IP="192.168.8.30"
QNAP_USER="admin"
QNAP_DOCKER="/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker"

# Auto-detect local IP on the network
AUTO_LOCAL_IP=$(ip -4 route get "${SQUID_IP}" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
LOCAL_IP="${AUTO_LOCAL_IP:-192.168.8.8}"

REDEPLOY=false
USE_LOCAL=false
CUSTOM_CLIENT_IP=""

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        redeploy|--redeploy|deploy|--deploy)
            REDEPLOY=true
            shift
            ;;
        local|--local|-l)
            USE_LOCAL=true
            shift
            ;;
        --client-ip|--client|-c)
            if [ -n "${2:-}" ]; then
                CUSTOM_CLIENT_IP="$2"
                shift 2
            else
                echo "Error: --client-ip requires an IP address argument."
                exit 1
            fi
            ;;
        --client-ip=*)
            CUSTOM_CLIENT_IP="${1#*=}"
            shift
            ;;
        -h|--help|help)
            echo "Squid Proxy Test Runner"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --local, -l                  Use local host IP (${LOCAL_IP}) as the client IP"
            echo "  --client-ip <IP>, -c <IP>    Specify custom remote client IP (default: ${DEFAULT_CLIENT_IP})"
            echo "  --redeploy                   Rebuild and redeploy containers before testing"
            echo "  --help, -h                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Run '$0 --help' for usage."
            exit 1
            ;;
    esac
done

if [ "${USE_LOCAL}" = true ]; then
    TARGET_CLIENT_IP="${LOCAL_IP}"
    IS_LOCAL_CLIENT=true
elif [ -n "${CUSTOM_CLIENT_IP}" ]; then
    TARGET_CLIENT_IP="${CUSTOM_CLIENT_IP}"
    IS_LOCAL_CLIENT=false
else
    TARGET_CLIENT_IP="${DEFAULT_CLIENT_IP}"
    IS_LOCAL_CLIENT=false
fi

# Exec tee to log files
exec > >(tee -a "${LOG_FILE}" | tee "${LATEST_LOG}") 2>&1

echo "========================================================================"
echo " SQUID PROXY & WEB UI COMPREHENSIVE TEST & DIAGNOSTIC - ${TIMESTAMP}"
echo " Log file: ${LOG_FILE}"
echo " Client Target : ${TARGET_CLIENT_IP} (Local Mode: ${IS_LOCAL_CLIENT})"
echo "========================================================================"
echo ""

SUDO_PASS=""
if [ -f "${SQUID_DIR}/.sudo_pass" ]; then
    SUDO_PASS=$(grep -E '^192.168.1.2' "${SQUID_DIR}/.sudo_pass" 2>/dev/null | awk '{print $2}')
fi

# Track pass/fail status
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

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
    TESTS_WARNED=$((TESTS_WARNED + 1))
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
    echo ">>> 0. SKIPPING REDEPLOYMENT (Pass '--redeploy' to rebuild & redeploy)"
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

if [ "${WEBUI_HOME_CODE}" = "200" ] && echo "${WEBUI_HOME_BODY}" | grep -qi "Squid Web UI\|Control Center\|Squid Proxy Center\|<title>"; then
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

# 6. GET /download/install-ubuntu.sh
UBUNTU_SH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${WEBUI_URL}/download/install-ubuntu.sh" 2>&1 || echo "000")
if [ "${UBUNTU_SH_CODE}" = "200" ]; then
    pass_test "Web UI Ubuntu Installer script endpoint verified (HTTP 200)."
else
    fail_test "Web UI Ubuntu Installer script returned HTTP ${UBUNTU_SH_CODE}."
fi
echo ""

echo "=== 2c. Web UI Policy Save & Apply Pipeline Test ==="
echo "--> Triggering /api/apply to test rules compilation and Docker socket reload..."
APPLY_RES=$(curl -s -m 5 -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" 2>&1 || echo "{}")
echo "  POST /api/apply -> ${APPLY_RES}"

if echo "${APPLY_RES}" | grep -q '"success":\s*true'; then
    pass_test "Web UI policy apply API executed successfully."
else
    fail_test "Web UI policy apply API failed."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 3: SQUID CONFIGURATION INTEGRITY & ACL VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 3. SQUID CONFIGURATION INTEGRITY & ACL VERIFICATION"
echo "--------------------------------------------------"

echo "--> 3a. Testing Squid syntax validation inside container (squid -k parse)..."
SQUID_PARSE_OUT=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy squid -k parse 2>&1" || true)
if echo "${SQUID_PARSE_OUT}" | grep -qi "FATAL\|Bungled"; then
    fail_test "Squid configuration syntax check FAILED (FATAL errors encountered)!"
    echo "${SQUID_PARSE_OUT}" | tail -n 20
else
    pass_test "Squid configuration syntax is valid (squid -k parse OK)."
fi
echo ""

echo "--> 3b. Inspecting active /etc/squid/configs/rules.acl inside squid-proxy..."
RULES_ACL=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/rules.acl" 2>&1 || echo "")
if echo "${RULES_ACL}" | grep -q "AUTO-GENERATED BY SQUID WEB UI"; then
    pass_test "Active rules.acl is present and generated by Web UI."
    echo "=== Active rules.acl snippet ==="
    echo "${RULES_ACL}" | head -n 30
else
    fail_test "Active rules.acl is missing or empty!"
fi
echo ""

echo "--> 3c. Inspecting active /etc/squid/configs/ssl_bump.acl inside squid-proxy..."
SSL_BUMP_ACL=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/ssl_bump.acl 2>/dev/null" || echo "")
if echo "${SSL_BUMP_ACL}" | grep -q "DYNAMIC SSL BUMP RULES"; then
    pass_test "Active ssl_bump.acl is present and contains dynamic per-device bump rules."
    echo "=== Active ssl_bump.acl snippet ==="
    echo "${SSL_BUMP_ACL}" | head -n 25
else
    fail_test "Active ssl_bump.acl is missing or empty!"
fi
echo ""

echo "--> 3d. Inspecting active /etc/squid/configs/bump_domains.acl inside squid-proxy..."
BUMP_DOM_ACL=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy cat /etc/squid/configs/bump_domains.acl 2>/dev/null" || echo "")
if echo "${BUMP_DOM_ACL}" | grep -q "steamcommunity.com" && ! echo "${BUMP_DOM_ACL}" | grep -q "pornhub.com"; then
    pass_test "Selective Bumping ACL Verification: bump_domains.acl contains ONLY path-rule domains (steamcommunity.com) and NOT plain blocklists (pornhub.com)."
else
    fail_test "Selective Bumping ACL Verification FAILED! bump_domains.acl missing path domain or contains plain domain."
fi
echo ""

echo "--> 3e. Checking Local SSL CA Certificates..."
if [ -f "${SQUID_DIR}/certs/squid-ca.pem" ] && [ -f "${SQUID_DIR}/certs/squid-ca.crt" ]; then
    pass_test "Local SSL CA certificates exist (squid-ca.pem, squid-ca.crt)."
else
    fail_test "Local SSL CA certificates missing!"
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 4: TESTING HTTP & HTTPS TRAFFIC INTERCEPTION & SSL BUMPING
# ------------------------------------------------------------------------------
echo ">>> 4. TESTING HTTP & HTTPS TRAFFIC INTERCEPTION & SSL BUMPING"
echo "--------------------------------------------------"

CLIENT_REACHABLE=false
if [ "${IS_LOCAL_CLIENT}" = true ]; then
    CLIENT_REACHABLE=true
    echo "  [+] Using local machine (${TARGET_CLIENT_IP}) as test client."
else
    echo "--> Checking SSH connectivity to remote test client ${TARGET_CLIENT_IP}..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "${TARGET_CLIENT_IP}" "echo OK" 2>/dev/null | grep -q "OK"; then
        CLIENT_REACHABLE=true
        pass_test "Remote test client ${TARGET_CLIENT_IP} is reachable via SSH."
    else
        fail_test "Remote test client ${TARGET_CLIENT_IP} is NOT reachable via SSH (banner exchange timeout / unreachable)!"
        echo "  [!] HINT: Ensure client ${TARGET_CLIENT_IP} is running and sshd is responsive, or pass '--local' to test via local IP (${LOCAL_IP})."
    fi
fi
echo ""

# Helper to execute curl and print live formatted test results
run_curl_test() {
    local label="$1"
    local url="$2"
    local expected_type="$3" # "allow", "block", or "custom"

    echo "--------------------------------------------------"
    echo "[Testing] ${label}: ${url}"
    echo "--------------------------------------------------"

    if [ "${CLIENT_REACHABLE}" != true ]; then
        fail_test "${label}: Skipped because test client (${TARGET_CLIENT_IP}) is unreachable!"
        echo ""
        return
    fi

    local raw_out=""
    if [ "${IS_LOCAL_CLIENT}" = true ]; then
        raw_out=$(curl -siv -4 -k --max-time 8 --noproxy "" --proxy "http://${SQUID_IP}:3128" "${url}" 2>&1 || true)
    else
        raw_out=$(ssh -o ConnectTimeout=8 "${TARGET_CLIENT_IP}" "curl -siv -4 -k --max-time 8 '${url}' 2>&1" || true)
    fi

    local status_line
    status_line=$(echo "$raw_out" | grep -i -E '^< HTTP/|^[*].*TLS connect error|^[*].*SSL routines' | head -1)
    local page_title
    page_title=$(echo "$raw_out" | grep -i '<title>' | head -1 | sed -e 's/^[ \t]*//')
    local block_banner
    block_banner=$(echo "$raw_out" | grep -i 'blocked by your parent\|Webpage Blocked\|ERR_ACCESS_DENIED\|wrong version number' | head -1 | sed -e 's/^[ \t]*//')

    echo "  Status Line : ${status_line:-No HTTP Response (Connection Reset / Timeout)}"
    echo "  Page Title  : ${page_title:-No Title Found}"
    if [ -n "${block_banner}" ]; then
        echo "  Block Banner: ${block_banner}"
    fi

    if [ "$expected_type" = "allow" ]; then
        if echo "${raw_out}" | grep -q -E '^< HTTP/(1\.[01]|2) (200|301|302)' || echo "${raw_out}" | grep -qi "Example Domain\|Wikipedia\|Steam Community"; then
            pass_test "${label} returned HTTP success / redirect as expected."
        else
            fail_test "${label} failed to return HTTP success."
        fi
    elif [ "$expected_type" = "block" ]; then
        if echo "${raw_out}" | grep -qi "Webpage Blocked\|ERR_ACCESS_DENIED\|blocked by your parent\|wrong version number" || echo "${raw_out}" | grep -q -E '^< HTTP/(1\.[01]|2) (403|503)'; then
            pass_test "${label} correctly blocked by Parental Control (HTTP 403 / SSL bump interception)."
        else
            fail_test "${label} was NOT blocked or returned unexpected status!"
        fi
    fi
    echo ""
}

# 1. Allowed Sites (Unrestricted baseline)
run_curl_test "Allowed HTTP (example.com)" "http://example.com" "allow"
run_curl_test "Allowed HTTPS (example.com)" "https://example.com" "allow"
run_curl_test "Allowed HTTPS (wikipedia.org)" "https://www.wikipedia.org" "allow"

# 2. Dynamic Video Category Lifecycle Integration Test (Unblock -> Block -> Unblock)
echo "=== 4b. Dynamic Video Category Lifecycle Integration Test (Web UI) ==="
if [ "${CLIENT_REACHABLE}" = true ]; then
    echo "--> Backing up current policies..."
    SAVED_POLICIES_JSON=$(curl -s "${WEBUI_URL}/api/policies")

    # Phase 1: Ensure Videos are UNBLOCKED
    echo "--> [Phase 1] Configuring Web UI policy: videos.txt ALLOWED for ${TARGET_CLIENT_IP}..."
    curl -s -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" \
        -d "{\"ip\": \"${TARGET_CLIENT_IP}\", \"hostname\": \"test-client\", \"always_block\": [], \"default_block\": [], \"ssl_bump_mode\": \"blocked_only\"}" > /dev/null
    curl -s -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" > /dev/null
    sleep 2

    run_curl_test "YouTube HTTPS (Videos Unblocked State)" "https://www.youtube.com" "allow"

    # Phase 2: Block Videos via Web UI
    echo "--> [Phase 2] Configuring Web UI policy: videos.txt BLOCKED for ${TARGET_CLIENT_IP}..."
    curl -s -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" \
        -d "{\"ip\": \"${TARGET_CLIENT_IP}\", \"hostname\": \"test-client\", \"always_block\": [\"videos.txt\"], \"default_block\": [], \"ssl_bump_mode\": \"blocked_only\"}" > /dev/null
    curl -s -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" > /dev/null
    sleep 2

    run_curl_test "YouTube HTTPS (Videos Blocked State)" "https://www.youtube.com" "block"

    # Phase 3: Restore Original Policies & Verify Recovery
    echo "--> [Phase 3] Restoring original policies..."
    curl -s -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" -d "${SAVED_POLICIES_JSON}" > /dev/null
    curl -s -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" > /dev/null
    sleep 2
    echo "  [+] Original policies restored."
else
    fail_test "Dynamic Video Category Lifecycle Test skipped due to unreachable client (${TARGET_CLIENT_IP})."
fi
echo ""

# 3. Custom Error Page Content & HTML Template Verification
echo "=== 4c. Custom Block Page Content & HTML Template Verification ==="
if [ "${CLIENT_REACHABLE}" = true ]; then
    echo "--> Configuring temporary test policy for ${TARGET_CLIENT_IP} with adult.txt blocked..."
    SAVED_POLICIES_FOR_CUSTOM=$(curl -s "${WEBUI_URL}/api/policies")
    curl -s -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" \
        -d "{\"ip\": \"${TARGET_CLIENT_IP}\", \"hostname\": \"test-client\", \"always_block\": [\"adult.txt\"], \"default_block\": [], \"ssl_bump_mode\": \"blocked_only\"}" > /dev/null
    curl -s -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" > /dev/null
    sleep 2

    echo "--> Fetching blocked site from ${TARGET_CLIENT_IP} and verifying custom HTML block page..."
    if [ "${IS_LOCAL_CLIENT}" = true ]; then
        CUSTOM_PAGE_OUT=$(curl -siv -4 -k --max-time 8 --noproxy "" --proxy "http://${SQUID_IP}:3128" "http://pornhub.com" 2>&1 || true)
        CUSTOM_HTTPS_OUT=$(curl -siv -4 -k --max-time 8 --noproxy "" --proxy "http://${SQUID_IP}:3128" "https://www.pornhub.com" 2>&1 || true)
    else
        CUSTOM_PAGE_OUT=$(ssh -o ConnectTimeout=8 "${TARGET_CLIENT_IP}" "curl -siv -4 -k --max-time 8 'http://pornhub.com' 2>&1" || true)
        CUSTOM_HTTPS_OUT=$(ssh -o ConnectTimeout=8 "${TARGET_CLIENT_IP}" "curl -siv -4 -k --max-time 8 'https://www.pornhub.com' 2>&1" || true)
    fi
    
    HAS_HTTP_403=false
    HAS_SQUID_ERR=false
    HAS_TITLE_BANNER=false
    HAS_PARENT_MSG=false
    HAS_WEBUI_LINK=false

    if echo "${CUSTOM_PAGE_OUT}" | grep -q -E '^< HTTP/(1\.[01]|2) 403' || echo "${CUSTOM_HTTPS_OUT}" | grep -q -E '^< HTTP/(1\.[01]|2) 403'; then HAS_HTTP_403=true; fi
    if echo "${CUSTOM_PAGE_OUT}" | grep -qi 'X-Squid-Error: ERR_ACCESS_DENIED' || echo "${CUSTOM_HTTPS_OUT}" | grep -qi 'X-Squid-Error: ERR_ACCESS_DENIED'; then HAS_SQUID_ERR=true; fi
    if echo "${CUSTOM_PAGE_OUT}" | grep -qi 'Webpage Blocked'; then HAS_TITLE_BANNER=true; fi
    if echo "${CUSTOM_PAGE_OUT}" | grep -qi 'blocked by your parent'; then HAS_PARENT_MSG=true; fi
    if echo "${CUSTOM_PAGE_OUT}" | grep -qi 'Parent Web UI\|Home Network Shield'; then HAS_WEBUI_LINK=true; fi

    echo "  HTTP 403 Status Code    : ${HAS_HTTP_403}"
    echo "  X-Squid-Error Header    : ${HAS_SQUID_ERR}"
    echo "  'Webpage Blocked' Title : ${HAS_TITLE_BANNER}"
    echo "  'Blocked by Parent' Msg : ${HAS_PARENT_MSG}"
    echo "  Web UI Portal Action    : ${HAS_WEBUI_LINK}"

    if [ "${HAS_HTTP_403}" = true ] && [ "${HAS_SQUID_ERR}" = true ] && [ "${HAS_TITLE_BANNER}" = true ] && [ "${HAS_PARENT_MSG}" = true ]; then
        pass_test "Custom Error Page Verification: Verified HTTP 403 status, ERR_ACCESS_DENIED header, and custom HTML content (Webpage Blocked / blocked by your parent)."
    else
        fail_test "Custom Error Page Verification FAILED! Custom block page template missing expected signatures."
    fi

    # Restore policies
    curl -s -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" -d "${SAVED_POLICIES_FOR_CUSTOM}" > /dev/null
    curl -s -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" > /dev/null
    sleep 2
    echo "  [+] Original policies restored."
else
    fail_test "Custom Error Page Verification skipped due to unreachable client (${TARGET_CLIENT_IP})."
fi
echo ""

# 4. Path-Based Deep URL Rules (steamcommunity.com/market vs base domain)
run_curl_test "Deep URL Path Rule (steamcommunity.com/market)" "https://steamcommunity.com/market" "custom"
run_curl_test "Base Domain Exception (steamcommunity.com)" "https://steamcommunity.com/" "allow"

# 5. Strict SSL Certificate Trust Verification (without -k)
echo "--------------------------------------------------"
echo "[Testing] Strict SSL Certificate Trust Verification (without -k)"
echo "--------------------------------------------------"
if [ "${CLIENT_REACHABLE}" = true ]; then
    if [ "${IS_LOCAL_CLIENT}" = true ]; then
        OUT_STRICT_SSL=$(curl -siv -4 --max-time 8 --noproxy "" --proxy "http://${SQUID_IP}:3128" "https://example.com" 2>&1 || true)
    else
        OUT_STRICT_SSL=$(ssh -o ConnectTimeout=8 "${TARGET_CLIENT_IP}" "curl -siv -4 --max-time 8 'https://example.com' 2>&1" || true)
    fi

    STRICT_STATUS=$(echo "${OUT_STRICT_SSL}" | grep -i '^< HTTP/' | head -1)
    STRICT_ERR=$(echo "${OUT_STRICT_SSL}" | grep -i 'SSL certificate problem\|self-signed certificate\|certificate has expired\|issuer certificate' | head -1)
    echo "  Status Line : ${STRICT_STATUS:-No HTTP Response}"
    if [ -n "${STRICT_ERR}" ]; then
        echo "  SSL Warning : ${STRICT_ERR}"
        fail_test "Strict SSL Certificate Verification FAILED! Root CA cert not trusted."
    else
        pass_test "Strict SSL Certificate Verification PASSED."
    fi
else
    fail_test "Strict SSL Certificate Verification skipped due to unreachable client (${TARGET_CLIENT_IP})."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 5: SQUID MANAGEMENT CLI (squid-mgmt.sh) VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 5. SQUID MANAGEMENT CLI (squid-mgmt.sh) VERIFICATION"
echo "--------------------------------------------------"

echo "--> 5a. Testing 'squid-mgmt.sh dump-config'..."
DUMP_CFG_OUT=$(bash "${SQUID_DIR}/squid-mgmt.sh" dump-config 2>&1 || true)
if echo "${DUMP_CFG_OUT}" | grep -qi "Config dumped\|parse OK\|Processing Configuration File"; then
    pass_test "squid-mgmt.sh dump-config succeeded."
else
    fail_test "squid-mgmt.sh dump-config failed!"
fi
echo ""

echo "--> 5b. Testing 'squid-mgmt.sh catlogs'..."
CATLOGS_OUT=$(bash "${SQUID_DIR}/squid-mgmt.sh" catlogs 2>&1 || true)
echo "=== Last 15 lines of catlogs output ==="
echo "${CATLOGS_OUT}" | tail -n 15
if echo "${CATLOGS_OUT}" | grep -qi "Displaying Squid Access Logs\|Saved local log snapshot"; then
    pass_test "squid-mgmt.sh catlogs retrieved access log successfully."
else
    fail_test "squid-mgmt.sh catlogs failed to retrieve access log."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 6: ROUTER ADVANCED RULES CHECK (SPOTIFY & YOUTUBE QUIC)
# ------------------------------------------------------------------------------
echo ">>> 6. ROUTER ADVANCED RULES CHECK"
echo "--------------------------------------------------"

# Spotify Port 4070 redirection check
ROUTER_SQUID_MARK=$(ssh "${ROUTER_IP}" "iptables -t mangle -L SQUID_MARK 2>/dev/null" || true)
CONTAINER_PREROUTING=$(ssh "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} exec squid-proxy iptables-legacy -t nat -L PREROUTING -n 2>/dev/null || ${QNAP_DOCKER} exec squid-proxy iptables -t nat -L PREROUTING -n 2>/dev/null" || true)

if echo "${ROUTER_SQUID_MARK}" | grep -q "4070" && echo "${CONTAINER_PREROUTING}" | grep -q "4070.*3130"; then
    pass_test "Spotify Port 4070 Redirection: Router mangle & container NAT REDIRECT rules active."
else
    fail_test "Spotify Port 4070 Redirection: Missing port 4070 iptables rules on router or container!"
fi

# YouTube QUIC router rules check
ROUTER_FORWARD=$(ssh "${ROUTER_IP}" "iptables -L FORWARD -n 2>/dev/null" || true)
if echo "${ROUTER_FORWARD}" | grep -q "youtube_quic" || echo "${ROUTER_FORWARD}" | grep -q "142.250."; then
    pass_test "YouTube QUIC Protocol Support: Router FORWARD chain ACCEPT rules for YouTube video IPs active."
else
    fail_test "YouTube QUIC Protocol Support: Router FORWARD chain rule missing!"
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 7: VERIFICATION ANALYSIS SUMMARY
# ------------------------------------------------------------------------------
echo "========================================================================"
echo " VERIFICATION SUMMARY & REPORT"
echo "========================================================================"
echo " TOTAL TESTS PASSED : ${TESTS_PASSED}"
echo " TOTAL TESTS FAILED : ${TESTS_FAILED}"
echo " TOTAL TESTS WARNED : ${TESTS_WARNED}"
echo "========================================================================"
echo "Full detailed log saved to:"
echo "  - ${LOG_FILE}"
echo "  - ${LATEST_LOG}"
echo "========================================================================"
sleep 0.5
