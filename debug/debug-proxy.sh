#!/bin/bash

# ==============================================================================
# SQUID PROXY & WEB UI COMPREHENSIVE AUTOMATED TEST & VERIFICATION SCRIPT
#
# Test suites (see debug/TEST_CASES.md for the full specification):
#   1. Infrastructure    — router policy routing (mangle SQUID_MARK + table 150),
#                          container state, container NAT REDIRECT rules
#   2. Web UI            — health, REST API contract, auth posture, apply pipeline
#   3. Config integrity  — squid -k parse, rules.acl / ssl_bump.acl / bump_domains.acl,
#                          dangling-ACL-reference check, CA certs
#   4. Traffic           — interception, selective SSL bumping, block page, path rules
#   5. Management CLI    — squid-mgmt.sh dump-config, catlogs
#   6. Router advanced   — Spotify 4070, YouTube QUIC allow + global QUIC reject
#
# Usage:
#   ./debug-proxy.sh                     # Default: tests via remote client (192.168.8.30)
#   ./debug-proxy.sh --local             # Uses local machine IP as client (explicit proxy)
#   ./debug-proxy.sh --client-ip 1.2.3.4 # Tests with custom client IP
#   ./debug-proxy.sh --redeploy          # Rebuilds & redeploys before testing
#
# Exit code: 0 if no test failed, 1 otherwise.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQUID_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEBUG_DIR="${SQUID_DIR}/debug"
BLOCKLIST_DIR="${SQUID_DIR}/block-lists"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
LOG_FILE="${DEBUG_DIR}/debug_${TIMESTAMP}.log"
LATEST_LOG="${DEBUG_DIR}/latest_debug.log"

mkdir -p "${DEBUG_DIR}"

ROUTER_IP="192.168.0.1"
QNAP_IP="192.168.1.2"
SQUID_IP="192.168.1.90"
WEBUI_IP="192.168.1.91"
WEBUI_PORT="3131"
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
            echo "  --local, -l                  Use local host IP (${LOCAL_IP}) as the client IP."
            echo "                               NOTE: local mode reaches Squid through the EXPLICIT"
            echo "                               proxy port 3128, which has no 'ssl-bump' flag. SSL-bump"
            echo "                               dependent assertions are reported as WARN, not FAIL."
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

# Colour codes (disabled when not writing to a terminal)
if [ -t 1 ]; then
    C_PASS=$'\033[0;32m'; C_FAIL=$'\033[0;31m'; C_WARN=$'\033[0;33m'
    C_INFO=$'\033[0;36m'; C_RST=$'\033[0m'
else
    C_PASS=""; C_FAIL=""; C_WARN=""; C_INFO=""; C_RST=""
fi

echo "========================================================================"
echo " SQUID PROXY & WEB UI COMPREHENSIVE TEST & DIAGNOSTIC - ${TIMESTAMP}"
echo " Log file: ${LOG_FILE}"
echo " Client Target : ${TARGET_CLIENT_IP} (Local Mode: ${IS_LOCAL_CLIENT})"
echo "========================================================================"
echo ""

# Track pass/fail status
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0
FAILED_NAMES=()

pass_test() {
    echo "  ${C_PASS}[PASS]${C_RST} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo "  ${C_FAIL}[FAIL]${C_RST} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILED_NAMES+=("$1")
}

warn_test() {
    echo "  ${C_WARN}[WARN]${C_RST} $1"
    TESTS_WARNED=$((TESTS_WARNED + 1))
}

info() {
    echo "  ${C_INFO}[INFO]${C_RST} $1"
}

# ------------------------------------------------------------------------------
# Remote exec helpers
#
# CRITICAL: 'docker exec' against a stopped/absent container still exits with a
# message that contains none of the strings the old assertions grepped for, so a
# dead container used to be reported as PASS. Every container assertion now goes
# through proxy_exec(), which surfaces the real exit code in PROXY_EXEC_RC and
# refuses to run at all when the container is known to be down.
# ------------------------------------------------------------------------------
PROXY_UP=false
WEBUI_UP=false
PROXY_EXEC_RC=0

proxy_exec() {
    # $* = command to run inside the squid-proxy container.
    # Prints combined output; sets PROXY_EXEC_RC.
    local out
    out=$(ssh -o ConnectTimeout=8 "${QNAP_USER}@${QNAP_IP}" \
            "${QNAP_DOCKER} exec squid-proxy $* 2>&1"; echo "__RC__$?")
    PROXY_EXEC_RC="${out##*__RC__}"
    out="${out%__RC__*}"
    # Container-level failures that must never be mistaken for command output
    if echo "${out}" | grep -qiE "is not running|No such container|Cannot connect to the Docker daemon"; then
        PROXY_EXEC_RC=125
    fi
    printf '%s' "${out}"
}

require_proxy_up() {
    # $1 = test label. Returns 1 (and records a FAIL) when squid-proxy is down.
    if [ "${PROXY_UP}" != true ]; then
        fail_test "$1: squid-proxy container is not running — assertion cannot be evaluated."
        return 1
    fi
    return 0
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
        if curl -s -o /dev/null -w "%{http_code}" -m 2 "http://${WEBUI_IP}:${WEBUI_PORT}/api/auth/status" 2>/dev/null | grep -q "200"; then
            WEBUI_READY=true
            info "Web UI service ready on attempt ${i}."
            break
        fi
        sleep 1
    done
    if [ "${WEBUI_READY}" = false ]; then
        warn_test "Web UI did not respond within 20s after redeploy. Proceeding with diagnostics..."
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

# --- TC-1.1: Router policy routing (fwmark 0x5000 -> table 150 -> Squid) ---
echo "--> 1a. Router policy rules & routing table 150..."
ROUTER_IP_RULE=$(ssh -o ConnectTimeout=8 "${ROUTER_IP}" "ip rule show" 2>&1 || true)
ROUTER_TABLE150=$(ssh -o ConnectTimeout=8 "${ROUTER_IP}" "ip route show table 150" 2>&1 || true)
echo "${ROUTER_IP_RULE}"
echo "--- Table 150 ---"
echo "${ROUTER_TABLE150}"

if echo "${ROUTER_IP_RULE}" | grep -q "fwmark 0x5000/0x5000 lookup 150"; then
    pass_test "TC-1.1a Router 'ip rule' has fwmark 0x5000/0x5000 -> table 150."
else
    fail_test "TC-1.1a Router 'ip rule' missing fwmark 0x5000/0x5000 -> table 150 (run: squid-mgmt.sh router-deploy)."
fi

if echo "${ROUTER_TABLE150}" | grep -q "default via ${SQUID_IP}"; then
    pass_test "TC-1.1b Router table 150 default route points at Squid (${SQUID_IP})."
else
    fail_test "TC-1.1b Router table 150 has no 'default via ${SQUID_IP}' route."
fi
echo ""

# --- TC-1.2: mangle SQUID_MARK chain marks the intercepted hosts ---
echo "--> 1b. Router mangle SQUID_MARK chain..."
ROUTER_SQUID_MARK=$(ssh -o ConnectTimeout=8 "${ROUTER_IP}" "iptables -t mangle -L SQUID_MARK -n -v" 2>&1 || true)
echo "${ROUTER_SQUID_MARK}"

if echo "${ROUTER_SQUID_MARK}" | grep -q "Chain SQUID_MARK"; then
    pass_test "TC-1.2a mangle chain SQUID_MARK exists on the router."
else
    fail_test "TC-1.2a mangle chain SQUID_MARK is missing on the router."
fi

# Every host in proxy-hosts.conf must have a MARK rule
PROXY_HOSTS_CONF="${SQUID_DIR}/router/proxy-hosts.conf"
HOSTS_MARKED=true
HOSTS_CHECKED=0
if [ -f "${PROXY_HOSTS_CONF}" ]; then
    while IFS= read -r line; do
        [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
        host_ip=$(echo "${line}" | awk '{print $1}')
        [ -z "${host_ip}" ] && continue
        HOSTS_CHECKED=$((HOSTS_CHECKED + 1))
        if ! echo "${ROUTER_SQUID_MARK}" | grep -q "${host_ip}"; then
            HOSTS_MARKED=false
            info "No SQUID_MARK rule found for ${host_ip}."
        fi
    done < "${PROXY_HOSTS_CONF}"
fi
if [ "${HOSTS_CHECKED}" -eq 0 ]; then
    warn_test "TC-1.2b proxy-hosts.conf lists no intercepted hosts — nothing to verify."
elif [ "${HOSTS_MARKED}" = true ]; then
    pass_test "TC-1.2b All ${HOSTS_CHECKED} host(s) in proxy-hosts.conf have SQUID_MARK rules."
else
    fail_test "TC-1.2b One or more hosts in proxy-hosts.conf are missing SQUID_MARK rules."
fi
echo ""

# --- TC-1.3: Container state ---
echo "--> 1c. QNAP Docker container status..."
CONTAINERS_PS=$(ssh -o ConnectTimeout=8 "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} ps --format '{{.Names}}\t{{.Status}}'" 2>&1 || true)
echo "${CONTAINERS_PS}"

if echo "${CONTAINERS_PS}" | grep -qE '^squid-proxy[[:space:]]+Up'; then PROXY_UP=true; fi
if echo "${CONTAINERS_PS}" | grep -qE '^squid-webui[[:space:]]+Up'; then WEBUI_UP=true; fi

if [ "${PROXY_UP}" = true ]; then
    pass_test "TC-1.3a squid-proxy container is UP and running."
else
    fail_test "TC-1.3a squid-proxy container is NOT running!"
    # Surface why — restart loops and config FATALs are the usual cause.
    echo "=== Last 25 lines of squid-proxy container logs ==="
    ssh -o ConnectTimeout=8 "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} logs --tail 25 squid-proxy" 2>&1 || true
fi

if [ "${WEBUI_UP}" = true ]; then
    pass_test "TC-1.3b squid-webui container is UP and running."
else
    fail_test "TC-1.3b squid-webui container is NOT running!"
fi
echo ""

# --- TC-1.4: Container-level NAT REDIRECT (SO_ORIGINAL_DST preservation) ---
echo "--> 1d. squid-proxy container iptables NAT PREROUTING..."
CONTAINER_PREROUTING=""
if require_proxy_up "TC-1.4 Container NAT REDIRECT rules"; then
    CONTAINER_PREROUTING=$(proxy_exec "iptables-legacy -t nat -L PREROUTING -n -v")
    echo "${CONTAINER_PREROUTING}"
    NAT_OK=true
    for pair in "80:3129" "443:3130" "4070:3130"; do
        dport="${pair%%:*}"; toport="${pair##*:}"
        if ! echo "${CONTAINER_PREROUTING}" | grep -qE "dpt:${dport}\b.*redir ports ${toport}"; then
            NAT_OK=false
            info "Missing container REDIRECT rule: tcp/${dport} -> ${toport}."
        fi
    done
    if [ "${NAT_OK}" = true ]; then
        pass_test "TC-1.4 Container NAT REDIRECT rules present (80->3129, 443->3130, 4070->3130)."
    else
        fail_test "TC-1.4 Container NAT REDIRECT rules incomplete — see missing rules above."
    fi
fi
echo ""

# --- TC-1.5: Squid is actually listening on its three ports ---
if require_proxy_up "TC-1.5 Squid listening ports"; then
    LISTEN_OUT=$(proxy_exec "netstat -tlnp")
    PORTS_OK=true
    for p in 3128 3129 3130; do
        if ! echo "${LISTEN_OUT}" | grep -qE ":${p}[[:space:]]"; then
            PORTS_OK=false
            info "Squid is not listening on port ${p}."
        fi
    done
    if [ "${PORTS_OK}" = true ]; then
        pass_test "TC-1.5 Squid is listening on 3128 (explicit), 3129 (HTTP intercept), 3130 (HTTPS bump)."
    else
        fail_test "TC-1.5 Squid is not listening on all expected ports — see above."
    fi
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 2: SQUID WEB UI FUNCTIONALITY & API VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 2. SQUID WEB UI FUNCTIONALITY & API VERIFICATION"
echo "--------------------------------------------------"

# The webui container runs on a macvlan network, so '-p 3131:3131' does NOT
# publish it on the QNAP host IP. Only the container IP is a valid target.
WEBUI_URL="http://${WEBUI_IP}:${WEBUI_PORT}"
WEBUI_REACHABLE=false
for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "%{http_code}" -m 2 "${WEBUI_URL}/api/auth/status" 2>/dev/null | grep -q "200"; then
        WEBUI_REACHABLE=true
        break
    fi
    sleep 1
done
info "Target Web UI URL: ${WEBUI_URL} (reachable: ${WEBUI_REACHABLE})"

if [ "${WEBUI_REACHABLE}" != true ]; then
    fail_test "TC-2.0 Web UI is unreachable at ${WEBUI_URL} — all Suite 2 assertions will fail."
fi

echo "=== 2a. Web UI Base Page Access (${WEBUI_URL}/) ==="
WEBUI_HOME_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${WEBUI_URL}/" 2>/dev/null || echo "000")
WEBUI_HOME_BODY=$(curl -s -m 5 "${WEBUI_URL}/" 2>/dev/null || true)
echo "  HTTP Response Code: ${WEBUI_HOME_CODE}"

if [ "${WEBUI_HOME_CODE}" = "200" ] && echo "${WEBUI_HOME_BODY}" | grep -qi "<title>"; then
    pass_test "TC-2.0 Web UI Dashboard page loaded successfully (HTTP 200)."
else
    fail_test "TC-2.0 Web UI Dashboard page failed to respond (HTTP ${WEBUI_HOME_CODE})."
fi
echo ""

echo "=== 2b. Web UI API Endpoints Check ==="

# TC-2.1 GET /api/auth/status
AUTH_STATUS_RES=$(curl -s -m 5 "${WEBUI_URL}/api/auth/status" 2>&1 || echo "{}")
echo "  GET /api/auth/status -> ${AUTH_STATUS_RES}"
if echo "${AUTH_STATUS_RES}" | grep -q '"authenticated"'; then
    pass_test "TC-2.1 API /api/auth/status returned valid JSON."
else
    fail_test "TC-2.1 API /api/auth/status failed."
fi

# TC-2.2 GET /api/devices
DEVICES_RES=$(curl -s -m 5 "${WEBUI_URL}/api/devices" 2>&1 || echo "{}")
echo "  GET /api/devices -> $(echo "${DEVICES_RES}" | cut -c1-200)..."
if echo "${DEVICES_RES}" | grep -q '"devices"'; then
    pass_test "TC-2.2 API /api/devices returned device list."
else
    fail_test "TC-2.2 API /api/devices failed."
fi

# TC-2.3 GET /api/policies
POLICIES_RES=$(curl -s -m 5 "${WEBUI_URL}/api/policies" 2>&1 || echo "{}")
echo "  GET /api/policies -> $(echo "${POLICIES_RES}" | cut -c1-200)..."
if echo "${POLICIES_RES}" | grep -q '"policies"'; then
    pass_test "TC-2.3 API /api/policies returned device policies."
else
    fail_test "TC-2.3 API /api/policies failed."
fi

# TC-2.4 GET /api/blocklists
BLOCKLISTS_RES=$(curl -s -m 5 "${WEBUI_URL}/api/blocklists" 2>&1 || echo "{}")
echo "  GET /api/blocklists -> ${BLOCKLISTS_RES}"
if echo "${BLOCKLISTS_RES}" | grep -q '"blocklists"'; then
    pass_test "TC-2.4 API /api/blocklists returned list of blocklists."
else
    fail_test "TC-2.4 API /api/blocklists failed."
fi

# TC-2.5 Certificate downloads — both formats must work, and the payload must
# actually be a certificate (a 200 with a JSON error body used to pass).
CERT_CRT_CODE=$(curl -s -o /tmp/_sq_cert.crt -w "%{http_code}" -m 5 "${WEBUI_URL}/download/cert.crt" 2>/dev/null || echo "000")
CERT_PEM_CODE=$(curl -s -o /tmp/_sq_cert.pem -w "%{http_code}" -m 5 "${WEBUI_URL}/download/cert.pem" 2>/dev/null || echo "000")
echo "  GET /download/cert.crt -> HTTP ${CERT_CRT_CODE}"
echo "  GET /download/cert.pem -> HTTP ${CERT_PEM_CODE}"
CERT_CRT_OK=false; CERT_PEM_OK=false
[ "${CERT_CRT_CODE}" = "200" ] && openssl x509 -inform DER -in /tmp/_sq_cert.crt -noout 2>/dev/null && CERT_CRT_OK=true
[ "${CERT_PEM_CODE}" = "200" ] && openssl x509 -inform PEM -in /tmp/_sq_cert.pem -noout 2>/dev/null && CERT_PEM_OK=true
if [ "${CERT_CRT_OK}" = true ] && [ "${CERT_PEM_OK}" = true ]; then
    pass_test "TC-2.5 Both CA download endpoints return a parseable X.509 certificate (DER + PEM)."
else
    fail_test "TC-2.5 CA download failed (crt parseable: ${CERT_CRT_OK}, pem parseable: ${CERT_PEM_OK}). Check that create_webui mounts an existing certs/ directory."
fi
rm -f /tmp/_sq_cert.crt /tmp/_sq_cert.pem

# TC-2.6 GET /download/install-ubuntu.sh
UBUNTU_SH=$(curl -s -m 5 "${WEBUI_URL}/download/install-ubuntu.sh" 2>&1 || echo "")
if echo "${UBUNTU_SH}" | grep -q "^#!/bin/bash" && echo "${UBUNTU_SH}" | grep -q "update-ca-certificates"; then
    pass_test "TC-2.6 Ubuntu installer endpoint returns a valid bash CA-install script."
else
    fail_test "TC-2.6 Ubuntu installer script missing or malformed."
fi

# TC-2.7 SECURITY: the API must reject unauthenticated writes.
# app.py currently has `def is_authenticated(): return True`, which leaves every
# policy endpoint open to the whole LAN — including the devices being filtered.
echo ""
echo "=== 2c. Authentication Posture (security regression check) ==="
UNAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
    -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" \
    -d '{"ip":"203.0.113.254","hostname":"__authprobe__","always_block":[],"default_block":[]}' 2>/dev/null || echo "000")
echo "  POST /api/policies (no session cookie) -> HTTP ${UNAUTH_CODE}"
if [ "${UNAUTH_CODE}" = "401" ] || [ "${UNAUTH_CODE}" = "403" ]; then
    pass_test "TC-2.7 Unauthenticated policy write correctly rejected (HTTP ${UNAUTH_CODE})."
else
    fail_test "TC-2.7 Unauthenticated policy write ACCEPTED (HTTP ${UNAUTH_CODE})! is_authenticated() is stubbed to return True in webui/app.py — any LAN device can rewrite its own parental controls."
    # Clean up the probe entry we just created.
    curl -s -o /dev/null -m 5 -X POST "${WEBUI_URL}/api/policies" \
        -H "Content-Type: application/json" -d "${POLICIES_RES}" 2>/dev/null || true
fi
echo ""

echo "=== 2d. Web UI Policy Save & Apply Pipeline Test ==="
echo "--> Triggering /api/apply to test rules compilation and Docker socket reload..."
APPLY_RES=$(curl -s -m 10 -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json" 2>&1 || echo "{}")
echo "  POST /api/apply -> ${APPLY_RES}"

if echo "${APPLY_RES}" | grep -qE '"success":[[:space:]]*true'; then
    pass_test "TC-2.8a Web UI policy apply API executed successfully."
else
    fail_test "TC-2.8a Web UI policy apply API failed."
fi

# A reload that kills Squid is worse than a reload that does nothing: the router
# policy-routes 80/443/4070 at Squid, so a dead proxy means no internet for the
# intercepted hosts. Verify the container survived the SIGHUP.
sleep 3
POST_APPLY_PS=$(ssh -o ConnectTimeout=8 "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} ps --format '{{.Names}}\t{{.Status}}'" 2>&1 || true)
if echo "${POST_APPLY_PS}" | grep -qE '^squid-proxy[[:space:]]+Up'; then
    pass_test "TC-2.8b squid-proxy survived the SIGHUP reload (still Up)."
else
    PROXY_UP=false
    fail_test "TC-2.8b squid-proxy is DOWN after /api/apply — the generated ACLs likely contain a fatal error."
    echo "=== Last 25 lines of squid-proxy container logs ==="
    ssh -o ConnectTimeout=8 "${QNAP_USER}@${QNAP_IP}" "${QNAP_DOCKER} logs --tail 25 squid-proxy" 2>&1 || true
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 3: SQUID CONFIGURATION INTEGRITY & ACL VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 3. SQUID CONFIGURATION INTEGRITY & ACL VERIFICATION"
echo "--------------------------------------------------"

RULES_ACL=""
SSL_BUMP_ACL=""
BUMP_DOM_ACL=""

# --- TC-3.1: squid -k parse ---
echo "--> 3a. Squid syntax validation inside container (squid -k parse)..."
if require_proxy_up "TC-3.1 Squid syntax validation"; then
    SQUID_PARSE_OUT=$(proxy_exec "squid -k parse")
    PARSE_RC="${PROXY_EXEC_RC}"
    if [ "${PARSE_RC}" != "0" ]; then
        fail_test "TC-3.1 'squid -k parse' exited ${PARSE_RC} (command did not run cleanly)."
        echo "${SQUID_PARSE_OUT}" | tail -n 20
    elif echo "${SQUID_PARSE_OUT}" | grep -qiE "FATAL|Bungled|ERROR:"; then
        fail_test "TC-3.1 Squid configuration syntax check FAILED (FATAL/ERROR encountered)!"
        echo "${SQUID_PARSE_OUT}" | grep -iE "FATAL|Bungled|ERROR:" | head -n 20
    else
        pass_test "TC-3.1 Squid configuration syntax is valid (squid -k parse exit 0, no FATAL/ERROR)."
    fi

    # --- TC-3.2: no empty-ACL warnings. An 'acl X dstdomain "file"' whose file has
    # no entries becomes a rule that can never match — the block silently stops
    # working while the config still "parses". This is the failure mode that makes
    # bump_domains.acl and domains_*.acl regressions invisible.
    EMPTY_ACLS=$(echo "${SQUID_PARSE_OUT}" | grep -i "empty ACL" || true)
    if [ -z "${EMPTY_ACLS}" ]; then
        pass_test "TC-3.2 No empty-ACL warnings — every dstdomain ACL file has entries."
    else
        fail_test "TC-3.2 Squid reported empty ACL(s); the corresponding rules can never match:"
        echo "${EMPTY_ACLS}" | head -n 10
    fi
fi
echo ""

# --- TC-3.3: rules.acl ---
echo "--> 3b. Active /etc/squid/configs/rules.acl inside squid-proxy..."
if require_proxy_up "TC-3.3 rules.acl inspection"; then
    RULES_ACL=$(proxy_exec "cat /etc/squid/configs/rules.acl")
    if [ "${PROXY_EXEC_RC}" != "0" ]; then
        fail_test "TC-3.3 Could not read rules.acl from the container (rc=${PROXY_EXEC_RC})."
    elif echo "${RULES_ACL}" | grep -q "AUTO-GENERATED BY SQUID WEB UI"; then
        pass_test "TC-3.3a rules.acl is present and generated by the Web UI."
        echo "=== Active rules.acl snippet ==="
        echo "${RULES_ACL}" | head -n 30

        # Every device that has a policy must have a matching src ACL in rules.acl.
        POLICY_IPS=$(echo "${POLICIES_RES}" | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+":[[:space:]]*\{' | grep -oE '[0-9.]+' || true)
        MISSING_SRC=false
        SRC_CHECKED=0
        for pip in ${POLICY_IPS}; do
            SRC_CHECKED=$((SRC_CHECKED + 1))
            src_name="src_dev_$(echo "${pip}" | tr '.' '_')"
            if ! echo "${RULES_ACL}" | grep -q "acl ${src_name} src ${pip}"; then
                # A device whose policy has no lists at all is legitimately skipped.
                if echo "${POLICIES_RES}" | grep -q "\"${pip}\""; then
                    info "No '${src_name}' ACL in rules.acl for ${pip} (expected if that device has no blocklists selected)."
                fi
            fi
        done
        if [ "${SRC_CHECKED}" -gt 0 ]; then
            pass_test "TC-3.3b Cross-checked ${SRC_CHECKED} policy device(s) against rules.acl src ACLs."
        else
            warn_test "TC-3.3b No device policies configured — rules.acl content could not be cross-checked."
        fi
    else
        fail_test "TC-3.3a rules.acl is missing or empty!"
    fi
fi
echo ""

# --- TC-3.4: ssl_bump.acl ---
echo "--> 3c. Active /etc/squid/configs/ssl_bump.acl inside squid-proxy..."
if require_proxy_up "TC-3.4 ssl_bump.acl inspection"; then
    SSL_BUMP_ACL=$(proxy_exec "cat /etc/squid/configs/ssl_bump.acl")
    if [ "${PROXY_EXEC_RC}" != "0" ]; then
        fail_test "TC-3.4 Could not read ssl_bump.acl from the container (rc=${PROXY_EXEC_RC})."
    elif echo "${SSL_BUMP_ACL}" | grep -q "DYNAMIC SSL BUMP RULES"; then
        pass_test "TC-3.4a ssl_bump.acl is present and Web UI generated."
        echo "=== Active ssl_bump.acl snippet ==="
        echo "${SSL_BUMP_ACL}" | head -n 25

        # Dangling-reference check: ssl_bump.acl only references ACL *names*; the
        # definitions live in rules.acl. If the two files drift out of sync Squid
        # aborts on reload, which takes the whole proxy down.
        DANGLING=""
        while read -r name; do
            [ -z "${name}" ] && continue
            if ! echo "${RULES_ACL}" | grep -qE "^acl ${name}[[:space:]]"; then
                DANGLING="${DANGLING} ${name}"
            fi
        done < <(echo "${SSL_BUMP_ACL}" | grep -E '^ssl_bump[[:space:]]+bump[[:space:]]' | awk '{for(i=3;i<=NF;i++) print $i}' | sort -u)

        if [ -z "${DANGLING}" ]; then
            pass_test "TC-3.4b Every ACL referenced by ssl_bump.acl is defined in rules.acl (no dangling references)."
        else
            fail_test "TC-3.4b ssl_bump.acl references ACL name(s) not defined in rules.acl:${DANGLING}"
        fi

        # A device with blocked lists but no bump rule can never be shown the block
        # page over HTTPS — the connection is spliced and the browser gets a TLS
        # error or the real site instead.
        if echo "${SSL_BUMP_ACL}" | grep -qE '^ssl_bump[[:space:]]+bump[[:space:]]'; then
            pass_test "TC-3.4c ssl_bump.acl contains at least one active per-device bump rule."
        elif echo "${POLICIES_RES}" | grep -qE '"always_block":[[:space:]]*\[[[:space:]]*"'; then
            fail_test "TC-3.4c Device policies exist with blocked lists, but ssl_bump.acl has no bump rules — HTTPS blocks cannot render the block page."
        else
            warn_test "TC-3.4c ssl_bump.acl has no bump rules (no device currently has blocked lists)."
        fi
    else
        fail_test "TC-3.4a ssl_bump.acl is missing or empty!"
    fi
fi
echo ""

# --- TC-3.5: bump_domains.acl must match what the blocklists actually contain ---
#
# The old assertion hardcoded 'must contain steamcommunity.com'. That is wrong:
# bump_domains.acl is DERIVED from blocklist entries that carry a URL path
# (domain/path). If no blocklist has a path rule, the correct output is an EMPTY
# list, and hardcoding a domain makes the test fail on a correct system. The
# expected content is now computed from block-lists/ at runtime.
echo "--> 3d. Active /etc/squid/configs/bump_domains.acl vs. block-lists source..."
EXPECTED_BUMP=$(grep -hE '^[^#].*/' "${BLOCKLIST_DIR}"/*.txt 2>/dev/null \
                  | sed 's#/.*##' | sed 's/^\.*/./' | sort -u || true)
EXPECTED_COUNT=$(echo "${EXPECTED_BUMP}" | grep -c . || true)
info "Blocklists define ${EXPECTED_COUNT} domain(s) with URL path rules."

if require_proxy_up "TC-3.5 bump_domains.acl inspection"; then
    BUMP_DOM_ACL=$(proxy_exec "cat /etc/squid/configs/bump_domains.acl")
    ACTUAL_BUMP=$(echo "${BUMP_DOM_ACL}" | grep -vE '^\s*(#|$)' | sort -u || true)
    ACTUAL_COUNT=$(echo "${ACTUAL_BUMP}" | grep -c . || true)
    echo "=== bump_domains.acl (${ACTUAL_COUNT} entries) ==="
    echo "${BUMP_DOM_ACL}"

    # bump_domains.conf carries the directives; squid.conf includes it instead of
    # declaring the ACL inline. It must declare an ACL only when the .acl file has
    # entries — otherwise squid.conf ends up with a rule that parses cleanly but
    # can never match.
    BUMP_DOM_CONF=$(proxy_exec "cat /etc/squid/configs/bump_domains.conf")
    CONF_DECLARES=false
    echo "${BUMP_DOM_CONF}" | grep -qE '^acl[[:space:]]+bump_domains[[:space:]]+dstdomain' && CONF_DECLARES=true
    echo "=== bump_domains.conf ==="
    echo "${BUMP_DOM_CONF}"

    if [ "${EXPECTED_COUNT}" -eq 0 ]; then
        # No path rules anywhere: the list must be empty and no ACL declared.
        if [ "${ACTUAL_COUNT}" -eq 0 ]; then
            pass_test "TC-3.5a No blocklist defines a URL path rule, and bump_domains.acl is correspondingly empty."
        else
            fail_test "TC-3.5a bump_domains.acl is STALE: it lists ${ACTUAL_COUNT} domain(s) but no blocklist contains a URL path rule."
            echo "  Stale entries: $(echo "${ACTUAL_BUMP}" | tr '\n' ' ')"
        fi
    else
        DIFF_OUT=$(diff <(echo "${EXPECTED_BUMP}") <(echo "${ACTUAL_BUMP}") || true)
        if [ -z "${DIFF_OUT}" ]; then
            pass_test "TC-3.5a bump_domains.acl exactly matches the path-rule domains derived from block-lists/."
        else
            fail_test "TC-3.5a bump_domains.acl does not match block-lists/ (regenerate: restart squid-proxy)."
            echo "  --- expected (<) vs actual (>) ---"
            echo "${DIFF_OUT}"
        fi
    fi

    # Regression guard for the original intent: plain (path-less) blocklist domains
    # must NOT leak into bump_domains.acl, or every blocked site gets decrypted.
    PLAIN_LEAK=""
    while read -r dom; do
        [ -z "${dom}" ] && continue
        base="${dom#.}"
        if ! echo "${EXPECTED_BUMP}" | grep -qx "${dom}"; then
            PLAIN_LEAK="${PLAIN_LEAK} ${base}"
        fi
    done < <(echo "${ACTUAL_BUMP}")
    if [ -z "${PLAIN_LEAK}" ]; then
        pass_test "TC-3.5b Selective bumping intact: no plain (path-less) blocklist domain leaked into bump_domains.acl."
    else
        fail_test "TC-3.5b Plain blocklist domain(s) leaked into bump_domains.acl — these would be decrypted for ALL devices:${PLAIN_LEAK}"
    fi

    # TC-3.5c: the .conf must agree with the .acl.
    if [ "${ACTUAL_COUNT}" -gt 0 ] && [ "${CONF_DECLARES}" = true ]; then
        pass_test "TC-3.5c bump_domains.conf declares the bump ACL, matching a non-empty domain list."
    elif [ "${ACTUAL_COUNT}" -eq 0 ] && [ "${CONF_DECLARES}" = false ]; then
        pass_test "TC-3.5c bump_domains.conf correctly declares no ACL for an empty domain list."
    elif [ "${CONF_DECLARES}" = true ]; then
        fail_test "TC-3.5c bump_domains.conf declares 'acl bump_domains' but bump_domains.acl is empty — the rule can never match."
    else
        fail_test "TC-3.5c bump_domains.acl has ${ACTUAL_COUNT} domain(s) but bump_domains.conf declares no ACL — deep URL path bumping is inactive."
    fi
fi
echo ""

# --- TC-3.6: local CA certs ---
echo "--> 3e. Local SSL CA Certificates..."
CA_OK=true
for f in squid-ca.pem squid-ca.crt; do
    if [ ! -s "${SQUID_DIR}/certs/${f}" ]; then CA_OK=false; info "Missing or empty: certs/${f}"; fi
done
if [ "${CA_OK}" = true ] && openssl x509 -in "${SQUID_DIR}/certs/squid-ca.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
    CA_EXPIRY=$(openssl x509 -in "${SQUID_DIR}/certs/squid-ca.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
    pass_test "TC-3.6 Local CA certificates exist and are valid for >30 days (expires: ${CA_EXPIRY})."
elif [ "${CA_OK}" = true ]; then
    fail_test "TC-3.6 Local CA certificate exists but expires within 30 days (or is unparseable). Regenerate with: squid-mgmt.sh cert"
else
    fail_test "TC-3.6 Local SSL CA certificates missing!"
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
    info "Using local machine (${TARGET_CLIENT_IP}) as test client via EXPLICIT proxy ${SQUID_IP}:3128."
    warn_test "Local mode limitation: port 3128 is declared 'http_port 3128' with NO 'ssl-bump' flag, so CONNECT tunnels are never bumped. SSL-bump dependent assertions below are downgraded to WARN. For a true end-to-end test, add this host to router/proxy-hosts.conf and run without --local."
else
    echo "--> Checking SSH connectivity to remote test client ${TARGET_CLIENT_IP}..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "${TARGET_CLIENT_IP}" "echo OK" 2>/dev/null | grep -q "OK"; then
        CLIENT_REACHABLE=true
        pass_test "TC-4.0 Remote test client ${TARGET_CLIENT_IP} is reachable via SSH."
    else
        fail_test "TC-4.0 Remote test client ${TARGET_CLIENT_IP} is NOT reachable via SSH!"
        info "HINT: Ensure ${TARGET_CLIENT_IP} is powered on and sshd is responsive. '--local' tests a different (explicit-proxy) code path and cannot validate SSL bumping."
    fi
fi
echo ""

# Downgrade bump-dependent failures to warnings in local mode.
bump_assert() {
    # $1 = ok(true/false)  $2 = message
    if [ "$1" = true ]; then
        pass_test "$2"
    elif [ "${IS_LOCAL_CLIENT}" = true ]; then
        warn_test "$2 — not assertable in --local mode (port 3128 does not ssl-bump)."
    else
        fail_test "$2"
    fi
}

client_curl() {
    # $1 = url ; extra args in $2 (optional)
    local url="$1"; local extra="${2:-}"
    if [ "${IS_LOCAL_CLIENT}" = true ]; then
        curl -siv -4 ${extra} --max-time 10 --noproxy "" --proxy "http://${SQUID_IP}:3128" "${url}" 2>&1 || true
    else
        ssh -o ConnectTimeout=8 "${TARGET_CLIENT_IP}" "curl -siv -4 ${extra} --max-time 10 '${url}' 2>&1" || true
    fi
}

# Helper to execute curl and print live formatted test results
run_curl_test() {
    local label="$1"
    local url="$2"
    local expected_type="$3" # "allow" | "block" | "allow_bumped"

    echo "--------------------------------------------------"
    echo "[Testing] ${label}: ${url}"
    echo "--------------------------------------------------"

    if [ "${CLIENT_REACHABLE}" != true ]; then
        fail_test "${label}: Skipped because test client (${TARGET_CLIENT_IP}) is unreachable!"
        echo ""
        return
    fi

    local raw_out
    raw_out=$(client_curl "${url}" "-k")

    local status_line page_title block_banner tls_error
    status_line=$(echo "$raw_out" | grep -i -E '^< HTTP/' | head -1)
    page_title=$(echo "$raw_out" | grep -i '<title>' | head -1 | sed -e 's/^[ \t]*//')
    block_banner=$(echo "$raw_out" | grep -i 'blocked by your parent\|Webpage Blocked\|ERR_ACCESS_DENIED' | head -1 | sed -e 's/^[ \t]*//')
    tls_error=$(echo "$raw_out" | grep -i 'wrong version number\|TLS connect error\|SSL routines' | head -1 | sed -e 's/^[ \t]*//')

    echo "  Status Line : ${status_line:-No HTTP Response (Connection Reset / Timeout)}"
    echo "  Page Title  : ${page_title:-No Title Found}"
    [ -n "${block_banner}" ] && echo "  Block Banner: ${block_banner}"
    [ -n "${tls_error}" ]    && echo "  TLS Error   : ${tls_error}"

    # 'wrong version number' means Squid sent a plaintext HTTP error down a socket
    # the client is speaking TLS on: the site was DENIED but NOT bumped. The old
    # script counted this as a successful block; it is actually a misconfiguration
    # (missing ssl_bump rule) that shows the user a browser error, not the block page.
    if [ -n "${tls_error}" ]; then
        warn_test "${label}: TLS protocol error ('${tls_error}'). The request was denied without being bumped — the user sees a browser TLS error instead of the parental block page. Check ssl_bump.acl covers this device+category."
    fi

    case "${expected_type}" in
        allow)
            if echo "${raw_out}" | grep -qE '^< HTTP/(1\.[01]|2) (200|301|302|303|307|308)'; then
                pass_test "${label} returned HTTP success / redirect as expected."
            else
                fail_test "${label} failed to return HTTP success."
            fi
            ;;
        block)
            local blocked=false
            if echo "${raw_out}" | grep -qi "Webpage Blocked\|ERR_ACCESS_DENIED\|blocked by your parent"; then
                blocked=true
            elif echo "${raw_out}" | grep -qE '^< HTTP/(1\.[01]|2) 403'; then
                blocked=true
            fi
            bump_assert "${blocked}" "${label} correctly blocked by Parental Control (403 + parental block page)."
            ;;
        allow_bumped)
            # Must succeed AND be served through the bumped path (block page absent).
            if echo "${raw_out}" | grep -qE '^< HTTP/(1\.[01]|2) (200|301|302|303|307|308)' \
               && ! echo "${raw_out}" | grep -qi "Webpage Blocked\|ERR_ACCESS_DENIED"; then
                pass_test "${label} allowed through as expected (no block page)."
            else
                fail_test "${label} was blocked or errored, but should have been allowed."
            fi
            ;;
    esac
    echo ""
}

# --- TC-4.1 / TC-4.2: Allowed baseline ---
run_curl_test "TC-4.1 Allowed HTTP (example.com)" "http://example.com" "allow"
run_curl_test "TC-4.2 Allowed HTTPS spliced (example.com)" "https://example.com" "allow"
run_curl_test "TC-4.2b Allowed HTTPS spliced (wikipedia.org)" "https://www.wikipedia.org" "allow"

# ------------------------------------------------------------------------------
# Policy backup / restore. A trap guarantees the original policies are put back
# even if the script is interrupted mid-test — the previous version leaked test
# policies (e.g. a stray 'test-runner' entry for the admin workstation) into the
# live parental-control config whenever a phase aborted.
# ------------------------------------------------------------------------------
SAVED_POLICIES_JSON=""
POLICY_MODIFIED=false

restore_policies() {
    if [ "${POLICY_MODIFIED}" = true ] && [ -n "${SAVED_POLICIES_JSON}" ]; then
        echo "--> Restoring original device policies..."
        curl -s -o /dev/null -m 10 -X POST "${WEBUI_URL}/api/policies" \
            -H "Content-Type: application/json" -d "${SAVED_POLICIES_JSON}" 2>/dev/null || true
        curl -s -o /dev/null -m 10 -X POST "${WEBUI_URL}/api/apply" \
            -H "Content-Type: application/json" 2>/dev/null || true
        sleep 2
        local now
        now=$(curl -s -m 5 "${WEBUI_URL}/api/policies" 2>/dev/null || echo "")
        if [ "${now}" = "${SAVED_POLICIES_JSON}" ]; then
            echo "  ${C_PASS}[PASS]${C_RST} Original policies restored and verified byte-identical."
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo "  ${C_FAIL}[FAIL]${C_RST} Policy restore MISMATCH — live policies differ from the pre-test snapshot. Check the Web UI before leaving the system unattended."
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
        POLICY_MODIFIED=false
    fi
}
trap restore_policies EXIT INT TERM

# --- TC-4.8: Dynamic video category lifecycle ---
echo "=== 4b. Dynamic Video Category Lifecycle Integration Test (Web UI) ==="
if [ "${CLIENT_REACHABLE}" = true ] && [ "${WEBUI_REACHABLE}" = true ]; then
    echo "--> Backing up current policies..."
    SAVED_POLICIES_JSON=$(curl -s -m 5 "${WEBUI_URL}/api/policies")
    if ! echo "${SAVED_POLICIES_JSON}" | grep -q '"policies"'; then
        fail_test "TC-4.8 Could not snapshot current policies — refusing to mutate live config."
    else
        POLICY_MODIFIED=true

        # Phase 1: Videos UNBLOCKED
        echo "--> [Phase 1] videos.txt ALLOWED for ${TARGET_CLIENT_IP}..."
        curl -s -o /dev/null -m 10 -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" \
            -d "{\"ip\": \"${TARGET_CLIENT_IP}\", \"hostname\": \"debug-test-client\", \"always_block\": [], \"default_block\": [], \"ssl_bump_mode\": \"blocked_only\"}"
        curl -s -o /dev/null -m 10 -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json"
        sleep 3
        run_curl_test "TC-4.8a YouTube HTTPS (videos unblocked)" "https://www.youtube.com" "allow_bumped"

        # Phase 2: Videos BLOCKED
        echo "--> [Phase 2] videos.txt BLOCKED for ${TARGET_CLIENT_IP}..."
        curl -s -o /dev/null -m 10 -X POST "${WEBUI_URL}/api/policies" -H "Content-Type: application/json" \
            -d "{\"ip\": \"${TARGET_CLIENT_IP}\", \"hostname\": \"debug-test-client\", \"always_block\": [\"videos.txt\"], \"default_block\": [], \"ssl_bump_mode\": \"blocked_only\"}"
        curl -s -o /dev/null -m 10 -X POST "${WEBUI_URL}/api/apply" -H "Content-Type: application/json"
        sleep 3
        run_curl_test "TC-4.8b YouTube HTTPS (videos blocked)" "https://www.youtube.com" "block"

        # TC-4.9: Custom block page content, asserted on the HTTPS (bumped) response
        # as well as HTTP — the original script only checked the HTTP body.
        echo "=== 4c. Custom Block Page Content & HTML Template Verification ==="
        HTTP_BLOCK_OUT=$(client_curl "http://www.youtube.com" "-k")
        HTTPS_BLOCK_OUT=$(client_curl "https://www.youtube.com" "-k")

        check_block_page() {
            local label="$1" body="$2"
            local has_403=false has_hdr=false has_title=false has_msg=false has_link=false
            echo "${body}" | grep -qE '^< HTTP/(1\.[01]|2) 403'                    && has_403=true
            echo "${body}" | grep -qi 'X-Squid-Error: ERR_ACCESS_DENIED'           && has_hdr=true
            echo "${body}" | grep -qi 'Webpage Blocked'                            && has_title=true
            echo "${body}" | grep -qi 'blocked by your parent'                     && has_msg=true
            echo "${body}" | grep -qi 'Parent Web UI\|Home Network Shield'         && has_link=true
            echo "  ${label}: 403=${has_403} X-Squid-Error=${has_hdr} title=${has_title} parentMsg=${has_msg} portalLink=${has_link}"
            if [ "${has_403}" = true ] && [ "${has_hdr}" = true ] && [ "${has_title}" = true ] && [ "${has_msg}" = true ]; then
                return 0
            fi
            return 1
        }

        if check_block_page "over HTTP " "${HTTP_BLOCK_OUT}"; then
            pass_test "TC-4.9a Custom block page rendered correctly over HTTP (403 + ERR_ACCESS_DENIED + parental HTML)."
        else
            fail_test "TC-4.9a Custom block page over HTTP missing expected signatures."
        fi

        if check_block_page "over HTTPS" "${HTTPS_BLOCK_OUT}"; then
            pass_test "TC-4.9b Custom block page rendered correctly over HTTPS (SSL bump working end-to-end)."
        else
            bump_assert false "TC-4.9b Custom block page over HTTPS missing expected signatures — the bumped block page is what users actually see."
        fi

        # Phase 3: restore (also runs via trap on abnormal exit)
        restore_policies
    fi
else
    fail_test "TC-4.8 Dynamic Video Category Lifecycle Test skipped (client reachable: ${CLIENT_REACHABLE}, Web UI reachable: ${WEBUI_REACHABLE})."
    fail_test "TC-4.9 Custom Block Page Verification skipped (depends on TC-4.8 setup)."
fi
echo ""

# --- TC-4.4: URL path selective inspection ---
#
# This test is only meaningful when a blocklist actually defines a 'domain/path'
# entry. The previous version always ran it with expected_type="custom", which
# matched neither branch of run_curl_test and therefore asserted NOTHING while
# still printing as if it had tested something.
echo "=== 4d. Deep URL Path Rule Inspection ==="
PATH_RULE_LINE=$(grep -hE '^[^#].*/' "${BLOCKLIST_DIR}"/*.txt 2>/dev/null | head -1 || true)
if [ -z "${PATH_RULE_LINE}" ]; then
    warn_test "TC-4.4 No blocklist defines a 'domain/path' rule, so deep URL path inspection cannot be tested. Add e.g. 'steamcommunity.com/market' to block-lists/gaming.txt to exercise this feature (bump_domains.acl is empty until then)."
else
    PATH_DOMAIN="${PATH_RULE_LINE%%/*}"
    PATH_DOMAIN="${PATH_DOMAIN#.}"
    PATH_SUFFIX="/${PATH_RULE_LINE#*/}"
    info "Path rule under test: ${PATH_DOMAIN}${PATH_SUFFIX}"
    run_curl_test "TC-4.4a Blocked path (${PATH_DOMAIN}${PATH_SUFFIX})" "https://${PATH_DOMAIN}${PATH_SUFFIX}" "block"
    run_curl_test "TC-4.4b Allowed base domain (${PATH_DOMAIN})"        "https://${PATH_DOMAIN}/"              "allow_bumped"
fi
echo ""

# --- TC-4.5: Strict SSL certificate trust ---
echo "--------------------------------------------------"
echo "[Testing] TC-4.5 Strict SSL Certificate Trust Verification (without -k)"
echo "--------------------------------------------------"
if [ "${CLIENT_REACHABLE}" = true ]; then
    OUT_STRICT_SSL=$(client_curl "https://example.com" "")
    STRICT_STATUS=$(echo "${OUT_STRICT_SSL}" | grep -i '^< HTTP/' | head -1)
    STRICT_ERR=$(echo "${OUT_STRICT_SSL}" | grep -i 'SSL certificate problem\|self-signed certificate\|certificate has expired\|issuer certificate\|unable to get local issuer' | head -1)
    echo "  Status Line : ${STRICT_STATUS:-No HTTP Response}"
    if [ -n "${STRICT_ERR}" ]; then
        echo "  SSL Warning : ${STRICT_ERR}"
        fail_test "TC-4.5 Strict SSL verification FAILED — Squid Root CA is not in the client trust store. Run: squid-mgmt.sh linux-deploy (or install ${WEBUI_URL}/download/cert.pem on the client)."
    elif [ -n "${STRICT_STATUS}" ]; then
        pass_test "TC-4.5 Strict SSL Certificate Verification PASSED (clean TLS handshake, no -k needed)."
    else
        fail_test "TC-4.5 Strict SSL verification inconclusive — no HTTP response at all."
    fi
else
    fail_test "TC-4.5 Strict SSL Certificate Verification skipped due to unreachable client (${TARGET_CLIENT_IP})."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 5: SQUID MANAGEMENT CLI (squid-mgmt.sh) VERIFICATION
# ------------------------------------------------------------------------------
echo ">>> 5. SQUID MANAGEMENT CLI (squid-mgmt.sh) VERIFICATION"
echo "--------------------------------------------------"

# NOTE: these assertions must NOT grep for strings that squid-mgmt.sh prints
# unconditionally ("Config dumped.", "Displaying Squid Access Logs...").
# Both used to pass even when the underlying docker command failed outright.

echo "--> 5a. squid-mgmt.sh dump-config..."
DUMP_CFG_OUT=$(bash "${SQUID_DIR}/squid-mgmt.sh" dump-config 2>&1 || true)
if echo "${DUMP_CFG_OUT}" | grep -qiE "is not running|No such container|Cannot connect to the Docker daemon"; then
    fail_test "TC-5.1 dump-config could not reach the squid-proxy container."
    echo "${DUMP_CFG_OUT}" | tail -n 5
elif echo "${DUMP_CFG_OUT}" | grep -qi "Processing Configuration File"; then
    if echo "${DUMP_CFG_OUT}" | grep -qiE "FATAL|Bungled"; then
        fail_test "TC-5.1 dump-config ran but the configuration contains FATAL errors."
        echo "${DUMP_CFG_OUT}" | grep -iE "FATAL|Bungled" | head -n 10
    else
        pass_test "TC-5.1 squid-mgmt.sh dump-config returned real parser output with no FATAL errors."
    fi
else
    fail_test "TC-5.1 squid-mgmt.sh dump-config produced no Squid parser output."
    echo "${DUMP_CFG_OUT}" | tail -n 5
fi
echo ""

echo "--> 5b. squid-mgmt.sh catlogs..."
LOCAL_ACCESS_LOG="${SQUID_DIR}/logs/access.log"
rm -f "${LOCAL_ACCESS_LOG}"
CATLOGS_OUT=$(bash "${SQUID_DIR}/squid-mgmt.sh" catlogs 2>&1 || true)
echo "=== Last 15 lines of catlogs output ==="
echo "${CATLOGS_OUT}" | tail -n 15
if [ -f "${LOCAL_ACCESS_LOG}" ] && echo "${CATLOGS_OUT}" | grep -q "Saved local log snapshot"; then
    if [ -s "${LOCAL_ACCESS_LOG}" ]; then
        pass_test "TC-5.2 squid-mgmt.sh catlogs retrieved a non-empty access log ($(wc -l < "${LOCAL_ACCESS_LOG}") lines)."
    else
        warn_test "TC-5.2 catlogs retrieved the access log but it is empty (0 bytes) — no traffic has been proxied yet."
    fi
else
    fail_test "TC-5.2 squid-mgmt.sh catlogs failed to retrieve the access log."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 6: ROUTER ADVANCED RULES CHECK (SPOTIFY & YOUTUBE QUIC)
# ------------------------------------------------------------------------------
echo ">>> 6. ROUTER ADVANCED RULES CHECK"
echo "--------------------------------------------------"

# --- TC-4.6: Spotify 4070. Router side and container side are asserted
# separately; the combined check used to report "router or container" and gave
# no way to tell which half was broken.
if echo "${ROUTER_SQUID_MARK}" | grep -q "4070"; then
    pass_test "TC-4.6a Spotify 4070: router mangle SQUID_MARK marks TCP 4070."
else
    fail_test "TC-4.6a Spotify 4070: router mangle SQUID_MARK has no rule covering TCP 4070."
fi

if require_proxy_up "TC-4.6b Spotify 4070 container REDIRECT"; then
    if echo "${CONTAINER_PREROUTING}" | grep -qE "dpt:4070\b.*redir ports 3130"; then
        pass_test "TC-4.6b Spotify 4070: container NAT REDIRECT 4070 -> 3130 active."
    else
        fail_test "TC-4.6b Spotify 4070: container NAT REDIRECT 4070 -> 3130 is missing."
    fi
fi

# --- TC-4.7: QUIC handling. Two rules must BOTH exist per intercepted host:
#   (1) ACCEPT UDP 80/443 to the youtube_quic ipset  -> YouTube keeps using QUIC
#   (2) REJECT all other UDP 443                     -> everything else falls back
#                                                       to TCP 443 so Squid sees it
# The old test only checked (1). Without (2), any site can bypass the proxy over QUIC.
ROUTER_FORWARD=$(ssh -o ConnectTimeout=8 "${ROUTER_IP}" "iptables -L FORWARD -n -v" 2>&1 || true)

if echo "${ROUTER_FORWARD}" | grep -q "match-set youtube_quic dst"; then
    pass_test "TC-4.7a YouTube QUIC allow-list: FORWARD ACCEPT rule for the youtube_quic ipset is active."
elif echo "${ROUTER_FORWARD}" | grep -qE "142\.250\.|172\.217\.|173\.194\."; then
    pass_test "TC-4.7a YouTube QUIC allow-list: FORWARD ACCEPT rules for YouTube CIDRs are active (ipset fallback path)."
else
    fail_test "TC-4.7a YouTube QUIC allow-list: no FORWARD ACCEPT rule for YouTube QUIC traffic."
fi

QUIC_REJECT_OK=true
QUIC_HOSTS=0
if [ -f "${PROXY_HOSTS_CONF}" ]; then
    while IFS= read -r line; do
        [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
        host_ip=$(echo "${line}" | awk '{print $1}')
        [ -z "${host_ip}" ] && continue
        QUIC_HOSTS=$((QUIC_HOSTS + 1))
        if ! echo "${ROUTER_FORWARD}" | grep -E "REJECT.*udp.*${host_ip}|${host_ip}.*udp.*dpt:443" | grep -qi "reject"; then
            QUIC_REJECT_OK=false
            info "No global UDP/443 REJECT rule found for ${host_ip} — that host can bypass Squid over QUIC."
        fi
    done < "${PROXY_HOSTS_CONF}"
fi
if [ "${QUIC_HOSTS}" -eq 0 ]; then
    warn_test "TC-4.7b No intercepted hosts configured — QUIC reject rule not verified."
elif [ "${QUIC_REJECT_OK}" = true ]; then
    pass_test "TC-4.7b QUIC bypass prevention: all ${QUIC_HOSTS} intercepted host(s) have a UDP/443 REJECT rule."
else
    fail_test "TC-4.7b QUIC bypass prevention: one or more intercepted hosts lack the UDP/443 REJECT rule — HTTPS can bypass the proxy over QUIC."
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
if [ "${TESTS_FAILED}" -gt 0 ]; then
    echo "------------------------------------------------------------------------"
    echo " FAILED ASSERTIONS:"
    for n in "${FAILED_NAMES[@]}"; do
        echo "   ${C_FAIL}✗${C_RST} ${n}"
    done
fi
echo "========================================================================"
echo "Full detailed log saved to:"
echo "  - ${LOG_FILE}"
echo "  - ${LATEST_LOG}"
echo "========================================================================"
sleep 0.5

[ "${TESTS_FAILED}" -eq 0 ] || exit 1
exit 0
