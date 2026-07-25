#!/bin/bash

# --- 1. CONFIGURATION ---
SQUID_INSTANCE_NAME="squid-proxy"

# Workstation Paths
GITDIR="${HOME}/GitHub"
SQUID_DIR="${GITDIR}/personal/home-network/squid"
BLOCKLIST_DIR="${SQUID_DIR}/block-lists"
CERT_DIR="${SQUID_DIR}/certs"
SQUID_CONF_TEMPLATE="${SQUID_DIR}/configs/squid.conf.template"

# Remote QNAP Settings
QNAP_IP="192.168.1.2"
QNAP_SERVER="admin@${QNAP_IP}"
BINDIR="/share/CACHEDEV1_DATA/.qpkg/container-station/bin"
DOCKER="${BINDIR}/docker"

# Remote paths on QNAP for Squid
SQUID_INSTANCE_NAME="squid-proxy"
SQUID_BASE_DIR="/share/Container/${SQUID_INSTANCE_NAME}"
SQUID_CERT_DIR_REMOTE="${SQUID_BASE_DIR}/certs"
SQUID_BLOCKLIST_DIR_REMOTE="${SQUID_BASE_DIR}/block-lists"
SQUID_CONF_REMOTE="${SQUID_BASE_DIR}/configs/squid.conf"

# Path for clients to download the certificate
CERT_DOWNLOAD_DIR="/share/CACHEDEV1_DATA/Web/certs"

# ASUS Router Settings (Merlin firmware)
ROUTER_IP="192.168.0.1"
ROUTER_SERVER="admin@${ROUTER_IP}"
ROUTER_SSH_OPTS="-o PubkeyAcceptedKeyTypes=+ssh-rsa"
ROUTER_SCP_OPTS="-O -o PubkeyAcceptedKeyTypes=+ssh-rsa"  # -O forces legacy SCP (Dropbear has no sftp-server)
ROUTER_FIREWALL_SCRIPT="/jffs/scripts/firewall-start"

# Squid Proxy Settings (used in generated router rules)
SQUID_PROXY_IP="192.168.1.90"
SQUID_HTTP_PORT="3129"
SQUID_HTTPS_PORT="3130"

# Local router config sources
ROUTER_DIR="${SQUID_DIR}/router"
PROXY_HOSTS_CONF="${ROUTER_DIR}/proxy-hosts.conf"

mkdir -p "${CERT_DIR}" "${BLOCKLIST_DIR}"

# --- 2. CORE FUNCTIONS ---

generate_cert() {
    echo "-----------------------------------------------"
    echo ">>> Checking for SSL Certificate..."
    if [ -f "${CERT_DIR}/squid-ca.pem" ]; then
        echo "  [+] Certificate already exists. Skipping generation."
    else
        echo "  [!] Certificate not found. Generating a new one..."
        # Generate a private key
        openssl genrsa -out "${CERT_DIR}/squid-ca.key" 4096
        # Generate a self-signed root CA certificate
        openssl req -x509 -new -nodes -key "${CERT_DIR}/squid-ca.key" \
            -sha256 -days 3650 -out "${CERT_DIR}/squid-ca.pem" \
            -subj "/C=US/ST=California/L=City/O=Home LAN/OU=Proxy/CN=squid.local"
        echo "  [+] New certificate generated."
    fi

    echo "  [*] Converting certificate to DER format for client compatibility..."
    openssl x509 -in "${CERT_DIR}/squid-ca.pem" -outform DER -out "${CERT_DIR}/squid-ca.crt"

    echo "  [*] Syncing certificates to QNAP..."
    ssh "${QNAP_SERVER}" "mkdir -p ${SQUID_CERT_DIR_REMOTE} ${CERT_DOWNLOAD_DIR}"
    scp "${CERT_DIR}/squid-ca.pem" "${CERT_DIR}/squid-ca.key" "${QNAP_SERVER}:${SQUID_CERT_DIR_REMOTE}/"
    scp "${CERT_DIR}/squid-ca.crt" "${QNAP_SERVER}:${CERT_DOWNLOAD_DIR}/"
    echo "  [+] Certificate available for download at http://${QNAP_IP}/certs/squid-ca.crt"
}

deploy_proxy() {
    echo "-----------------------------------------------"
    echo ">>> Deploying Squid Proxy to QNAP..."

    local DEPLOY_SCRIPT="${SQUID_DIR}/docker/deploy-squid-docker.sh"

    if [ ! -f "${DEPLOY_SCRIPT}" ]; then
        echo "  [!] ERROR: Deploy script not found: ${DEPLOY_SCRIPT}"
        exit 1
    fi

    echo "  [*] Building and running squid-proxy container on QNAP..."
    "${DEPLOY_SCRIPT}" remove create squid-proxy

    echo "  [+] Squid Proxy deployed!"
}

dump_config() {
    echo "-----------------------------------------------"
    echo ">>> Dumping parsed Squid Configuration from QNAP proxy container..."

    local out rc
    out=$(ssh -T "${QNAP_SERVER}" "${DOCKER} exec ${SQUID_INSTANCE_NAME} squid -k parse 2>&1")
    rc=$?
    echo "${out}"

    # Report what actually happened. This used to print '[+] Config dumped.'
    # unconditionally, so a stopped container or a config full of FATAL errors
    # still looked like a success to both a human and the test suite.
    if [ ${rc} -ne 0 ] || echo "${out}" | grep -qiE "is not running|No such container|Cannot connect to the Docker daemon"; then
        echo "  [!] ERROR: could not run 'squid -k parse' in container '${SQUID_INSTANCE_NAME}'."
        return 1
    fi
    if echo "${out}" | grep -qiE "FATAL|Bungled"; then
        echo "  [!] ERROR: configuration contains FATAL errors (see above)."
        return 1
    fi
    if echo "${out}" | grep -qi "empty ACL"; then
        echo "  [!] WARNING: empty ACL(s) detected — those rules can never match."
    fi
    echo "  [+] Config parsed cleanly."
    return 0
}

analyze_logs() {
    echo "-----------------------------------------------"
    echo ">>> Analyzing Squid Access Logs with GoAccess..."

    # Check that goaccess is available locally
    if ! command -v goaccess &> /dev/null; then
        echo "  [!] ERROR: 'goaccess' is not installed. Install it with: sudo apt install goaccess"
        exit 1
    fi

    local LOCAL_LOG_DIR="${SQUID_DIR}/logs"
    local LOCAL_LOG="${LOCAL_LOG_DIR}/access.log"
    local REPORT="${LOCAL_LOG_DIR}/squid-report.html"
    local REMOTE_LOG="/var/log/squid/access.log"

    mkdir -p "${LOCAL_LOG_DIR}"

    echo "  [*] Copying access log from container '${SQUID_INSTANCE_NAME}' on QNAP..."
    # Use 'docker cp' via SSH and pipe the tar stream locally to avoid tmp files on QNAP
    ssh -T "${QNAP_SERVER}" "${DOCKER} cp ${SQUID_INSTANCE_NAME}:${REMOTE_LOG} -" \
        | tar -xO > "${LOCAL_LOG}"

    if [ ! -s "${LOCAL_LOG}" ]; then
        echo "  [!] ERROR: Log file is empty or could not be retrieved."
        exit 1
    fi

    local TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    local SNAPSHOT_LOG="${LOCAL_LOG_DIR}/access_${TIMESTAMP}.log"
    cp "${LOCAL_LOG}" "${SNAPSHOT_LOG}"
    echo "  [+] Saved local log snapshot: ${SNAPSHOT_LOG}"

    echo "  [*] Running GoAccess to generate HTML report..."
    awk '{
        ts = $1; sub(/\.[0-9]+/, "", ts);
        elapsed = $2;
        ip = $3;
        code = $4;
        size = $5;
        method = $6;
        url = $7;
        domain = url;
        sub(/^https?:\/\//, "", domain);
        sub(/\/.*$/, "", domain);
        sub(/:.*$/, "", domain);
        if (domain == "") domain = "-";
        print domain, ts, elapsed, ip, code, size, method, url
    }' "${LOCAL_LOG}" \
        | goaccess - \
            --log-format='%v %x %L %h %^/%s %b %m %U' \
            --date-format='%s' \
            --time-format='%s' \
            --output="${REPORT}" \
            --ignore-crawlers \
            --real-os

    local HOST_REPORT="${LOCAL_LOG_DIR}/host-domains-report.html"
    local HOSTS_CONF="${SQUID_DIR}/router/proxy-hosts.conf"

    echo "  [*] Running Standalone Log Analyzer (analyze-squid-logs.py)..."
    python3 "${SQUID_DIR}/logs/analyze-squid-logs.py" \
        --log "${LOCAL_LOG}" \
        --hosts-conf "${HOSTS_CONF}" \
        --out-host-report "${HOST_REPORT}" \
        --out-goaccess-report "${REPORT}"

    echo "  [+] Reports generated:"
    echo "      - Per-Host Activity: ${HOST_REPORT}"
    echo "      - GoAccess Dashboard: ${REPORT}"

    # Open the report in a web browser if a graphical environment is available
    if [ -f "${REPORT}" ] && [ -n "${DISPLAY}" ]; then
        local browser_cmd=""
        if [ -n "${BROWSER}" ] && command -v "${BROWSER}" &> /dev/null; then
            browser_cmd="${BROWSER}"
        elif command -v google-chrome &> /dev/null; then
            browser_cmd="google-chrome"
        elif command -v firefox &> /dev/null; then
            browser_cmd="firefox"
        elif command -v chromium &> /dev/null; then
            browser_cmd="chromium"
        elif command -v x-www-browser &> /dev/null; then
            browser_cmd="x-www-browser"
        elif command -v xdg-open &> /dev/null; then
            browser_cmd="xdg-open"
        fi

        if [ -n "${browser_cmd}" ]; then
            echo "  [*] Opening report in browser (${browser_cmd})..."
            "${browser_cmd}" "${REPORT}" &> /dev/null &
        fi
    fi
}

cat_logs() {
    echo "-----------------------------------------------"
    echo ">>> Displaying Squid Access Logs..."

    local LOCAL_LOG_DIR="${SQUID_DIR}/logs"
    local LOCAL_LOG="${LOCAL_LOG_DIR}/access.log"
    local REMOTE_LOG="/var/log/squid/access.log"

    mkdir -p "${LOCAL_LOG_DIR}"

    echo "  [*] Copying access log from container '${SQUID_INSTANCE_NAME}' on QNAP..."
    # PIPESTATUS is checked so a failed 'docker cp' is not masked by tar succeeding
    # on an empty stream, which would leave a 0-byte log looking like a clean run.
    ssh -T "${QNAP_SERVER}" "${DOCKER} cp ${SQUID_INSTANCE_NAME}:${REMOTE_LOG} -" \
        | tar -xO > "${LOCAL_LOG}"
    local cp_rc=${PIPESTATUS[0]}

    if [ ${cp_rc} -ne 0 ] || [ ! -f "${LOCAL_LOG}" ]; then
        echo "  [!] ERROR: Log file could not be retrieved from container (docker cp rc=${cp_rc})."
        return 1
    fi

    local TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    local SNAPSHOT_LOG="${LOCAL_LOG_DIR}/access_${TIMESTAMP}.log"
    cp "${LOCAL_LOG}" "${SNAPSHOT_LOG}"
    echo "  [+] Saved local log snapshot: ${SNAPSHOT_LOG}"
    echo "-----------------------------------------------"
    if [ ! -s "${LOCAL_LOG}" ]; then
        echo "  [i] Access log is currently empty (0 bytes)."
    else
        cat "${LOCAL_LOG}"
    fi
}

deploy_router_proxy() {
    echo "-----------------------------------------------"
    echo ">>> Deploying Transparent Proxy Rules to Router..."

    if [ ! -f "${PROXY_HOSTS_CONF}" ]; then
        echo "  [!] ERROR: Host config not found: ${PROXY_HOSTS_CONF}"
        exit 1
    fi

    local PROXY_SCRIPT="/jffs/scripts/squid-proxy-rules.sh"
    local TEMP_SCRIPT="/tmp/squid-proxy-rules.sh"
    local MARKER="MANAGED-BY-SQUID-MGMT"

    # ---- Step 1: Render the sidecar script from the checked-in template ----
    #
    # The rule logic lives in router/squid-proxy-rules.sh, NOT inline here. It used
    # to be duplicated as a long printf block, which drifted out of sync with the
    # checked-in copy: the file in git described a DNAT + MASQUERADE scheme while
    # this function generated a policy-routing one. Deploying the wrong variant
    # silently breaks every per-device src ACL, so there is now exactly one copy.
    local RULES_TEMPLATE="${ROUTER_DIR}/squid-proxy-rules.sh"

    if [ ! -f "${RULES_TEMPLATE}" ]; then
        echo "  [!] ERROR: Rules template not found: ${RULES_TEMPLATE}"
        exit 1
    fi
    if ! grep -q "^# --- Per-host rules ---" "${RULES_TEMPLATE}"; then
        echo "  [!] ERROR: ${RULES_TEMPLATE} is missing the '# --- Per-host rules ---' marker."
        exit 1
    fi

    # Copy the template, pinning SQUID_IP to this script's configured value.
    sed "s|^SQUID_IP=.*|SQUID_IP=\"${SQUID_PROXY_IP}\"|" "${RULES_TEMPLATE}" > "${TEMP_SCRIPT}"

    # ---- Step 2: Append one add_host call per intercepted host ----
    local host_count=0
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        line="${line%%#*}"
        local host_ip host_name host_options quic_mode vpn_mode option
        read -r host_ip host_name host_options <<< "$line"
        [ -z "$host_ip" ] && continue

        quic_mode=""
        vpn_mode=""
        for option in ${host_options}; do
            case "${option}" in
                no_quic) quic_mode="no_quic" ;;
                no_vpn) vpn_mode="no_vpn" ;;
                *)
                    echo "  [!] ERROR: Unknown option '${option}' for ${host_name} (${host_ip}) in ${PROXY_HOSTS_CONF}."
                    rm -f "${TEMP_SCRIPT}"
                    exit 1
                    ;;
            esac
        done

        echo "add_host \"${host_ip}\" \"${quic_mode}\" \"${vpn_mode}\"   # ${host_name}" >> "${TEMP_SCRIPT}"
        host_count=$((host_count + 1))
    done < "${PROXY_HOSTS_CONF}"

    if [ "${host_count}" -eq 0 ]; then
        echo "  [!] WARNING: ${PROXY_HOSTS_CONF} lists no hosts — deploying rules that intercept nothing."
    else
        echo "  [*] Rendered sidecar with ${host_count} intercepted host(s)."
    fi

    chmod +x "${TEMP_SCRIPT}"

    # Sanity-check the rendered script before it ever reaches the router.
    if ! sh -n "${TEMP_SCRIPT}"; then
        echo "  [!] ERROR: Rendered sidecar script has a syntax error. Aborting deploy."
        rm -f "${TEMP_SCRIPT}"
        exit 1
    fi

    # ---- Step 3: Upload the sidecar script to the router ----
    echo "  [*] Uploading ${PROXY_SCRIPT} to router (${ROUTER_IP})..."
    scp ${ROUTER_SCP_OPTS} "${TEMP_SCRIPT}" "${ROUTER_SERVER}:${PROXY_SCRIPT}"
    rm -f "${TEMP_SCRIPT}"

    # ---- Step 4: Safely update firewall-start to call our sidecar ----
    # firewall-start is NEVER overwritten. We only append a call if not present.
    echo "  [*] Checking firewall-start on router..."
    ssh ${ROUTER_SSH_OPTS} -T "${ROUTER_SERVER}" \
        "chmod +x \"${PROXY_SCRIPT}\";
         FW=\"${ROUTER_FIREWALL_SCRIPT}\";
         SIDECAR=\"${PROXY_SCRIPT}\";
         if [ ! -f \"\$FW\" ]; then
             printf '#!/bin/sh\nsh %s\n' \"\$SIDECAR\" > \"\$FW\";
             chmod +x \"\$FW\";
             echo '  [i] Created new firewall-start.';
         elif grep -q \"\$SIDECAR\" \"\$FW\"; then
             echo '  [i] firewall-start already calls our sidecar — no change needed.';
         else
             cp \"\$FW\" \"\$FW.pre-squid.bak\";
             printf '\n# Added by squid-mgmt.sh — transparent proxy rules\nsh %s\n' \"\$SIDECAR\" >> \"\$FW\";
             echo '  [!] Existing firewall-start preserved (backup: .pre-squid.bak).';
             echo '  [i] Proxy rules appended at the end.';
         fi;
         sh \"\$SIDECAR\""

    echo ""
    echo "  [+] Proxy rules deployed and active immediately."
    echo "  [i] Sidecar: ${PROXY_SCRIPT} (called from firewall-start on every reboot)."
    echo ""
    echo "  Intercepted hosts:"
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        local host_ip host_name
        read -r host_ip host_name <<< "$line"
        [ -z "$host_ip" ] && continue
        echo "    ${host_ip}  (${host_name})  -> ${SQUID_PROXY_IP}:${SQUID_HTTP_PORT}/${SQUID_HTTPS_PORT}"
    done < "${PROXY_HOSTS_CONF}"
}

deploy_linux_cert() {
    echo "-----------------------------------------------"
    echo ">>> Installing Squid CA Certificate on Linux Hosts..."

    local CERT_PEM="${CERT_DIR}/squid-ca.pem"
    local REMOTE_CERT_NAME="squid-proxy-ca.crt"
    local REMOTE_INSTALL_SCRIPT="/tmp/squid-install-cert.sh"
    local LOCAL_INSTALL_SCRIPT="/tmp/squid-install-cert.sh"

    if [ ! -f "${CERT_PEM}" ]; then
        echo "  [!] ERROR: CA cert not found at ${CERT_PEM}"
        echo "  [i] Run: $0 cert   to generate it first."
        exit 1
    fi

    if [ ! -f "${PROXY_HOSTS_CONF}" ]; then
        echo "  [!] ERROR: Host config not found: ${PROXY_HOSTS_CONF}"
        exit 1
    fi

    # Build the install script once locally; it will be scp'd to each host.
    # It runs as root (via 'sudo sh'), so no sudo calls needed inside it.
    cat > "${LOCAL_INSTALL_SCRIPT}" << 'INSTALL_SCRIPT'
#!/bin/sh
# Must be run as root (called via: sudo sh /tmp/squid-install-cert.sh)
set -e
CERT_SRC="/tmp/squid-proxy-ca.crt"
REMOTE_CERT_NAME="squid-proxy-ca.crt"
PROXY_URL="http://192.168.1.90:3128"

if command -v update-ca-certificates > /dev/null 2>&1; then
    # Debian / Ubuntu
    cp "$CERT_SRC" "/usr/local/share/ca-certificates/$REMOTE_CERT_NAME"
    update-ca-certificates
    echo "  [+] Installed via update-ca-certificates (Debian/Ubuntu)."
elif command -v update-ca-trust > /dev/null 2>&1; then
    # RHEL / CentOS / Fedora
    cp "$CERT_SRC" "/etc/pki/ca-trust/source/anchors/$REMOTE_CERT_NAME"
    update-ca-trust extract
    echo "  [+] Installed via update-ca-trust (RHEL/Fedora)."
else
    echo "  [!] ERROR: No known CA trust tool found (tried update-ca-certificates, update-ca-trust)."
    rm -f "$CERT_SRC"
    exit 1
fi

# Also update Chrome/NSS certificate databases if present
if ! command -v certutil >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq libnss3-tools >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y nss-tools >/dev/null 2>&1 || true
    fi
fi

if command -v certutil >/dev/null 2>&1; then
    for user_home in /root /home/*; do
        if [ -d "$user_home/.pki/nssdb" ]; then
            certutil -d "sql:$user_home/.pki/nssdb" -A -t "C,," -n "squid.local" -i "$CERT_SRC" 2>/dev/null || true
            user_owner=$(stat -c '%U:%G' "$user_home" 2>/dev/null || echo "")
            [ -n "$user_owner" ] && chown -R "$user_owner" "$user_home/.pki/nssdb" 2>/dev/null || true
        fi
    done
    echo "  [+] Imported Root CA into Chrome/NSS certificate databases."
fi

cat > /etc/profile.d/squid-proxy.sh << PROXY_EOF
export http_proxy="${PROXY_URL}"
export https_proxy="${PROXY_URL}"
export HTTP_PROXY="${PROXY_URL}"
export HTTPS_PROXY="${PROXY_URL}"
export no_proxy="localhost,127.0.0.1,192.168.0.0/16,local,.local"
export NO_PROXY="localhost,127.0.0.1,192.168.0.0/16,local,.local"
PROXY_EOF
chmod 755 /etc/profile.d/squid-proxy.sh
echo "  [+] System-wide proxy profile installed at /etc/profile.d/squid-proxy.sh."

rm -f "$CERT_SRC" "/tmp/squid-install-cert.sh"
INSTALL_SCRIPT

    local any_host=false

    # Collect sudo password once locally — read -s suppresses echo so it's never visible.
    # The password is piped to 'sudo -S' on the remote (reads from stdin, no PTY needed).
    local SUDO_PASS
    read -r -s -p "  [?] sudo password for remote hosts (input hidden): " SUDO_PASS
    echo ""  # newline after silent input

    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        local host_ip host_name
        read -r host_ip host_name <<< "$line"
        [ -z "$host_ip" ] && continue
        any_host=true

        echo "-----------------------------------------------"
        echo "  [*] Deploying cert to ${host_name} (${host_ip})..."

        # Upload cert and install script
        scp -q "${CERT_PEM}" "${host_ip}:/tmp/${REMOTE_CERT_NAME}"
        if [ $? -ne 0 ]; then
            echo "  [!] ERROR: scp of cert failed for ${host_name}. Skipping."
            continue
        fi
        scp -q "${LOCAL_INSTALL_SCRIPT}" "${host_ip}:${REMOTE_INSTALL_SCRIPT}"
        if [ $? -ne 0 ]; then
            echo "  [!] ERROR: scp of install script failed for ${host_name}. Skipping."
            continue
        fi

        # Pipe the password to sudo -S (reads from stdin) — no PTY, no echo, no hang.
        echo "  [*] Running install script on ${host_name} (using sudo -S)..."
        printf '%s\n' "${SUDO_PASS}" | ssh "${host_ip}" "sudo -S sh ${REMOTE_INSTALL_SCRIPT}"

        if [ $? -eq 0 ]; then
            echo "  [+] ${host_name} (${host_ip}): cert installed successfully."
            echo "  [*] Verifying HTTPS trust on ${host_name}..."
            ssh "${host_ip}" ". /etc/profile.d/squid-proxy.sh && curl -s --max-time 5 https://google.com > /dev/null \
                && echo '  [+] HTTPS via Squid proxy verified & trusted successfully.' \
                || echo '  [i] Setup complete. Verify manually: curl -v https://google.com'"
        else
            echo "  [!] ${host_name} (${host_ip}): installation encountered errors (see above)."
        fi
    done < "${PROXY_HOSTS_CONF}"

    rm -f "${LOCAL_INSTALL_SCRIPT}"

    if [ "$any_host" = false ]; then
        echo "  [!] No hosts found in ${PROXY_HOSTS_CONF}."
    fi
}

deploy_webui() {
    echo "-----------------------------------------------"
    echo ">>> Deploying Squid Web UI to QNAP..."

    local DEPLOY_SCRIPT="${SQUID_DIR}/docker/deploy-squid-docker.sh"

    if [ ! -f "${DEPLOY_SCRIPT}" ]; then
        echo "  [!] ERROR: Deploy script not found: ${DEPLOY_SCRIPT}"
        exit 1
    fi

    echo "  [*] Building and running squid-webui container on QNAP..."
    "${DEPLOY_SCRIPT}" create squid-webui

    echo "  [+] Squid Web UI deployed!"
    echo "  [i] Access Web UI at: http://192.168.1.91:3131 (or http://${QNAP_IP}:3131)"
}

# --- 3. EXECUTION ---

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [cert|dump-config|logs|catlogs|proxy-deploy|webui-deploy|router-deploy|linux-deploy|all]"
    exit 1
fi

while [ $# -gt 0 ] ; do
    case "$1" in
        # Mostly not needed, only when the cert has problems.
        cert)           generate_cert ;;

        # Command line option to dump the config files to the local machine
        dump-config)    dump_config ;;
        logs)           analyze_logs ;;
        catlogs)        cat_logs ;;

        # Command line option to deploy the system to qnap, router, and linux client.
        proxy-deploy)   deploy_proxy ;;
        webui-deploy)   deploy_webui ;;
        router-deploy)  deploy_router_proxy ;;
        linux-deploy)   deploy_linux_cert ;;

        all)
            deploy_proxy
            deploy_webui
            deploy_router_proxy
            ;;
        *)
            echo "Unknown command: $1"
            echo "Usage: $0 [cert|dump-config|logs|catlogs|proxy-deploy|webui-deploy|router-deploy|linux-deploy|all]"
            ;;
    esac
    shift
done

cleanup_pycache() {
    find "${SQUID_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "${SQUID_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
}

cleanup_pycache

echo "-----------------------------------------------"
echo "Operation Complete."
