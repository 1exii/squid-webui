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
SQUID_BASE_DIR="/share/CACHEDEV1_DATA/Container/container-station-data/application/squid"
SQUID_CERT_DIR_REMOTE="${SQUID_BASE_DIR}/certs"
SQUID_BLOCKLIST_DIR_REMOTE="${SQUID_BASE_DIR}/block-lists"
SQUID_CONF_REMOTE="${SQUID_BASE_DIR}/squid.conf"

# Path for clients to download the certificate
CERT_DOWNLOAD_DIR="/share/CACHEDEV1_DATA/Web/certs"

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

sync_blocklists() {
    echo "-----------------------------------------------"
    echo ">>> Syncing Blocklists..."
    
    local combined_list_path="/tmp/squid_blocklist.txt"
    
    # Combine all .txt files in the blocklist directory
    if [ -n "$(find "${BLOCKLIST_DIR}" -maxdepth 1 -name '*.txt' -print -quit)" ]; then
        echo "  [+] Combining blocklist files..."
        # Strip comments, remove empty lines, and sort uniquely
        sed 's/#.*//' "${BLOCKLIST_DIR}"/*.txt | grep -v '^[[:space:]]*$' | sort -u > "${combined_list_path}"
        
        echo "  [*] Syncing combined blocklist to QNAP..."
        ssh "${QNAP_SERVER}" "mkdir -p ${SQUID_BLOCKLIST_DIR_REMOTE}"
        scp "${combined_list_path}" "${QNAP_SERVER}:${SQUID_BLOCKLIST_DIR_REMOTE}/domains.txt"
        rm "${combined_list_path}"
        echo "  [+] Blocklist synced."
    else
        echo "  [!] No blocklist files (*.txt) found in ${BLOCKLIST_DIR}. Skipping sync."
    fi
}

apply_config() {
    echo "-----------------------------------------------"
    echo ">>> Applying Squid Configuration..."

    if [ ! -f "${SQUID_CONF_TEMPLATE}" ]; then
        echo "  [!] ERROR: Squid config template not found at ${SQUID_CONF_TEMPLATE}"
        exit 1
    fi

    echo "  [*] Syncing squid.conf to QNAP..."
    scp "${SQUID_CONF_TEMPLATE}" "${QNAP_SERVER}:${SQUID_CONF_REMOTE}"
    
    echo "  [*] Restarting Squid container to apply changes..."
    ssh -T "${QNAP_SERVER}" "${DOCKER} restart ${SQUID_INSTANCE_NAME}"
    
    echo "  [+] Squid configuration applied and service restarted."
}

# --- 3. EXECUTION ---

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [cert|blocklist|config|all]"
    exit 1
fi

while [ $# -gt 0 ] ; do
    case "$1" in
        cert)       generate_cert ;;
        blocklist)  sync_blocklists ;;
        config)     apply_config ;;
        all)
            generate_cert
            sync_blocklists
            apply_config
            ;;
        *)
            echo "Unknown command: $1"
            echo "Usage: $0 [cert|blocklist|config|all]"
            ;;
    esac
    shift
done

echo "-----------------------------------------------"
echo "Operation Complete."
