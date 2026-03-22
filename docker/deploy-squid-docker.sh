#!/bin/bash

# --- 1. CONFIGURATION TABLE ---
DOCKER_INSTANCES=(
    "192.168.1.90 squid-proxy squid-ssl:latest"
    "192.168.1.91 squid-webui squid-webui:latest"
)

# --- 2. GLOBAL SETTINGS ---
TIMEZONE="America/Los_Angeles"

GITDIR="${HOME}/GitHub"
HOMENET_DIR="${GITDIR}/personal/home-network"
SQUID_DIR="${HOMENET_DIR}/squid"
LOCAL_CONF_TEMPLATE="${SQUID_DIR}/configs/squid.conf.template"
LOCAL_CERT_DIR="${SQUID_DIR}/certs"
DOCKERFILE_DIR="${SQUID_DIR}/docker"  # contains Dockerfile + docker-entrypoint.sh

QNAP_IP="192.168.1.2"
QNAP_USER="admin"
QNAP_SERVER="${QNAP_USER}@${QNAP_IP}"

BINDIR="/share/CACHEDEV1_DATA/.qpkg/container-station/bin"
DOCKER="${BINDIR}/docker"
DOCKER_NET="qnet-static-eth0-8623fd"

# --- 3. HELPER FUNCTIONS ---

# This function filters the main array and validates matches
get_filtered_instances() {
    local filtered=()
    for target in "${TARGET_NAMES[@]}"; do
        local found=false
        for entry in "${DOCKER_INSTANCES[@]}"; do
            read -r IP NAME IMAGE <<< "$entry"
            if [[ "$NAME" == "$target" ]]; then
                filtered+=("$entry")
                found=true
            fi
        done
        if [ "$found" = false ]; then
            echo "WARNING: No configuration found for target '$target'. Skipping." >&2
        fi
    done

    # Return unique entries
    printf "%s\n" "${filtered[@]}" | sort -u
}

function remove_instances() {
    # Use mapfile to read the function output line-by-line into an array
    mapfile -t active_list < <(get_filtered_instances)

    [ ${#active_list[@]} -eq 0 ] && return

    echo ">>> Removing targeted Squid instances..."
    for entry in "${active_list[@]}"; do
        read -r IP NAME IMAGE <<< "$entry"
        [ -z "$NAME" ] && continue # Safety check

        echo "Stopping and removing $NAME..."
        ssh -T "$QNAP_SERVER" "$DOCKER stop $NAME > /dev/null 2>&1; $DOCKER rm $NAME > /dev/null 2>&1"
    done
}

function create_squid() {
    local IP=$1
    local NAME=$2
    local IMAGE=$3

    echo "Launching $NAME ($IP)..."
    REMOTE_BASE="/share/Container/$NAME"

    REMOTE_BUILD_DIR="/tmp/squid-build"
    # container-station's docker wrapper needs a homes dir for the SSH user;
    # pre-create it to avoid the 'permission denied' mkdir error during docker build.
    HOMES_DIR="/share/CACHEDEV1_DATA/.qpkg/container-station/homes/${QNAP_USER}"

    echo ">>> Building $IMAGE on QNAP from local Dockerfile..."
    ssh "$QNAP_SERVER" "rm -rf ${REMOTE_BUILD_DIR} && mkdir -p ${HOMES_DIR} ${REMOTE_BUILD_DIR}"
    scp "${DOCKERFILE_DIR}/Dockerfile" \
        "${DOCKERFILE_DIR}/docker-entrypoint.sh" \
        "$QNAP_SERVER:${REMOTE_BUILD_DIR}/"
    ssh -T "$QNAP_SERVER" \
        "cd ${REMOTE_BUILD_DIR} && $DOCKER build -t ${IMAGE} . && rm -rf ${REMOTE_BUILD_DIR}"
    if [ $? -ne 0 ]; then
        echo "ERROR: docker build failed on QNAP."
        exit 1
    fi

    # Sync config, errors, and certs before starting the container
    echo "  [*] Syncing squid.conf to QNAP..."
    ssh "$QNAP_SERVER" "mkdir -p ${REMOTE_BASE}/configs ${REMOTE_BASE}/configs/errors ${REMOTE_BASE}/certs ${REMOTE_BASE}/block-lists ${REMOTE_BASE}/router ${REMOTE_BASE}/cache ${REMOTE_BASE}/ssl_db && touch ${REMOTE_BASE}/configs/rules.acl"
    scp "$LOCAL_CONF_TEMPLATE" "$QNAP_SERVER:${REMOTE_BASE}/configs/squid.conf"
    if [ -d "${SQUID_DIR}/configs/errors" ]; then
        scp -r "${SQUID_DIR}/configs/errors/"* "$QNAP_SERVER:${REMOTE_BASE}/configs/errors/" 2>/dev/null || true
    fi

    if [ -f "${LOCAL_CERT_DIR}/squid-ca.pem" ] && [ -f "${LOCAL_CERT_DIR}/squid-ca.key" ]; then
        echo "  [*] Syncing SSL certs to QNAP..."
        scp "${LOCAL_CERT_DIR}/squid-ca.pem" "${LOCAL_CERT_DIR}/squid-ca.key" "$QNAP_SERVER:${REMOTE_BASE}/certs/"
    else
        echo "  [!] WARNING: SSL certs not found in ${LOCAL_CERT_DIR}. Run squid-mgmt.sh cert first."
    fi

    if [ -d "${SQUID_DIR}/block-lists" ]; then
        echo "  [*] Syncing blocklists to QNAP..."
        ssh "$QNAP_SERVER" "rm -f ${REMOTE_BASE}/block-lists/*.txt"
        scp "${SQUID_DIR}/block-lists/"*.txt "$QNAP_SERVER:${REMOTE_BASE}/block-lists/" 2>/dev/null || true
    fi

    ssh -T "$QNAP_SERVER" << EOF
        $DOCKER run -d \
            --name "$NAME" --hostname "$NAME" \
            --net "$DOCKER_NET" --ip "$IP" \
            --cap-add=NET_ADMIN \
            --restart=unless-stopped \
            -e TZ="$TIMEZONE" \
            -v "${REMOTE_BASE}/configs/squid.conf:/etc/squid/squid.conf:ro" \
            -v "${REMOTE_BASE}/configs/rules.acl:/etc/squid/configs/rules.acl:ro" \
            -v "${REMOTE_BASE}/configs:/etc/squid/configs" \
            -v "${REMOTE_BASE}/certs:/etc/squid/certs:ro" \
            -v "${REMOTE_BASE}/block-lists:/etc/squid/block-lists:ro" \
            -v "${REMOTE_BASE}/cache:/var/cache/squid" \
            -v "${REMOTE_BASE}/ssl_db:/var/lib/squid/ssl_db" \
            $IMAGE > /dev/null
EOF
}

function create_webui() {
    local IP=$1
    local NAME=$2
    local IMAGE=$3

    echo "Launching $NAME ($IP)..."
    REMOTE_SQUID_BASE="/share/Container/squid-proxy"
    REMOTE_BUILD_DIR="/tmp/squid-webui-build"
    HOMES_DIR="/share/CACHEDEV1_DATA/.qpkg/container-station/homes/${QNAP_USER}"

    echo ">>> Syncing webui source and building $IMAGE on QNAP..."
    ssh "$QNAP_SERVER" "rm -rf ${REMOTE_BUILD_DIR} && mkdir -p ${HOMES_DIR} ${REMOTE_BUILD_DIR}"
    scp -r "${SQUID_DIR}/webui/"* "$QNAP_SERVER:${REMOTE_BUILD_DIR}/"
    ssh -T "$QNAP_SERVER" \
        "cd ${REMOTE_BUILD_DIR} && $DOCKER build -t ${IMAGE} . && rm -rf ${REMOTE_BUILD_DIR}"
    if [ $? -ne 0 ]; then
        echo "ERROR: docker build for webui failed on QNAP."
        exit 1
    fi

    # Sync proxy-hosts.conf and devices.list to squid-proxy directory if present
    ssh "$QNAP_SERVER" "mkdir -p ${REMOTE_SQUID_BASE}/configs ${REMOTE_SQUID_BASE}/block-lists ${REMOTE_SQUID_BASE}/router && touch ${REMOTE_SQUID_BASE}/configs/rules.acl"
    
    ssh "$QNAP_SERVER" "rm -f ${REMOTE_SQUID_BASE}/router/proxy-hosts.conf ${REMOTE_SQUID_BASE}/configs/devices.list"
    if [ -f "${SQUID_DIR}/router/proxy-hosts.conf" ]; then
        scp "${SQUID_DIR}/router/proxy-hosts.conf" "$QNAP_SERVER:${REMOTE_SQUID_BASE}/router/"
    fi
    if [ -f "${SQUID_DIR}/webui/devices.list" ]; then
        scp "${SQUID_DIR}/webui/devices.list" "$QNAP_SERVER:${REMOTE_SQUID_BASE}/configs/devices.list"
    fi
    if [ -d "${SQUID_DIR}/block-lists" ]; then
        ssh "$QNAP_SERVER" "rm -f ${REMOTE_SQUID_BASE}/block-lists/*.txt"
        scp "${SQUID_DIR}/block-lists/"*.txt "$QNAP_SERVER:${REMOTE_SQUID_BASE}/block-lists/" 2>/dev/null || true
    fi

    # Stop and remove existing container if running
    ssh -T "$QNAP_SERVER" "$DOCKER stop $NAME > /dev/null 2>&1; $DOCKER rm $NAME > /dev/null 2>&1"

    ssh -T "$QNAP_SERVER" << EOF
        $DOCKER run -d \
            --name "$NAME" --hostname "$NAME" \
            --net "$DOCKER_NET" --ip "$IP" \
            --restart=unless-stopped \
            -p 3131:3131 \
            -e TZ="$TIMEZONE" \
            -e RUNNING_ON_NAS="true" \
            -v "${REMOTE_SQUID_BASE}/configs:/etc/squid/configs" \
            -v "${REMOTE_SQUID_BASE}/certs:/etc/squid/certs:ro" \
            -v "${REMOTE_SQUID_BASE}/block-lists:/etc/squid/block-lists" \
            -v "${REMOTE_SQUID_BASE}/router:/etc/squid/router" \
            -v "/etc/config/shadow:/host_etc/config/shadow:ro" \
            -v "/etc/shadow:/host_etc/shadow:ro" \
            -v "/var/run/docker.sock:/var/run/docker.sock" \
            $IMAGE > /dev/null
EOF
}

function create_instances() {
    mapfile -t active_list < <(get_filtered_instances)

    [ ${#active_list[@]} -eq 0 ] && return

    if [ ! -f "$LOCAL_CONF_TEMPLATE" ]; then
        echo "ERROR: Squid config template missing at $LOCAL_CONF_TEMPLATE"
        exit 1
    fi

    for entry in "${active_list[@]}"; do
        read -r IP NAME IMAGE <<< "$entry"

        if [ "$NAME" == "squid-proxy" ]; then
            create_squid "$IP" "$NAME" "$IMAGE"
        elif [ "$NAME" == "squid-webui" ]; then
            create_webui "$IP" "$NAME" "$IMAGE"
        else
            echo "ERROR: Unknown container name '$NAME'"
        fi
    done

    echo ">>> Waiting 15s for services to start..."
    sleep 15
}

# --- 4. EXECUTION LOGIC ---
CREATE=FALSE
REMOVE=FALSE
TARGET_NAMES=()

# Parse arguments
while [ $# -gt 0 ] ; do
    case "$1" in
        create) CREATE=TRUE ;;
        remove) REMOVE=TRUE ;;
        *)      TARGET_NAMES+=("$1") ;;
    esac
    shift
done

# Check 1: Must have an action
if [[ "$CREATE" == "FALSE" && "$REMOVE" == "FALSE" ]]; then
    echo "ERROR: You must specify 'create', 'remove', or both."
    exit 1
fi

# Check 2: Must have at least one target name
if [ ${#TARGET_NAMES[@]} -eq 0 ]; then
    echo "-------------------------------------------------------"
    echo "ERROR: No target containers specified."
    echo "Usage: $0 {create|remove} <target1> <target2> ..."
    echo "-------------------------------------------------------"
    echo "Available Targets:"
    for entry in "${DOCKER_INSTANCES[@]}"; do
        read -r IP NAME IMAGE <<< "$entry"
        echo "   - $NAME"
    done
    exit 1
fi

if [[ "$REMOVE" == "TRUE" ]]; then
    remove_instances
fi

if [[ "$CREATE" == "TRUE" ]]; then
    create_instances
fi

find "${SQUID_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${SQUID_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true

echo "DONE."
