#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQUID_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=../lib/load-deployment.sh
source "${SQUID_DIR}/lib/load-deployment.sh"
set -u

# --- 1. CONFIGURATION TABLE ---
DOCKER_INSTANCES=(
    "${SQUID_PROXY_IP} ${SQUID_CONTAINER_NAME} ${SQUID_IMAGE}"
    "${WEBUI_IP} ${WEBUI_CONTAINER_NAME} ${WEBUI_IMAGE}"
)

# --- 2. GLOBAL SETTINGS ---
LOCAL_CONF_TEMPLATE="${SQUID_DIR}/configs/squid.conf.template"
LOCAL_CERT_DIR="${CERT_DIR}"
DOCKERFILE_DIR="${SQUID_DIR}/docker"  # contains Dockerfile + docker-entrypoint.sh

QNAP_SERVER="${QNAP_USER}@${QNAP_IP}"
DOCKER="${QNAP_DOCKER}"
DOCKER_NET="${QNAP_DOCKER_NETWORK}"
# The proxy is required after every unattended NAS boot. `always` still honors
# a manual stop until Docker restarts, then brings the proxy back automatically.
SQUID_RESTART_POLICY="always"
WEBUI_RESTART_POLICY="unless-stopped"

# --- 3. HELPER FUNCTIONS ---

# This function filters the main array and validates matches
get_filtered_instances() {
    local filtered=()
    for target in "${TARGET_NAMES[@]}"; do
        # Normalize target aliases
        if [[ "$target" == "webui" || "$target" == "squid-webui" ]]; then
            target="$WEBUI_CONTAINER_NAME"
        elif [[ "$target" == "squid" || "$target" == "proxy" || "$target" == "squid-proxy" ]]; then
            target="$SQUID_CONTAINER_NAME"
        fi

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

function sync_squid_config() {
    local NAME=$1
    local REMOTE_BASE="${QNAP_CONTAINER_ROOT}/$NAME"

    echo "  [*] Syncing squid.conf and configs to QNAP..."
    # squid.conf 'include's rules.acl, ssl_bump.acl, bump_domains.conf, and early_splice.acl.
    # Pre-create all includes so a first-time deploy starts cleanly.
    ssh "$QNAP_SERVER" "mkdir -p ${REMOTE_BASE}/configs ${REMOTE_BASE}/configs/errors ${REMOTE_BASE}/certs ${REMOTE_BASE}/block-lists ${REMOTE_BASE}/router ${REMOTE_BASE}/cache ${REMOTE_BASE}/ssl_db ${REMOTE_BASE}/logs && touch ${REMOTE_BASE}/configs/rules.acl ${REMOTE_BASE}/configs/ssl_bump.acl ${REMOTE_BASE}/configs/bump_domains.conf ${REMOTE_BASE}/configs/early_splice.acl"
    local rendered_conf rendered_error_dir
    rendered_conf="$(mktemp)"
    rendered_error_dir="$(mktemp -d)"
    trap 'rm -f "${rendered_conf:-}"; rm -rf "${rendered_error_dir:-}"' RETURN
    sed \
        -e "s|__LOCAL_NETWORKS__|${LOCAL_NETWORKS}|g" \
        -e "s|__SQUID_PROXY_PORT__|${SQUID_PROXY_PORT}|g" \
        -e "s|__SQUID_HTTP_PORT__|${SQUID_HTTP_PORT}|g" \
        -e "s|__SQUID_HTTPS_PORT__|${SQUID_HTTPS_PORT}|g" \
        -e "s|__SQUID_DNS_SERVERS__|${SQUID_DNS_SERVERS}|g" \
        "$LOCAL_CONF_TEMPLATE" > "$rendered_conf"
    scp "$rendered_conf" "$QNAP_SERVER:${REMOTE_BASE}/configs/squid.conf"

    if [ -f "${SQUID_DIR}/configs/generate_bump_domains.py" ]; then
        scp "${SQUID_DIR}/configs/generate_bump_domains.py" "$QNAP_SERVER:${REMOTE_BASE}/configs/" 2>/dev/null || true
    fi
    if [ -d "${SQUID_DIR}/configs/errors" ]; then
        cp -a "${SQUID_DIR}/configs/errors/." "$rendered_error_dir/"
        if [ -f "$rendered_error_dir/ERR_ACCESS_DENIED" ]; then
            sed -i "s|__WEBUI_PUBLIC_URL__|${WEBUI_PUBLIC_URL}|g" "$rendered_error_dir/ERR_ACCESS_DENIED"
        fi
        scp -r "$rendered_error_dir/"* "$QNAP_SERVER:${REMOTE_BASE}/configs/errors/" 2>/dev/null || true
    fi

    if [ -f "${LOCAL_CERT_DIR}/squid-ca.pem" ] && [ -f "${LOCAL_CERT_DIR}/squid-ca.key" ]; then
        echo "  [*] Syncing SSL certs to QNAP..."
        scp "${LOCAL_CERT_DIR}/squid-ca.pem" "${LOCAL_CERT_DIR}/squid-ca.key" "$QNAP_SERVER:${REMOTE_BASE}/certs/"
    else
        echo "  [!] WARNING: SSL certs not found in ${LOCAL_CERT_DIR}. Run squid-mgmt.sh cert first."
    fi

    if [ -d "${BLOCKLIST_DIR}" ]; then
        echo "  [*] Syncing blocklists to QNAP..."
        ssh "$QNAP_SERVER" "rm -f ${REMOTE_BASE}/block-lists/*.txt"
        scp "${BLOCKLIST_DIR}/"*.txt "$QNAP_SERVER:${REMOTE_BASE}/block-lists/" 2>/dev/null || true
    fi
}

function update_squid_config() {
    local NAME=$1
    local REMOTE_BASE="${QNAP_CONTAINER_ROOT}/$NAME"

    echo ">>> Updating configuration for $NAME without recreating container..."

    # Check if container is running
    local is_running
    is_running=$(ssh -T "$QNAP_SERVER" "$DOCKER inspect -f '{{.State.Running}}' '$NAME' 2>/dev/null" || true)
    if [ "$is_running" != "true" ]; then
        echo "  [!] ERROR: Container '$NAME' is not running on QNAP."
        echo "      Use 'proxy-deploy' to build and run the container first."
        return 1
    fi

    # Backup existing configuration file on QNAP in case new config is invalid
    echo "  [*] Backing up current squid.conf on QNAP..."
    ssh "$QNAP_SERVER" "[ -f '${REMOTE_BASE}/configs/squid.conf' ] && cp -p '${REMOTE_BASE}/configs/squid.conf' '${REMOTE_BASE}/configs/squid.conf.bak' || true"

    # Sync configuration files
    sync_squid_config "$NAME"

    # Regenerate bump_domains.acl inside container if generator script exists
    echo "  [*] Refreshing bump_domains.acl inside container..."
    ssh -T "$QNAP_SERVER" "$DOCKER exec '$NAME' sh -c '[ -f /etc/squid/configs/generate_bump_domains.py ] && python3 /etc/squid/configs/generate_bump_domains.py /etc/squid/block-lists /etc/squid/configs/bump_domains.acl || true'"

    # Validate syntax before reloading
    echo "  [*] Validating Squid configuration (squid -k parse)..."
    local parse_out parse_rc
    parse_out=$(ssh -T "$QNAP_SERVER" "$DOCKER exec '$NAME' squid -k parse 2>&1")
    parse_rc=$?

    if [ $parse_rc -ne 0 ] || echo "$parse_out" | grep -qiE "FATAL|Bungled"; then
        echo "  [!] ERROR: Squid configuration validation failed! Parse output:"
        echo "$parse_out"
        echo "  [*] Rolling back squid.conf to previous version..."
        ssh -T "$QNAP_SERVER" "[ -f '${REMOTE_BASE}/configs/squid.conf.bak' ] && cp -f '${REMOTE_BASE}/configs/squid.conf.bak' '${REMOTE_BASE}/configs/squid.conf' && rm -f '${REMOTE_BASE}/configs/squid.conf.bak'"
        return 1
    fi

    if echo "$parse_out" | grep -qi "empty ACL"; then
        echo "  [!] WARNING: empty ACL(s) detected — those rules can never match."
    fi

    # Hot-reload configuration without disrupting active connections
    echo "  [*] Hot-reloading Squid configuration via SIGHUP..."
    ssh -T "$QNAP_SERVER" "$DOCKER kill -s HUP '$NAME' >/dev/null && rm -f '${REMOTE_BASE}/configs/squid.conf.bak'"
    if [ $? -ne 0 ]; then
        echo "  [!] ERROR: Failed to send SIGHUP to container '$NAME'."
        return 1
    fi

    # Verify container remains running
    sleep 1
    is_running=$(ssh -T "$QNAP_SERVER" "$DOCKER inspect -f '{{.State.Running}}' '$NAME' 2>/dev/null" || true)
    if [ "$is_running" != "true" ]; then
        echo "  [!] ERROR: Container '$NAME' stopped unexpectedly after reload signal."
        return 1
    fi

    echo "  [+] Squid configuration updated and reloaded cleanly (zero container downtime)!"
    return 0
}

function create_squid() {
    local IP=$1
    local NAME=$2
    local IMAGE=$3

    echo "Launching $NAME ($IP)..."
    REMOTE_BASE="${QNAP_CONTAINER_ROOT}/$NAME"

    REMOTE_BUILD_DIR="/tmp/squid-build"
    # container-station's docker wrapper needs a homes dir for the SSH user;
    # pre-create it to avoid the 'permission denied' mkdir error during docker build.
    HOMES_DIR="${QNAP_DOCKER_HOME_ROOT}/${QNAP_USER}"

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
    sync_squid_config "$NAME"

    # NOTE: individual :ro file mounts for rules.acl / ssl_bump.acl were removed.
    # The parent configs/ directory is already mounted read-write (the Web UI and
    # the entrypoint generator both write into it), so the per-file mounts were
    # redundant AND fragile: a bind-mounted file is pinned to one inode, so any
    # writer using write-to-temp + rename would leave Squid reading a stale file.
    ssh -T "$QNAP_SERVER" << EOF
        $DOCKER stop "$NAME" >/dev/null 2>&1 || true
        $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
        $DOCKER run -d \
            --name "$NAME" --hostname "$NAME" \
            --net "$DOCKER_NET" --ip "$IP" \
            --cap-add=NET_ADMIN \
            --restart="$SQUID_RESTART_POLICY" \
            -e TZ="$TIMEZONE" \
            -e SQUID_HTTP_PORT="$SQUID_HTTP_PORT" \
            -e SQUID_HTTPS_PORT="$SQUID_HTTPS_PORT" \
            -v "${REMOTE_BASE}/configs/squid.conf:/etc/squid/squid.conf:ro" \
            -v "${REMOTE_BASE}/configs:/etc/squid/configs" \
            -v "${REMOTE_BASE}/certs:/etc/squid/certs:ro" \
            -v "${REMOTE_BASE}/block-lists:/etc/squid/block-lists:ro" \
            -v "${REMOTE_BASE}/cache:/var/cache/squid" \
            -v "${REMOTE_BASE}/ssl_db:/var/lib/squid/ssl_db" \
            -v "${REMOTE_BASE}/logs:/var/log/squid" \
            $IMAGE > /dev/null
EOF
}

function create_webui() {
    local IP=$1
    local NAME=$2
    local IMAGE=$3

    echo "Launching $NAME ($IP)..."
    REMOTE_SQUID_BASE="${QNAP_CONTAINER_ROOT}/${SQUID_CONTAINER_NAME}"
    REMOTE_BUILD_DIR="/tmp/squid-webui-build"
    HOMES_DIR="${QNAP_DOCKER_HOME_ROOT}/${QNAP_USER}"

    echo ">>> Syncing webui source and building $IMAGE on QNAP..."
    ssh "$QNAP_SERVER" "rm -rf ${REMOTE_BUILD_DIR} && mkdir -p ${HOMES_DIR} ${REMOTE_BUILD_DIR}"
    scp -r "${SQUID_DIR}/webui/"* "$QNAP_SERVER:${REMOTE_BUILD_DIR}/"
    ssh -T "$QNAP_SERVER" \
        "cd ${REMOTE_BUILD_DIR} && $DOCKER build -t ${IMAGE} . && rm -rf ${REMOTE_BUILD_DIR}"
    if [ $? -ne 0 ]; then
        echo "ERROR: docker build for webui failed on QNAP."
        exit 1
    fi

    # Sync proxy-hosts.conf and devices.list to squid-proxy directory if present.
    # certs/ is created here too: create_webui mounts it, and when the webui is
    # deployed on its own (without create_squid having run first) Docker would
    # otherwise silently create an empty directory and the CA download endpoints
    # would 404.
    ssh "$QNAP_SERVER" "mkdir -p ${REMOTE_SQUID_BASE}/configs ${REMOTE_SQUID_BASE}/certs ${REMOTE_SQUID_BASE}/block-lists ${REMOTE_SQUID_BASE}/router ${REMOTE_SQUID_BASE}/logs && touch ${REMOTE_SQUID_BASE}/configs/rules.acl ${REMOTE_SQUID_BASE}/configs/ssl_bump.acl ${REMOTE_SQUID_BASE}/configs/bump_domains.conf ${REMOTE_SQUID_BASE}/configs/early_splice.acl"

    if [ -f "${LOCAL_CERT_DIR}/squid-ca.pem" ]; then
        scp "${LOCAL_CERT_DIR}/squid-ca.pem" "$QNAP_SERVER:${REMOTE_SQUID_BASE}/certs/" 2>/dev/null || true
        [ -f "${LOCAL_CERT_DIR}/squid-ca.crt" ] && \
            scp "${LOCAL_CERT_DIR}/squid-ca.crt" "$QNAP_SERVER:${REMOTE_SQUID_BASE}/certs/" 2>/dev/null || true
    else
        echo "  [!] WARNING: No CA cert in ${LOCAL_CERT_DIR}; the Web UI cert download endpoints will 404."
        echo "      Run 'squid-mgmt.sh cert' first."
    fi
    
    ssh "$QNAP_SERVER" "rm -f ${REMOTE_SQUID_BASE}/router/proxy-hosts.conf ${REMOTE_SQUID_BASE}/configs/devices.list"
    if [ -f "${PROXY_HOSTS_CONF}" ]; then
        scp "${PROXY_HOSTS_CONF}" "$QNAP_SERVER:${REMOTE_SQUID_BASE}/router/proxy-hosts.conf"
    fi
    if [ -f "${DEVICES_LIST}" ]; then
        scp "${DEVICES_LIST}" "$QNAP_SERVER:${REMOTE_SQUID_BASE}/configs/devices.list"
    fi
    if [ -d "${BLOCKLIST_DIR}" ]; then
        ssh "$QNAP_SERVER" "rm -f ${REMOTE_SQUID_BASE}/block-lists/*.txt"
        scp "${BLOCKLIST_DIR}/"*.txt "$QNAP_SERVER:${REMOTE_SQUID_BASE}/block-lists/" 2>/dev/null || true
    fi

    # Stop and remove existing container if running
    ssh -T "$QNAP_SERVER" "$DOCKER stop $NAME > /dev/null 2>&1; $DOCKER rm $NAME > /dev/null 2>&1"

    # NOTE: '-p 3131:3131' was removed. $DOCKER_NET is a macvlan/qnet network, so
    # published ports are a no-op there — the Web UI is only ever reachable on the
    # container IP ($IP), never on the QNAP host IP. Keeping the flag implied a
    # fallback URL that could never work.
    ssh -T "$QNAP_SERVER" << EOF
        $DOCKER run -d \
            --name "$NAME" --hostname "$NAME" \
            --net "$DOCKER_NET" --ip "$IP" \
            --restart="$WEBUI_RESTART_POLICY" \
            -e TZ="$TIMEZONE" \
            -e RUNNING_ON_NAS="true" \
            -e QNAP_IP="$QNAP_IP" \
            -e SQUID_CONTAINER_NAME="$SQUID_CONTAINER_NAME" \
            -e SQUID_PROXY_HOST="$SQUID_PROXY_IP" \
            -e SQUID_PROXY_PORT="$SQUID_PROXY_PORT" \
            -e WEBUI_PUBLIC_URL="$WEBUI_PUBLIC_URL" \
            -e WEBUI_PORT="$WEBUI_PORT" \
            -e ADMIN_CLIENT_IPS="$ADMIN_CLIENT_IPS" \
            -e CERT_NAME="$CERT_NAME" \
            -e FAILURE_REPORT_RETENTION_DAYS="$FAILURE_REPORT_RETENTION_DAYS" \
            -v "${REMOTE_SQUID_BASE}/configs:/etc/squid/configs" \
            -v "${REMOTE_SQUID_BASE}/certs:/etc/squid/certs:ro" \
            -v "${REMOTE_SQUID_BASE}/block-lists:/etc/squid/block-lists" \
            -v "${REMOTE_SQUID_BASE}/router:/etc/squid/router" \
            -v "${REMOTE_SQUID_BASE}/logs:/var/log/squid:ro" \
            -v "/etc/config/shadow:/host_etc/config/shadow:ro" \
            -v "/etc/shadow:/host_etc/shadow:ro" \
            -v "/var/run/docker.sock:/var/run/docker.sock" \
            $IMAGE > /dev/null
EOF
}

function create_instances() {
    mapfile -t active_list < <(get_filtered_instances)

    if [ ${#active_list[@]} -eq 0 ]; then
        echo "ERROR: No matching container targets found."
        exit 1
    fi

    if [ ! -f "$LOCAL_CONF_TEMPLATE" ]; then
        echo "ERROR: Squid config template missing at $LOCAL_CONF_TEMPLATE"
        exit 1
    fi

    for entry in "${active_list[@]}"; do
        read -r IP NAME IMAGE <<< "$entry"

        if [ "$NAME" == "$SQUID_CONTAINER_NAME" ]; then
            create_squid "$IP" "$NAME" "$IMAGE"
        elif [ "$NAME" == "$WEBUI_CONTAINER_NAME" ]; then
            create_webui "$IP" "$NAME" "$IMAGE"
        else
            echo "ERROR: Unknown container name '$NAME'"
        fi
    done

    echo ">>> Waiting 15s for services to start..."
    sleep 15
}

function update_instances_config() {
    mapfile -t active_list < <(get_filtered_instances)

    [ ${#active_list[@]} -eq 0 ] && return

    if [ ! -f "$LOCAL_CONF_TEMPLATE" ]; then
        echo "ERROR: Squid config template missing at $LOCAL_CONF_TEMPLATE"
        exit 1
    fi

    for entry in "${active_list[@]}"; do
        read -r IP NAME IMAGE <<< "$entry"

        if [ "$NAME" == "$SQUID_CONTAINER_NAME" ]; then
            update_squid_config "$NAME"
            if [ $? -ne 0 ]; then
                exit 1
            fi
        else
            echo "ERROR: Config-only update is not supported for '$NAME'"
            exit 1
        fi
    done
}

# --- 4. EXECUTION LOGIC ---
CREATE=FALSE
REMOVE=FALSE
CONFIG=FALSE
TARGET_NAMES=()

# Parse arguments
while [ $# -gt 0 ] ; do
    case "$1" in
        create) CREATE=TRUE ;;
        remove) REMOVE=TRUE ;;
        config|config-deploy|reconfigure) CONFIG=TRUE ;;
        *)      TARGET_NAMES+=("$1") ;;
    esac
    shift
done

# Check 1: Must have an action
if [[ "$CREATE" == "FALSE" && "$REMOVE" == "FALSE" && "$CONFIG" == "FALSE" ]]; then
    echo "ERROR: You must specify 'create', 'remove', 'config', or a combination."
    exit 1
fi

# Check 2: Must have at least one target name
if [ ${#TARGET_NAMES[@]} -eq 0 ]; then
    echo "-------------------------------------------------------"
    echo "ERROR: No target containers specified."
    echo "Usage: $0 {create|remove|config} <target1> <target2> ..."
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

if [[ "$CONFIG" == "TRUE" ]]; then
    update_instances_config
fi

find "${SQUID_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${SQUID_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true

echo "DONE."
