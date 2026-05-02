import os
import json
import re
import secrets
import subprocess
import threading
import time
import socket
import http.client
from datetime import date
import paramiko
from passlib.hash import md5_crypt, sha512_crypt, sha256_crypt, des_crypt
from flask import Flask, render_template, request, jsonify, session, send_file

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))

# Configuration paths (inside container / host)
SQUID_CONFIG_DIR = os.environ.get("SQUID_CONFIG_DIR", "/etc/squid/configs")
SQUID_BLOCKLIST_DIR = os.environ.get("SQUID_BLOCKLIST_DIR", "/etc/squid/block-lists")
SQUID_CERT_DIR = os.environ.get("SQUID_CERT_DIR", "/etc/squid/certs")
ROUTER_HOSTS_CONF = os.environ.get("ROUTER_HOSTS_CONF", "/etc/squid/router/proxy-hosts.conf")

RULES_JSON_PATH = os.path.join(SQUID_CONFIG_DIR, "rules.json")
RULES_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "rules.acl")

QNAP_IP = os.environ.get("QNAP_IP", "192.168.1.2")
SQUID_CONTAINER_NAME = os.environ.get("SQUID_CONTAINER_NAME", "squid-proxy")

# IPs that get the Admin page as the default landing page
ADMIN_CLIENT_IPS = {
    "192.168.8.8",   # pc-admin
}

DAY_MAP = {
    "Sunday": "S",
    "Monday": "M",
    "Tuesday": "T",
    "Wednesday": "W",
    "Thursday": "H",
    "Friday": "F",
    "Saturday": "A"
}


def is_authenticated():
    return True  # AUTH DISABLED FOR TESTING — re-enable before production
    # return session.get("authenticated", False)



def verify_shadow_password(username, password):
    """Verify password directly against mounted QNAP shadow file."""
    shadow_paths = [
        "/host_etc/shadow",
        "/host_etc/config/shadow",
        "/etc/shadow",
        "/etc/config/shadow"
    ]
    for path in shadow_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 2 and parts[0] == username:
                            stored_hash = parts[1]
                            if stored_hash in ["*", "!", ""]:
                                return False

                            if stored_hash.startswith("$1$"):
                                return md5_crypt.verify(password, stored_hash)
                            elif stored_hash.startswith("$6$"):
                                return sha512_crypt.verify(password, stored_hash)
                            elif stored_hash.startswith("$5$"):
                                return sha256_crypt.verify(password, stored_hash)
                            else:
                                return des_crypt.verify(password, stored_hash)
            except Exception as e:
                print(f"Error reading shadow file at {path}: {e}")
    return False


def verify_nas_credentials(username, password):
    """Verify user credentials via shadow file or SSH fallback."""
    if verify_shadow_password(username, password):
        return True

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        target = QNAP_IP
        ssh.connect(
            target,
            port=22,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=5
        )
        ssh.close()
        return True
    except Exception as e:
        print(f"Authentication failed for user '{username}' on target {QNAP_IP}: {e}")
        return False


DEVICE_POLICIES_PATH = os.path.join(SQUID_CONFIG_DIR, "device_policies.json")
DAY_LETTERS = ["S", "M", "T", "W", "H", "F", "A"]


def make_empty_weekly():
    """Return a fresh 7×48 all-False matrix."""
    return [[False] * 48 for _ in range(7)]


def make_empty_today():
    """Return a fresh 48-slot all-False list."""
    return [False] * 48


def today_str():
    return date.today().isoformat()


def migrate_legacy_policy(legacy):
    """
    Migrate an old-format policy (blocklists + matrix) to the new schema.
    Old blocklists are promoted to always_block; old matrix is discarded.
    """
    return {
        "ip": legacy.get("ip", ""),
        "hostname": legacy.get("hostname", legacy.get("ip", "")),
        "always_block": legacy.get("blocklists", []),
        "default_block": []
    }


def ensure_policy_schema(policy):
    """Ensure a policy dict has the current schema fields, migrating if necessary."""
    # Detect legacy flat format (has 'blocklists' key but not 'always_block')
    if "blocklists" in policy and "always_block" not in policy:
        policy = migrate_legacy_policy(policy)

    policy.setdefault("always_block", [])
    policy.setdefault("default_block", [])

    repaired = []
    for entry in policy["default_block"]:
        if not isinstance(entry, dict) or "list" not in entry:
            continue
        entry.setdefault("unblock_weekly", make_empty_weekly())
        entry.setdefault("unblock_today", make_empty_today())
        entry.setdefault("today_date", "")
        # Auto-clear today overrides if date has changed
        if entry["today_date"] != today_str():
            entry["unblock_today"] = make_empty_today()
            entry["today_date"] = today_str()
        # Ensure correct dimensions
        if len(entry["unblock_weekly"]) != 7:
            entry["unblock_weekly"] = make_empty_weekly()
        for d in range(7):
            if len(entry["unblock_weekly"][d]) != 48:
                entry["unblock_weekly"][d] = [False] * 48
        if len(entry["unblock_today"]) != 48:
            entry["unblock_today"] = make_empty_today()
        repaired.append(entry)
    policy["default_block"] = repaired
    return policy


def load_proxy_hosts_ips():
    """Load redirected IP addresses from proxy-hosts.conf."""
    ips = set()
    possible_paths = [
        ROUTER_HOSTS_CONF,
        "/etc/squid/router/proxy-hosts.conf",
        os.path.join(os.path.dirname(__file__), "..", "router", "proxy-hosts.conf")
    ]
    for path in possible_paths:
        if path and os.path.exists(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 1:
                                ips.add(parts[0])
                if ips:
                    break
            except Exception as e:
                print(f"Error reading proxy-hosts.conf from {path}: {e}")
    return ips


def load_devices_list():
    """Find and parse devices.list file containing IP and Hostname entries."""
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "devices.list"),
        os.environ.get("DEVICES_LIST_PATH"),
        "/etc/squid/devices.list",
        "/etc/squid/configs/devices.list",
        os.path.join(SQUID_CONFIG_DIR, "devices.list")
    ]
    proxy_ips = load_proxy_hosts_ips()
    devices = []
    seen = set()
    for path in possible_paths:
        if path and os.path.exists(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip, hostname = parts[0], parts[1]
                                if ip not in seen:
                                    seen.add(ip)
                                    clean_name = hostname.replace(".home", "").replace(".alt", "")
                                    devices.append({
                                        "ip": ip,
                                        "hostname": hostname,
                                        "name": clean_name,
                                        "in_proxy_hosts": (ip in proxy_ips)
                                    })
                if devices:
                    break
            except Exception as e:
                print(f"Error reading devices.list from {path}: {e}")
    return devices


def load_device_policies():
    if os.path.exists(DEVICE_POLICIES_PATH):
        try:
            with open(DEVICE_POLICIES_PATH, "r") as f:
                raw = json.load(f)
            migrated = {}
            for ip, pol in raw.items():
                migrated[ip] = ensure_policy_schema(pol)
            return migrated
        except Exception as e:
            print(f"Error loading device_policies.json: {e}")
    return {}


def save_device_policies(policies):
    os.makedirs(os.path.dirname(DEVICE_POLICIES_PATH), exist_ok=True)
    for ip in policies:
        policies[ip] = ensure_policy_schema(policies[ip])
    with open(DEVICE_POLICIES_PATH, "w") as f:
        json.dump(policies, f, indent=2)
    compile_device_policies_acls(policies)


def slot_to_time(slot_idx):
    """Convert slot index (0..47) to HH:MM string."""
    hours = slot_idx // 2
    mins = (slot_idx % 2) * 30
    return f"{hours:02d}:{mins:02d}"


def slot_to_end_time(slot_idx):
    """Convert slot index end (0..47) to HH:MM string."""
    if slot_idx >= 47:
        return "23:59"
    next_slot = slot_idx + 1
    hours = next_slot // 2
    mins = (next_slot % 2) * 30
    return f"{hours:02d}:{mins:02d}"


def extract_allow_ranges(slots_7x48):
    """
    Given a 7×48 matrix where True = unblocked window,
    return a dict mapping (start_time, end_time) -> [day_letters].
    """
    range_to_days = {}
    for day_idx in range(7):
        day_letter = DAY_LETTERS[day_idx]
        day_slots = slots_7x48[day_idx] if len(slots_7x48) > day_idx else [False] * 48
        in_range = False
        start_slot = 0
        for slot_idx in range(48):
            if day_slots[slot_idx] and not in_range:
                in_range = True
                start_slot = slot_idx
            elif not day_slots[slot_idx] and in_range:
                in_range = False
                t_key = (slot_to_time(start_slot), slot_to_end_time(slot_idx - 1))
                range_to_days.setdefault(t_key, []).append(day_letter)
        if in_range:
            t_key = (slot_to_time(start_slot), slot_to_end_time(47))
            range_to_days.setdefault(t_key, []).append(day_letter)
    return range_to_days


def merge_today_into_weekly(unblock_weekly, unblock_today):
    """
    Overlay today's unblock slots onto the weekly matrix for the current day.
    Returns a new merged 7×48 matrix.
    """
    # Convert Python weekday (Mon=0..Sun=6) to our index (S=0,M=1,T=2,W=3,H=4,F=5,A=6)
    python_to_our = {6: 0, 0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 6}
    our_day = python_to_our.get(date.today().weekday(), 0)
    merged = [list(row) for row in unblock_weekly]
    for slot_idx in range(48):
        if unblock_today[slot_idx]:
            merged[our_day][slot_idx] = True
    return merged


def deduplicate_domains(domains):
    """
    Deduplicates a collection of domain strings for Squid dstdomain ACLs.

    Squid dstdomain matching rules:
    - '.example.com' matches 'example.com' and all subdomains ('*.example.com').
    - 'example.com' matches ONLY exact 'example.com'.

    Subsumption / Duplication rules:
    1. If '.example.com' exists, 'example.com' is redundant and causes Squid duplicate domain errors/crashes.
    2. If '.example.com' exists, any '.sub.example.com' or 'sub.example.com' is subsumed and redundant.
    3. Exact string duplicates are removed.
    """
    cleaned = set()
    for d in domains:
        d = d.strip()
        if d:
            cleaned.add(d)

    wildcard_bases = {}
    for d in cleaned:
        if d.startswith("."):
            base = d.lstrip(".")
            if base:
                wildcard_bases[d] = base

    result = set()
    for d in cleaned:
        if d.startswith("."):
            base = d.lstrip(".")
            subsumed = False
            for w_domain, w_base in wildcard_bases.items():
                if w_domain != d:
                    if base == w_base or base.endswith("." + w_base):
                        if len(w_base) < len(base) or (len(w_base) == len(base) and w_domain < d):
                            subsumed = True
                            break
            if not subsumed:
                result.add(d)
        else:
            subsumed = False
            for w_domain, w_base in wildcard_bases.items():
                if d == w_base or d.endswith("." + w_base):
                    subsumed = True
                    break
            if not subsumed:
                result.add(d)

    return sorted(result)


def parse_blocklists(blocklist_dir, output_dir):
    """
    Parse raw blocklist files in blocklist_dir, generate clean per-blocklist domain ACL files,
    and return structured metadata (domains + URL path rules).
    """
    os.makedirs(output_dir, exist_ok=True)
    parsed_blocklists = {}

    if not os.path.exists(blocklist_dir):
        return parsed_blocklists

    try:
        for filename in sorted(os.listdir(blocklist_dir)):
            if not filename.endswith(".txt"):
                continue

            filepath = os.path.join(blocklist_dir, filename)
            plain_domains = set()
            path_rules = []

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        if "/" in line:
                            # Entry contains URL path (e.g. steamcommunity.com/market)
                            parts = line.split("/", 1)
                            raw_domain = parts[0].strip()
                            path = "/" + parts[1].strip()

                            clean_domain = raw_domain.lstrip(".")
                            if not clean_domain:
                                continue

                            bump_domain = f".{clean_domain}"
                            path_rules.append({
                                "raw_domain": raw_domain,
                                "clean_domain": clean_domain,
                                "bump_domain": bump_domain,
                                "path": path
                            })
                        else:
                            # Plain domain entry
                            plain_domains.add(line)
            except Exception as e:
                print(f"Error parsing blocklist file {filepath}: {e}")

            # Deduplicate plain domains for this specific blocklist
            dedup_plain = deduplicate_domains(plain_domains)

            # Write per-blocklist clean domain ACL file
            domain_acl_filename = f"domains_{filename}.acl"
            domain_acl_file = os.path.join(output_dir, domain_acl_filename)
            try:
                with open(domain_acl_file, "w", encoding="utf-8") as f:
                    f.write(f"# Auto-generated clean domain blocklist for {filename}\n")
                    for dom in dedup_plain:
                        f.write(f"{dom}\n")
            except Exception as e:
                print(f"Error writing {domain_acl_file}: {e}")

            parsed_blocklists[filename] = {
                "domain_acl_file": domain_acl_file,
                "domain_acl_filename": domain_acl_filename,
                "plain_domains": dedup_plain,
                "path_rules": path_rules
            }
    except Exception as e:
        print(f"Error reading blocklist directory {blocklist_dir}: {e}")

    return parsed_blocklists


def get_parsed_blocklists():
    """Get parsed clean domains and path rules per blocklist."""
    return parse_blocklists(SQUID_BLOCKLIST_DIR, SQUID_CONFIG_DIR)


def compile_device_policies_acls(policies):
    """
    Compile device policies into Squid ACL rules.
    - always_block lists  → unconditional http_access deny (domain + path rules)
    - default_block lists → allow windows + fallback deny (domain + path rules)
    """
    parsed_blocklists = get_parsed_blocklists()

    acl_lines = [
        "# ===========================================================",
        "# AUTO-GENERATED BY SQUID WEB UI - DEVICE POLICIES",
        "# ===========================================================",
        ""
    ]

    declared_blocklists = set()
    declared_path_rules = set()

    for ip, policy in policies.items():
        policy = ensure_policy_schema(policy)
        hostname = policy.get("hostname", ip)
        always_block = policy.get("always_block", [])
        default_block = policy.get("default_block", [])

        if not always_block and not default_block:
            continue

        clean_ip_id = ip.replace(".", "_")
        src_acl_name = f"src_dev_{clean_ip_id}"

        acl_lines.append(f"# ── Device: {hostname} ({ip}) ──")
        acl_lines.append(f"acl {src_acl_name} src {ip}")
        acl_lines.append("")

        # Declare all blocklist domain and path ACLs once
        all_lists = list(always_block) + [e["list"] for e in default_block if "list" in e]
        for bl in all_lists:
            bl_id = bl.replace('.', '_').replace('-', '_')
            bl_acl_name = f"list_{bl_id}"

            if bl_acl_name not in declared_blocklists:
                if bl in parsed_blocklists:
                    dom_file = parsed_blocklists[bl]["domain_acl_file"]
                else:
                    dom_file = os.path.join(SQUID_BLOCKLIST_DIR, bl)
                acl_lines.append(f"acl {bl_acl_name} dstdomain \"{dom_file}\"")
                declared_blocklists.add(bl_acl_name)

                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx, rule in enumerate(path_rules, 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        p_url_acl = f"path_url_{bl_id}_{idx}"
                        if p_dom_acl not in declared_path_rules:
                            acl_lines.append(f"acl {p_dom_acl} dstdomain {rule['bump_domain']}")
                            acl_lines.append(f"acl {p_url_acl} urlpath_regex -i ^{re.escape(rule['path'])}")
                            declared_path_rules.add(p_dom_acl)
        acl_lines.append("")

        # Section A: Always Block
        if always_block:
            acl_lines.append(f"  # Always Block — {hostname}")
            for bl in always_block:
                bl_id = bl.replace('.', '_').replace('-', '_')
                bl_acl_name = f"list_{bl_id}"
                acl_lines.append(f"http_access deny {src_acl_name} {bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        p_url_acl = f"path_url_{bl_id}_{idx}"
                        acl_lines.append(f"http_access deny {src_acl_name} {p_dom_acl} {p_url_acl}")
            acl_lines.append("")

        # Section B: Default Block with unblock windows
        time_acl_idx = 0
        for entry in default_block:
            bl = entry.get("list", "")
            if not bl:
                continue
            bl_id = bl.replace('.', '_').replace('-', '_')
            bl_acl_name = f"list_{bl_id}"
            unblock_weekly = entry.get("unblock_weekly", make_empty_weekly())
            unblock_today = entry.get("unblock_today", make_empty_today())
            merged = merge_today_into_weekly(unblock_weekly, unblock_today)
            allow_ranges = extract_allow_ranges(merged)

            acl_lines.append(f"  # Default Block (unblock windows): {bl} — {hostname}")
            for (t_start, t_end), day_list in allow_ranges.items():
                days_code = "".join(day_list)
                time_acl_name = f"time_allow_{clean_ip_id}_{time_acl_idx}"
                acl_lines.append(f"acl {time_acl_name} time {days_code} {t_start}-{t_end}")
                acl_lines.append(f"http_access allow {src_acl_name} {bl_acl_name} {time_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        p_url_acl = f"path_url_{bl_id}_{idx}"
                        acl_lines.append(f"http_access allow {src_acl_name} {p_dom_acl} {p_url_acl} {time_acl_name}")
                time_acl_idx += 1

            # Fallback: deny plain domains and path rules outside allowed windows
            acl_lines.append(f"http_access deny {src_acl_name} {bl_acl_name}")
            if bl in parsed_blocklists:
                path_rules = parsed_blocklists[bl].get("path_rules", [])
                for idx in range(1, len(path_rules) + 1):
                    p_dom_acl = f"path_dom_{bl_id}_{idx}"
                    p_url_acl = f"path_url_{bl_id}_{idx}"
                    acl_lines.append(f"http_access deny {src_acl_name} {p_dom_acl} {p_url_acl}")
            acl_lines.append("")

        acl_lines.append("")

    os.makedirs(os.path.dirname(RULES_ACL_PATH), exist_ok=True)
    with open(RULES_ACL_PATH, "w") as f:
        f.write("\n".join(acl_lines) + "\n")

    reload_squid()


def load_rules():
    if os.path.exists(RULES_JSON_PATH):
        try:
            with open(RULES_JSON_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading rules.json: {e}")
    return []


def save_rules(rules):
    os.makedirs(os.path.dirname(RULES_JSON_PATH), exist_ok=True)
    with open(RULES_JSON_PATH, "w") as f:
        json.dump(rules, f, indent=2)
    compile_squid_acls(rules)


def compile_squid_acls(rules):
    """Compile custom rules list into Squid ACL file (rules.acl)."""
    parsed_blocklists = get_parsed_blocklists()

    acl_lines = [
        "# ===========================================================",
        "# AUTO-GENERATED BY SQUID WEB UI - DO NOT EDIT MANUALLY",
        "# ===========================================================",
        ""
    ]

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_id = rule.get("id")
        rule_name = rule.get("name", "Unnamed Rule")
        src_ip = rule.get("source_ip")
        blocklist = rule.get("blocklist")
        days = rule.get("days", [])
        time_start = rule.get("time_start", "00:00")
        time_end = rule.get("time_end", "23:59")
        policy = rule.get("policy", "allow_during_slot")

        if not src_ip or not blocklist:
            continue

        acl_lines.append(f"# Rule: {rule_name} ({rule_id})")
        acl_lines.append(f"acl src_{rule_id} src {src_ip}")

        bl_id = blocklist.replace('.', '_').replace('-', '_')
        if blocklist in parsed_blocklists:
            dom_file = parsed_blocklists[blocklist]["domain_acl_file"]
            path_rules = parsed_blocklists[blocklist].get("path_rules", [])
        else:
            dom_file = f"/etc/squid/block-lists/{blocklist}"
            path_rules = []

        acl_lines.append(f"acl list_{rule_id} dstdomain \"{dom_file}\"")
        for idx, p_rule in enumerate(path_rules, 1):
            acl_lines.append(f"acl path_dom_{rule_id}_{idx} dstdomain {p_rule['bump_domain']}")
            acl_lines.append(f"acl path_url_{rule_id}_{idx} urlpath_regex -i ^{re.escape(p_rule['path'])}")

        day_codes = "".join([DAY_MAP[d] for d in days if d in DAY_MAP])
        if not day_codes:
            day_codes = "SMWTHFA"

        acl_lines.append(f"acl time_{rule_id} time {day_codes} {time_start}-{time_end}")

        if policy == "allow_during_slot":
            acl_lines.append(f"http_access allow src_{rule_id} list_{rule_id} time_{rule_id}")
            for idx in range(1, len(path_rules) + 1):
                acl_lines.append(f"http_access allow src_{rule_id} path_dom_{rule_id}_{idx} path_url_{rule_id}_{idx} time_{rule_id}")

            acl_lines.append(f"http_access deny src_{rule_id} list_{rule_id}")
            for idx in range(1, len(path_rules) + 1):
                acl_lines.append(f"http_access deny src_{rule_id} path_dom_{rule_id}_{idx} path_url_{rule_id}_{idx}")
        elif policy == "block_during_slot":
            acl_lines.append(f"http_access deny src_{rule_id} list_{rule_id} time_{rule_id}")
            for idx in range(1, len(path_rules) + 1):
                acl_lines.append(f"http_access deny src_{rule_id} path_dom_{rule_id}_{idx} path_url_{rule_id}_{idx} time_{rule_id}")

        acl_lines.append("")

    os.makedirs(os.path.dirname(RULES_ACL_PATH), exist_ok=True)
    with open(RULES_ACL_PATH, "w") as f:
        f.write("\n".join(acl_lines) + "\n")

    reload_squid()



class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket."""
    def __init__(self, unix_socket):
        super().__init__("localhost")
        self.unix_socket = unix_socket

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.unix_socket)


def docker_socket_request(method, path, body=None):
    """Make an HTTP request to the Docker daemon via Unix socket."""
    conn = UnixSocketHTTPConnection("/var/run/docker.sock")
    headers = {"Content-Type": "application/json"}
    body_bytes = json.dumps(body).encode() if body else b""
    conn.request(method, path, body=body_bytes, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def reload_squid():
    """Trigger Squid ACL reload by sending SIGHUP via Docker socket API."""
    try:
        status, data = docker_socket_request(
            "POST",
            f"/containers/{SQUID_CONTAINER_NAME}/kill?signal=HUP"
        )
        if status in (200, 204):
            print(f"Squid container '{SQUID_CONTAINER_NAME}' successfully reloaded via SIGHUP.")
        else:
            print(f"Failed to send SIGHUP to Squid: HTTP {status} {data.decode()}")
    except Exception as e:
        print(f"Failed to reload Squid via Docker socket: {e}")


# --- API ENDPOINTS ---

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/blocked")
def blocked():
    domain = request.args.get("domain", "Unknown Webpage")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    return render_template("blocked.html", domain=domain, client_ip=client_ip)


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    return jsonify({
        "authenticated": is_authenticated(),
        "user": session.get("username", ""),
        "client_ip": client_ip,
        "is_admin_client": client_ip in ADMIN_CLIENT_IPS
    })


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    if verify_nas_credentials(username, password):
        session["authenticated"] = True
        session["username"] = username
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Invalid NAS Username or Password"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    hosts = []
    if os.path.exists(ROUTER_HOSTS_CONF):
        try:
            with open(ROUTER_HOSTS_CONF, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            hosts.append({"ip": parts[0], "hostname": parts[1]})
        except Exception as e:
            print(f"Error parsing proxy-hosts.conf: {e}")

    return jsonify({"hosts": hosts})


@app.route("/api/blocklists", methods=["GET"])
def get_blocklists():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    files = []
    if os.path.exists(SQUID_BLOCKLIST_DIR):
        try:
            files = sorted(
                f for f in os.listdir(SQUID_BLOCKLIST_DIR)
                if f.endswith(".txt")
            )
        except Exception as e:
            print(f"Error listing blocklists: {e}")

    return jsonify({"blocklists": files})


@app.route("/api/blocklists/<filename>", methods=["GET"])
def get_blocklist_content(filename):
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".txt"):
        return jsonify({"error": "Invalid blocklist file"}), 400

    filepath = os.path.join(SQUID_BLOCKLIST_DIR, safe_filename)
    if not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404

    return send_file(filepath, mimetype="text/plain")




@app.route("/api/devices", methods=["GET"])
def get_devices():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"devices": load_devices_list()})


@app.route("/api/policies", methods=["GET"])
def get_policies():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"policies": load_device_policies()})


@app.route("/api/policies", methods=["POST"])
def update_policies():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.json or {}
        policies = load_device_policies()

        if "ip" in data:
            ip = data["ip"]
            new_pol = {
                "ip": ip,
                "hostname": data.get("hostname", ip),
                "always_block": data.get("always_block", []),
                "default_block": data.get("default_block", [])
            }
            policies[ip] = ensure_policy_schema(new_pol)
        elif "policies" in data:
            raw = data["policies"]
            policies = {}
            if isinstance(raw, dict):
                for ip, pol in raw.items():
                    if isinstance(pol, dict):
                        pol["ip"] = ip
                        policies[ip] = ensure_policy_schema(pol)

        save_device_policies(policies)
        return jsonify({"success": True, "policies": policies})
    except Exception as e:
        print(f"Error in update_policies API: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/apply", methods=["POST"])
def apply_rules_api():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        policies = load_device_policies()
        compile_device_policies_acls(policies)
        return jsonify({"success": True, "message": "Squid rules applied and service reloaded successfully."})
    except Exception as e:
        print(f"Error in apply_rules_api: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/rules", methods=["GET"])
def get_rules_api():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"rules": load_rules()})



@app.route("/api/rules", methods=["POST"])
def add_or_update_rule():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    rules = load_rules()

    rule_id = data.get("id") or f"rule_{secrets.token_hex(4)}"
    new_rule = {
        "id": rule_id,
        "name": data.get("name", "New Rule").strip(),
        "source_ip": data.get("source_ip", "").strip(),
        "source_name": data.get("source_name", "").strip(),
        "blocklist": data.get("blocklist", "").strip(),
        "days": data.get("days", []),
        "time_start": data.get("time_start", "00:00"),
        "time_end": data.get("time_end", "23:59"),
        "policy": data.get("policy", "allow_during_slot"),
        "enabled": data.get("enabled", True)
    }

    # Replace existing rule if ID matches, otherwise append
    updated = False
    for i, r in enumerate(rules):
        if r.get("id") == rule_id:
            rules[i] = new_rule
            updated = True
            break
    if not updated:
        rules.append(new_rule)

    save_rules(rules)
    return jsonify({"success": True, "rule": new_rule})


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    rules = load_rules()
    rules = [r for r in rules if r.get("id") != rule_id]
    save_rules(rules)
    return jsonify({"success": True})


@app.route("/api/rules/<rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    rules = load_rules()
    for r in rules:
        if r.get("id") == rule_id:
            r["enabled"] = not r.get("enabled", True)
            break
    save_rules(rules)
    return jsonify({"success": True})


@app.route("/download/cert.crt")
def download_cert_crt():
    """Public endpoint to download Root CA certificate in DER format (.crt) for Windows/iOS/macOS."""
    cert_path = os.path.join(SQUID_CERT_DIR, "squid-ca.crt")
    pem_path = os.path.join(SQUID_CERT_DIR, "squid-ca.pem")

    if os.path.exists(cert_path):
        return send_file(cert_path, as_attachment=True, download_name="squid-ca.crt", mimetype="application/x-x509-ca-cert")
    elif os.path.exists(pem_path):
        return send_file(pem_path, as_attachment=True, download_name="squid-ca.crt", mimetype="application/x-x509-ca-cert")
    return jsonify({"error": "Certificate not found on proxy server"}), 404


@app.route("/download/cert.pem")
def download_cert_pem():
    """Public endpoint to download Root CA certificate in PEM format (.pem) for Linux."""
    pem_path = os.path.join(SQUID_CERT_DIR, "squid-ca.pem")
    if os.path.exists(pem_path):
        return send_file(pem_path, as_attachment=True, download_name="squid-ca.pem", mimetype="application/x-pem-file")
    return jsonify({"error": "Certificate not found on proxy server"}), 404


@app.route("/download/install-ubuntu.sh")
def download_ubuntu_script():
    """Public automated installation script for Ubuntu Linux clients."""
    host = request.host
    script = f"""#!/bin/bash
set -e
echo "========================================================="
echo "   Squid Proxy CA Certificate & System Installer (Ubuntu)"
echo "========================================================="

CERT_URL="http://{host}/download/cert.pem"
PROXY_URL="http://192.168.1.90:3128"

echo "[*] Downloading Root CA Certificate..."
sudo wget -q -O /usr/local/share/ca-certificates/squid-proxy-ca.crt "$CERT_URL"

echo "[*] Updating System Trust Store..."
sudo update-ca-certificates

if command -v certutil > /dev/null 2>&1; then
    echo "[*] Importing into Chrome/NSS Certificate Database..."
    for user_home in /root /home/*; do
        if [ -d "$user_home/.pki/nssdb" ]; then
            sudo certutil -d "sql:$user_home/.pki/nssdb" -A -t "CT,C,C" -n "squid.local" -i /usr/local/share/ca-certificates/squid-proxy-ca.crt 2>/dev/null || true
        fi
    done
fi

echo "[*] Cleaning up any old static proxy profiles (Transparent Routing active)..."
sudo rm -f /etc/profile.d/squid-proxy.sh

echo "========================================================="
echo "   [+] Installation Complete! HTTPS traffic is now trusted."
echo "========================================================="
"""
    return script, 200, {"Content-Type": "text/plain; charset=utf-8"}


# --- STARTUP LOGIC & BACKGROUND TASKS ---

def daily_expiration_task():
    """Background thread to auto-expire 'Today Only' rules at midnight."""
    while True:
        time.sleep(3600)  # Check every hour
        try:
            policies = load_device_policies()
            changed = False
            current_today = today_str()
            
            for ip, policy in policies.items():
                for entry in policy.get("default_block", []):
                    if entry.get("today_date") and entry["today_date"] != current_today:
                        changed = True
                        break
                if changed:
                    break
            
            if changed:
                print("Daily expiration triggered: Cleaning up stale 'Today Only' rules.")
                # This will automatically clear stale today_date entries during ensure_policy_schema
                save_device_policies(policies)
        except Exception as e:
            print(f"Error in daily_expiration_task: {e}")

# Compile on startup to ensure rules.acl is always generated correctly
try:
    initial_policies = load_device_policies()
    compile_device_policies_acls(initial_policies)
except Exception as e:
    print(f"Startup compilation failed: {e}")

expiration_thread = threading.Thread(target=daily_expiration_task, daemon=True)
expiration_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3131, debug=False)
