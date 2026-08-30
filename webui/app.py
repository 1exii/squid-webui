import os
import json
import copy
import secrets
import threading
import time
import socket
import http.client
from datetime import date, datetime, timedelta
import paramiko
from passlib.hash import md5_crypt, sha512_crypt, sha256_crypt, des_crypt
from flask import Flask, render_template, request, jsonify, session, send_file
from config_audit import (
    append_audit_record,
    combine_audit_records,
    make_audit_record,
    policy_changes,
    read_audit_records,
)
from activity_reports import (
    load_overall_report,
    load_period_report,
    load_report,
    load_reports,
    overall_report_exists,
    period_report_exists,
    prune_overall_reports,
    prune_period_reports,
    prune_reports,
    report_exists,
    save_overall_report,
    save_period_reports,
    save_reports,
)
from overall_analytics import (
    aggregate_overall_reports,
    build_daily_overall_archive,
)
from traffic_analytics import (
    activity_period_bounds,
    aggregate_activity_archive,
    aggregate_activity_reports,
    build_daily_activity,
    build_daily_activity_archive,
    empty_daily_activity,
)

app = Flask(__name__)

# Configuration paths (inside container / host)
SQUID_CONFIG_DIR = os.environ.get("SQUID_CONFIG_DIR", "/etc/squid/configs")
SQUID_BLOCKLIST_DIR = os.environ.get("SQUID_BLOCKLIST_DIR", "/etc/squid/block-lists")
SQUID_CERT_DIR = os.environ.get("SQUID_CERT_DIR", "/etc/squid/certs")
ROUTER_HOSTS_CONF = os.environ.get("ROUTER_HOSTS_CONF", "/etc/squid/router/proxy-hosts.conf")
SQUID_ACCESS_LOG = os.environ.get("SQUID_ACCESS_LOG", "/var/log/squid/access.log")
SQUID_ACTIVITY_REPORT_DIR = os.environ.get(
    "SQUID_ACTIVITY_REPORT_DIR", os.path.join(SQUID_CONFIG_DIR, "activity-reports")
)
SQUID_AUDIT_LOG = os.environ.get(
    "SQUID_AUDIT_LOG", os.path.join(SQUID_CONFIG_DIR, "configuration_audit.jsonl")
)
ACTIVITY_RETENTION_DAYS = 365
ACTIVITY_LOG_BACKFILL_DAYS = 30

RULES_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "rules.acl")
SSL_BUMP_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "ssl_bump.acl")
# Domain list requiring SSL bumping for deep URL path inspection (data file).
BUMP_DOMAINS_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "bump_domains.acl")
# Squid directives that reference the list above. Generated alongside it so that
# when NO blocklist defines a URL path rule this file is empty, instead of
# leaving squid.conf with an `acl ... dstdomain "<empty file>"` that parses fine
# but can never match — a silently dead rule.
BUMP_DOMAINS_CONF_PATH = os.path.join(SQUID_CONFIG_DIR, "bump_domains.conf")

QNAP_IP = os.environ.get("QNAP_IP", "127.0.0.1")
SQUID_CONTAINER_NAME = os.environ.get("SQUID_CONTAINER_NAME", "squid-proxy")
SQUID_PROXY_HOST = os.environ.get("SQUID_PROXY_HOST", "127.0.0.1")
SQUID_PROXY_PORT = int(os.environ.get("SQUID_PROXY_PORT", "3128"))
WEBUI_PUBLIC_URL = os.environ.get("WEBUI_PUBLIC_URL", "http://127.0.0.1:3131").rstrip("/")
PAC_URL = f"{WEBUI_PUBLIC_URL}/proxy.pac"
CERT_NAME = os.environ.get("CERT_NAME", "squid.local")


def _load_or_create_secret_key():
    """
    Return a Flask secret key that is stable across gunicorn workers and restarts.

    Generating the key at import time gives every worker process a DIFFERENT key,
    so a session cookie set by worker 1 is rejected by worker 2 and logins fail
    intermittently. Prefer the environment, then a key persisted on the shared
    config volume, and only fall back to an ephemeral key if neither works.
    """
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key

    key_path = os.path.join(SQUID_CONFIG_DIR, ".flask_secret_key")
    try:
        if os.path.exists(key_path):
            with open(key_path, "r") as f:
                existing = f.read().strip()
            if existing:
                return existing

        os.makedirs(SQUID_CONFIG_DIR, exist_ok=True)
        key = secrets.token_hex(32)
        # Write atomically so a concurrently starting worker cannot read a
        # half-written key, then re-read to settle races on who wrote first.
        tmp_path = f"{key_path}.{os.getpid()}.tmp"
        with open(tmp_path, "w") as f:
            f.write(key)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, key_path)
        with open(key_path, "r") as f:
            return f.read().strip() or key
    except Exception as e:
        print(f"[secret_key] Could not persist Flask secret key ({e}); using an "
              f"ephemeral key. Sessions will not survive a restart.")
        return secrets.token_hex(32)


app.secret_key = _load_or_create_secret_key()

# Serialises ACL compilation + reload. Guards against two requests (or the
# background expiry thread) interleaving writes to rules.acl / ssl_bump.acl.
COMPILE_LOCK = threading.Lock()
ACTIVITY_REPORT_LOCK = threading.Lock()

# IPs that get the Admin page as the default landing page are deployment data.
# An empty value requires authentication for every client.
ADMIN_CLIENT_IPS = {
    value.strip()
    for value in os.environ.get("ADMIN_CLIENT_IPS", "").split(",")
    if value.strip()
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


def get_client_ip():
    """Return the peer IP used for trusted-admin access decisions.

    The Web UI is exposed directly on its macvlan address, so accepting a
    client-supplied X-Forwarded-For header here would let any LAN client spoof
    an allowlisted address and bypass authentication.
    """
    return request.remote_addr or ""


def is_admin_client():
    """Whether this request comes from a password-exempt admin workstation."""
    return get_client_ip() in ADMIN_CLIENT_IPS


def is_authenticated():
    """Allow trusted admin workstations or a password-authenticated session."""
    return is_admin_client() or session.get("authenticated", False)


def request_audit_actor():
    """Identify the authenticated user or trusted workstation making a change."""
    username = session.get("username", "")
    if username:
        auth_method = "nas_session"
        display_name = username
    else:
        auth_method = "trusted_admin_client"
        display_name = "Trusted admin client"
    return {
        "display_name": display_name,
        "username": username,
        "client_ip": get_client_ip(),
        "authentication": auth_method,
    }


def record_policy_change(before, after, actor, source, success, message):
    """Persist an audit event when a policy save made a semantic change."""
    changes = policy_changes(before, after)
    if not changes:
        return False
    record = make_audit_record(actor, source, changes, success, message)
    append_audit_record(SQUID_AUDIT_LOG, record)
    return True



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
        "ssl_bump_mode": legacy.get("ssl_bump_mode", "blocked_only"),
        "always_block": legacy.get("blocklists", []),
        "always_allow": [],
        "default_block": []
    }


def ensure_policy_schema(policy):
    """Ensure a policy dict has the current schema fields, migrating if necessary."""
    # Detect legacy flat format (has 'blocklists' key but not 'always_block')
    if "blocklists" in policy and "always_block" not in policy:
        policy = migrate_legacy_policy(policy)

    policy.setdefault("ssl_bump_mode", "blocked_only")
    policy.setdefault("always_block", [])
    policy.setdefault("always_allow", [])
    policy.setdefault("default_block", [])
    for field in ("always_block", "always_allow", "default_block"):
        if not isinstance(policy[field], list):
            policy[field] = []

    # Always Block has highest precedence if malformed/external input places a
    # category in both explicit sets.
    policy["always_block"] = list(dict.fromkeys(
        item for item in policy["always_block"] if isinstance(item, str)
    ))
    blocked = set(policy["always_block"])
    policy["always_allow"] = list(dict.fromkeys(
        item for item in policy["always_allow"]
        if isinstance(item, str) and item not in blocked
    ))
    explicit = blocked | set(policy["always_allow"])

    repaired = []
    for entry in policy["default_block"]:
        if (not isinstance(entry, dict) or "list" not in entry or
                entry["list"] in explicit):
            continue
        entry.setdefault("unblock_weekly", make_empty_weekly())
        entry.setdefault("unblock_today", make_empty_today())
        entry.setdefault("today_date", "")
        # Auto-clear today overrides if date has changed
        if entry["today_date"] != today_str():
            entry["unblock_today"] = make_empty_today()
            entry["today_date"] = today_str()
        # Ensure correct dimensions
        if (not isinstance(entry["unblock_weekly"], list) or
                len(entry["unblock_weekly"]) != 7):
            entry["unblock_weekly"] = make_empty_weekly()
        for d in range(7):
            if (not isinstance(entry["unblock_weekly"][d], list) or
                    len(entry["unblock_weekly"][d]) != 48):
                entry["unblock_weekly"][d] = [False] * 48
        if (not isinstance(entry["unblock_today"], list) or
                len(entry["unblock_today"]) != 48):
            entry["unblock_today"] = make_empty_today()
        repaired.append(entry)
    policy["default_block"] = repaired
    return policy


def list_blocklist_files():
    """Return available blocklist filenames, or None when the directory is unavailable."""
    if not os.path.isdir(SQUID_BLOCKLIST_DIR):
        return None
    try:
        return sorted(
            filename for filename in os.listdir(SQUID_BLOCKLIST_DIR)
            if filename.endswith(".txt")
        )
    except OSError as e:
        print(f"Error listing blocklists for policy synchronization: {e}")
        return None


def synchronize_default_block(policy, blocklist_names):
    """Materialize Default Block as the complement of the two explicit sets.

    Existing timetable entries are retained. Newly discovered/unclassified
    blocklists start blocked at all times until an unblock window is configured.
    """
    policy = ensure_policy_schema(policy)
    if blocklist_names is None:
        return policy

    explicit = set(policy["always_block"]) | set(policy["always_allow"])
    existing = {entry["list"]: entry for entry in policy["default_block"]}
    synchronized = []
    for list_name in blocklist_names:
        if list_name in explicit:
            continue
        entry = existing.get(list_name, {
            "list": list_name,
            "unblock_weekly": make_empty_weekly(),
            "unblock_today": make_empty_today(),
            "today_date": today_str(),
        })
        synchronized.append(entry)
    policy["default_block"] = synchronized
    return ensure_policy_schema(policy)


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
            blocklist_names = list_blocklist_files()
            for ip, pol in raw.items():
                migrated[ip] = synchronize_default_block(pol, blocklist_names)
            return migrated
        except Exception as e:
            print(f"Error loading device_policies.json: {e}")
    return {}


def save_device_policies(policies):
    """Persist policies to disk and recompile the Squid ACLs. Returns (ok, message)."""
    os.makedirs(os.path.dirname(DEVICE_POLICIES_PATH), exist_ok=True)
    blocklist_names = list_blocklist_files()
    for ip in policies:
        policies[ip] = synchronize_default_block(policies[ip], blocklist_names)
    # Write atomically so a crash mid-write cannot leave unparseable JSON behind,
    # which load_device_policies() would silently swallow as "no policies at all".
    tmp_path = f"{DEVICE_POLICIES_PATH}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(policies, f, indent=2)
    os.replace(tmp_path, DEVICE_POLICIES_PATH)
    return compile_device_policies_acls(policies)


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


def ere_escape(text):
    """
    Escape a literal string for use in a Squid POSIX ERE (urlpath_regex).

    re.escape() is NOT safe here: it emits Python-flavoured escapes such as '\\-'
    and '\\ ', which are undefined sequences in POSIX ERE and behave
    inconsistently across Squid's regex backends. Only the characters that are
    actually special in ERE are escaped.
    """
    special = set('.^$*+?()[]{}|\\')
    return "".join("\\" + c if c in special else c for c in text)


def collect_path_rule_domains(parsed_blocklists):
    """
    Return the sorted set of '.domain' entries that require SSL bumping because a
    blocklist defines a deep URL path rule for them (e.g. 'steamcommunity.com/market').
    Derived from the SAME parse used to build the ACLs, so the two can never drift.
    """
    bump = set()
    for meta in parsed_blocklists.values():
        for rule in meta.get("path_rules", []):
            bump.add(rule["bump_domain"])
    return deduplicate_domains(bump)


def write_bump_domains(parsed_blocklists):
    """
    Regenerate bump_domains.acl (the data file) and bump_domains.conf (the Squid
    directives that use it).

    Previously bump_domains.acl was only produced by docker-entrypoint.sh at
    container start, so any blocklist edit made through the Web UI left it stale
    until the next restart. Regenerating it on every compile keeps selective
    bumping in step with the blocklists.
    """
    domains = collect_path_rule_domains(parsed_blocklists)

    os.makedirs(SQUID_CONFIG_DIR, exist_ok=True)
    with open(BUMP_DOMAINS_ACL_PATH, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: domains requiring SSL Bumping for deep URL path rules.\n")
        f.write("# Source: block-lists/*.txt entries of the form 'domain/path'.\n")
        for d in domains:
            f.write(f"{d}\n")

    with open(BUMP_DOMAINS_CONF_PATH, "w", encoding="utf-8") as f:
        f.write("# Auto-generated Squid directives for deep URL path SSL bumping.\n")
        if domains:
            f.write(f'acl bump_domains dstdomain "{BUMP_DOMAINS_ACL_PATH}"\n')
            f.write("ssl_bump bump bump_domains\n")
        else:
            f.write("# No blocklist defines a 'domain/path' rule, so no global bump\n")
            f.write("# ACL is emitted. Declaring one against an empty file would\n")
            f.write("# parse cleanly but never match.\n")

    print(f"[bump_domains] Wrote {len(domains)} bump domain(s).")
    return domains


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


def _build_policy_acls(policies, parsed_blocklists):
    """
    Render device policies into the text of rules.acl and ssl_bump.acl.
    - always_block lists  → unconditional http_access deny (domain + path rules)
    - always_allow lists  → unconditional allow ahead of scheduled defaults
    - default_block lists → allow windows + fallback deny (domain + path rules)
    - ssl_bump.acl        → per-device dynamic SSL bump rules (blocked sites or full device bump)
    Returns (rules_acl_text, ssl_bump_acl_text).
    """

    acl_lines = [
        "# ===========================================================",
        "# AUTO-GENERATED BY SQUID WEB UI - DEVICE POLICIES",
        "# ===========================================================",
        ""
    ]

    ssl_bump_lines = [
        "# ===========================================================",
        "# AUTO-GENERATED BY SQUID WEB UI - DYNAMIC SSL BUMP RULES",
        "# ===========================================================",
        ""
    ]

    declared_blocklists = set()
    declared_path_rules = set()

    for ip, policy in policies.items():
        # Compilation is a second enforcement boundary: callers that bypass the
        # persistence helpers still get the automatic Default Block complement.
        policy = synchronize_default_block(policy, sorted(parsed_blocklists))
        hostname = policy.get("hostname", ip)
        always_block = policy.get("always_block", [])
        always_allow = policy.get("always_allow", [])
        default_block = policy.get("default_block", [])
        ssl_bump_mode = policy.get("ssl_bump_mode", "blocked_only")

        if not always_block and not always_allow and not default_block:
            continue

        clean_ip_id = ip.replace(".", "_")
        src_acl_name = f"src_dev_{clean_ip_id}"

        # ------------------------------------------------------------------
        # CONNECT scoping — this is what makes the HTTPS block page render.
        #
        # For an intercepted TLS connection Squid peeks the ClientHello, builds a
        # synthetic "CONNECT host:443" request, and runs http_access on it BEFORE
        # consulting ssl_bump. A plain 'http_access deny <src> <list>' therefore
        # matches at the CONNECT stage and Squid writes the ERR_ACCESS_DENIED HTML
        # in cleartext onto a socket where the client is still waiting for a
        # ServerHello. The browser sees a protocol error, not the block page — and
        # the 'ssl_bump bump' rule never runs at all.
        #
        # Restricting the deny to '!CONNECT' lets the tunnel be established and
        # bumped; the decrypted inner GET then matches the same deny and the block
        # page is delivered inside the TLS session, where the browser can render it.
        #
        # This is ONLY safe when the connection is guaranteed to be bumped —
        # otherwise the CONNECT would fall through to 'http_access allow localnet'
        # and the site would be fully reachable. ssl_bump.acl below bumps exactly
        # 'src_dev + list' in blocked_only mode and the whole device in all mode,
        # so those two modes qualify. Any other mode keeps the CONNECT-level deny:
        # the user gets a connection error rather than a page, but access is denied.
        bump_guaranteed = ssl_bump_mode in ("all", "blocked_only")
        deny_scope = "!CONNECT " if bump_guaranteed else ""

        acl_lines.append(f"# ── Device: {hostname} ({ip}) ──")
        acl_lines.append(f"acl {src_acl_name} src {ip}")
        if not bump_guaranteed:
            acl_lines.append(
                f"# NOTE: ssl_bump_mode='{ssl_bump_mode}' — HTTPS is denied at the CONNECT"
            )
            acl_lines.append(
                "#       stage, so blocked sites fail with a TLS error instead of the block page."
            )
        acl_lines.append("")

        ssl_bump_lines.append(f"# ── Device SSL Bump: {hostname} ({ip}) [Mode: {ssl_bump_mode}] ──")

        # Declare all blocklist domain and path ACLs once
        all_lists = (list(always_block) + list(always_allow) +
                     [e["list"] for e in default_block if "list" in e])
        for bl in all_lists:
            bl_id = bl.replace('.', '_').replace('-', '_')
            bl_acl_name = f"list_{bl_id}"
            sni_bl_acl_name = f"sni_list_{bl_id}"

            if bl_acl_name not in declared_blocklists:
                if bl in parsed_blocklists:
                    dom_file = parsed_blocklists[bl]["domain_acl_file"]
                else:
                    dom_file = os.path.join(SQUID_BLOCKLIST_DIR, bl)
                acl_lines.append(f"acl {bl_acl_name} dstdomain \"{dom_file}\"")
                declared_blocklists.add(bl_acl_name)

                # A transparently intercepted TLS connection initially exposes
                # its original destination IP, not a CONNECT hostname. Match the
                # ClientHello SNI for ssl_bump decisions; keep dstdomain above for
                # decrypted HTTP requests and explicit-proxy CONNECT requests.
                acl_lines.append(f"acl {sni_bl_acl_name} ssl::server_name \"{dom_file}\"")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx, rule in enumerate(path_rules, 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        p_sni_acl = f"sni_path_dom_{bl_id}_{idx}"
                        p_url_acl = f"path_url_{bl_id}_{idx}"
                        if p_dom_acl not in declared_path_rules:
                            acl_lines.append(f"acl {p_dom_acl} dstdomain {rule['bump_domain']}")
                            acl_lines.append(f"acl {p_sni_acl} ssl::server_name {rule['bump_domain']}")
                            acl_lines.append(f"acl {p_url_acl} urlpath_regex -i ^{ere_escape(rule['path'])}")
                            declared_path_rules.add(p_dom_acl)
        acl_lines.append("")

        # Dynamic SSL Bumping Rules for this device
        if ssl_bump_mode == "all":
            # Bump all HTTPS traffic for this specific device
            ssl_bump_lines.append(f"ssl_bump bump {src_acl_name}")
        elif ssl_bump_mode == "blocked_only":
            # Always-blocked categories are bumped unconditionally so Squid can
            # render the HTTPS block page after decrypting the inner request.
            for bl in always_block:
                bl_id = bl.replace('.', '_').replace('-', '_')
                sni_bl_acl_name = f"sni_list_{bl_id}"
                ssl_bump_lines.append(f"ssl_bump bump {src_acl_name} {sni_bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_sni_acl = f"sni_path_dom_{bl_id}_{idx}"
                        ssl_bump_lines.append(f"ssl_bump bump {src_acl_name} {p_sni_acl}")

            # Always Allow is evaluated after Always Block (which retains highest
            # precedence) but before scheduled defaults. Splicing here prevents
            # an overlapping default category from unnecessarily decrypting an
            # explicitly allowed destination.
            for bl in always_allow:
                bl_id = bl.replace('.', '_').replace('-', '_')
                sni_bl_acl_name = f"sni_list_{bl_id}"
                ssl_bump_lines.append(f"ssl_bump splice {src_acl_name} {sni_bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_sni_acl = f"sni_path_dom_{bl_id}_{idx}"
                        ssl_bump_lines.append(f"ssl_bump splice {src_acl_name} {p_sni_acl}")

            # A scheduled category must use native end-to-end TLS while it is
            # allowed. Merely adding an http_access allow still leaves the stream
            # bumped, which breaks transports such as YouTube's googlevideo UMP
            # playback. Splice the category during each allow window, then retain
            # the unconditional fallback bump so it can be blocked outside them.
            bump_time_acl_idx = 0
            for entry in default_block:
                bl = entry.get("list", "")
                if not bl:
                    continue
                bl_id = bl.replace('.', '_').replace('-', '_')
                sni_bl_acl_name = f"sni_list_{bl_id}"
                unblock_weekly = entry.get("unblock_weekly", make_empty_weekly())
                unblock_today = entry.get("unblock_today", make_empty_today())
                merged = merge_today_into_weekly(unblock_weekly, unblock_today)
                allow_ranges = extract_allow_ranges(merged)

                for _range_key in allow_ranges:
                    time_acl_name = f"time_allow_{clean_ip_id}_{bump_time_acl_idx}"
                    ssl_bump_lines.append(
                        f"ssl_bump splice {src_acl_name} {sni_bl_acl_name} {time_acl_name}"
                    )
                    if bl in parsed_blocklists:
                        path_rules = parsed_blocklists[bl].get("path_rules", [])
                        for idx in range(1, len(path_rules) + 1):
                            p_sni_acl = f"sni_path_dom_{bl_id}_{idx}"
                            ssl_bump_lines.append(
                                f"ssl_bump splice {src_acl_name} {p_sni_acl} {time_acl_name}"
                            )
                    bump_time_acl_idx += 1

                ssl_bump_lines.append(f"ssl_bump bump {src_acl_name} {sni_bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_sni_acl = f"sni_path_dom_{bl_id}_{idx}"
                        ssl_bump_lines.append(f"ssl_bump bump {src_acl_name} {p_sni_acl}")
        # Note: If ssl_bump_mode == "splice_all" / "none", no bump rules are added so traffic falls through to splice all.
        ssl_bump_lines.append("")

        # Section A: Always Block
        if always_block:
            acl_lines.append(f"  # Always Block — {hostname}")
            for bl in always_block:
                bl_id = bl.replace('.', '_').replace('-', '_')
                bl_acl_name = f"list_{bl_id}"
                acl_lines.append(f"http_access deny {deny_scope}{src_acl_name} {bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        p_url_acl = f"path_url_{bl_id}_{idx}"
                        # urlpath_regex can never match a CONNECT (no path component),
                        # so these are inherently post-decryption rules already.
                        acl_lines.append(f"http_access deny {src_acl_name} {p_dom_acl} {p_url_acl}")
            acl_lines.append("")

        # Section B: Always Allow. Always Block is emitted first intentionally,
        # so it wins if blocklist contents overlap across categories.
        if always_allow:
            acl_lines.append(f"  # Always Allow — {hostname}")
            for bl in always_allow:
                bl_id = bl.replace('.', '_').replace('-', '_')
                bl_acl_name = f"list_{bl_id}"
                acl_lines.append(f"http_access allow {src_acl_name} {bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        p_url_acl = f"path_url_{bl_id}_{idx}"
                        acl_lines.append(f"http_access allow {src_acl_name} {p_dom_acl} {p_url_acl}")
            acl_lines.append("")

        # Section C: Default Block with unblock windows
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
            acl_lines.append(f"http_access deny {deny_scope}{src_acl_name} {bl_acl_name}")
            if bl in parsed_blocklists:
                path_rules = parsed_blocklists[bl].get("path_rules", [])
                for idx in range(1, len(path_rules) + 1):
                    p_dom_acl = f"path_dom_{bl_id}_{idx}"
                    p_url_acl = f"path_url_{bl_id}_{idx}"
                    acl_lines.append(f"http_access deny {src_acl_name} {p_dom_acl} {p_url_acl}")
            acl_lines.append("")

        acl_lines.append("")

    return "\n".join(acl_lines) + "\n", "\n".join(ssl_bump_lines) + "\n"


def compile_device_policies_acls(policies):
    """
    Regenerate every managed Squid config file from the device policies, then
    validate and reload. On a validation failure the previous configuration is
    restored and Squid is never signalled.

    Returns (ok, message).
    """
    with COMPILE_LOCK:
        snap = snapshot_configs()
        try:
            parsed_blocklists = get_parsed_blocklists()

            # Keep the bump list in step with the blocklists on every compile,
            # not just at container start.
            write_bump_domains(parsed_blocklists)

            rules_text, ssl_text = _build_policy_acls(policies, parsed_blocklists)

            os.makedirs(SQUID_CONFIG_DIR, exist_ok=True)
            with open(RULES_ACL_PATH, "w") as f:
                f.write(rules_text)
            with open(SSL_BUMP_ACL_PATH, "w") as f:
                f.write(ssl_text)
        except Exception as e:
            restore_configs(snap)
            msg = f"ACL generation failed, previous configuration restored: {e}"
            print(f"[compile] {msg}")
            return False, msg

        ok, detail = reload_squid()
        if not ok:
            restore_configs(snap)
            # Best effort: put Squid back on the known-good config.
            reload_squid()
            return False, detail
        return True, "Squid rules applied and service reloaded successfully."


# NOTE: the legacy rules.json engine (load_rules / save_rules / compile_squid_acls
# and the /api/rules endpoints) has been removed. It wrote the SAME rules.acl and
# ssl_bump.acl files as compile_device_policies_acls(), so a single call to
# /api/rules silently erased every per-device parental-control policy. The Web UI
# never used it — device policies are the only supported rule engine.


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


def _demux_docker_stream(raw):
    """
    Strip Docker's 8-byte stream-multiplexing frame headers from exec output.
    Falls back to a best-effort decode when the stream is not multiplexed.
    """
    out = bytearray()
    i = 0
    try:
        while i + 8 <= len(raw):
            stream_type = raw[i]
            if stream_type not in (0, 1, 2):
                # Not a framed stream — return the payload as-is.
                return raw.decode("utf-8", "replace")
            length = int.from_bytes(raw[i + 4:i + 8], "big")
            out += raw[i + 8:i + 8 + length]
            i += 8 + length
        return bytes(out).decode("utf-8", "replace")
    except Exception:
        return raw.decode("utf-8", "replace")


def docker_exec(cmd):
    """
    Run a command inside the Squid container via the Docker exec API.
    Returns (exit_code, output). exit_code is None when the call itself failed.
    """
    try:
        status, data = docker_socket_request(
            "POST",
            f"/containers/{SQUID_CONTAINER_NAME}/exec",
            {"AttachStdout": True, "AttachStderr": True, "Tty": False, "Cmd": cmd},
        )
        if status not in (200, 201):
            return None, f"exec create failed: HTTP {status} {data.decode('utf-8', 'replace')}"

        exec_id = json.loads(data.decode()).get("Id")
        if not exec_id:
            return None, "exec create returned no Id"

        status, out = docker_socket_request(
            "POST", f"/exec/{exec_id}/start", {"Detach": False, "Tty": False}
        )
        text = _demux_docker_stream(out)

        status, info = docker_socket_request("GET", f"/exec/{exec_id}/json")
        exit_code = json.loads(info.decode()).get("ExitCode") if status == 200 else None
        return exit_code, text
    except Exception as e:
        return None, f"exec failed: {e}"


def validate_squid_config():
    """
    Run 'squid -k parse' inside the container.
    Returns (ok, message). ok is True only on a clean parse.

    Validation is advisory when the exec API itself is unavailable: we do not
    want an unreachable Docker socket to block every policy save. It is NOT
    advisory when the parser actually reports a problem.
    """
    exit_code, output = docker_exec(["squid", "-k", "parse"])

    if exit_code is None:
        return True, f"config validation skipped (could not run squid -k parse: {output.strip()[:200]})"

    fatal_lines = [
        ln for ln in output.splitlines()
        if any(tok in ln.upper() for tok in ("FATAL", "BUNGLED", "ERROR:"))
    ]
    if exit_code != 0 or fatal_lines:
        detail = " | ".join(fatal_lines[:5]) or f"exit code {exit_code}"
        return False, detail

    empty_acls = [ln for ln in output.splitlines() if "empty ACL" in ln]
    if empty_acls:
        # Not fatal to Squid, but it means a block rule can never match.
        print(f"[validate] WARNING — empty ACL(s) detected: {' | '.join(empty_acls[:5])}")
    return True, "ok"


# Files rewritten on every compile; all are snapshotted so a bad generation can
# be rolled back before Squid is ever asked to load it.
_MANAGED_CONFIG_FILES = (
    RULES_ACL_PATH,
    SSL_BUMP_ACL_PATH,
    BUMP_DOMAINS_ACL_PATH,
    BUMP_DOMAINS_CONF_PATH,
)


def snapshot_configs():
    """Read the current managed config files so they can be restored on failure."""
    snap = {}
    for path in _MANAGED_CONFIG_FILES:
        try:
            with open(path, "r", encoding="utf-8") as f:
                snap[path] = f.read()
        except FileNotFoundError:
            snap[path] = None
        except Exception as e:
            print(f"[snapshot] Could not read {path}: {e}")
    return snap


def restore_configs(snap):
    """
    Roll the managed config files back to a previous snapshot.

    A file that did not exist before is truncated rather than skipped: squid.conf
    `include`s all of them, so leaving a rejected generation on disk would let it
    load on the next container restart, bypassing validation entirely.
    """
    for path, content in snap.items():
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content if content is not None else
                        "# Reverted: this generation failed validation.\n")
        except Exception as e:
            print(f"[restore] Could not restore {path}: {e}")


def reload_squid():
    """
    Validate the generated configuration, then reload Squid via SIGHUP.

    Squid is the default route for HTTP/HTTPS on every intercepted host, so a
    reload that kills it takes those devices offline entirely. Never send the
    signal without checking that the config parses first. Returns (ok, message).
    """
    valid, detail = validate_squid_config()
    if not valid:
        msg = f"Refusing to reload Squid — generated configuration is invalid: {detail}"
        print(f"[reload] {msg}")
        return False, msg

    try:
        status, data = docker_socket_request(
            "POST", f"/containers/{SQUID_CONTAINER_NAME}/kill?signal=HUP"
        )
        if status in (200, 204):
            print(f"[reload] Squid container '{SQUID_CONTAINER_NAME}' reloaded via SIGHUP.")
            return True, "reloaded"
        msg = f"Failed to send SIGHUP to Squid: HTTP {status} {data.decode('utf-8', 'replace')}"
        print(f"[reload] {msg}")
        return False, msg
    except Exception as e:
        msg = f"Failed to reload Squid via Docker socket: {e}"
        print(f"[reload] {msg}")
        return False, msg


# --- API ENDPOINTS ---

@app.route("/", defaults={"admin_requested": False})
@app.route("/admin", defaults={"admin_requested": True})
def index(admin_requested):
    # On the public landing page, do not render any discoverable admin UI for
    # ordinary clients. /admin is the explicit opt-in entry point for them.
    admin_visible = is_admin_client() or admin_requested
    return render_template(
        "index.html",
        admin_visible=admin_visible,
        admin_requested=admin_requested,
        activity_retention_days=ACTIVITY_RETENTION_DAYS,
        pac_url=PAC_URL,
        webui_public_url=WEBUI_PUBLIC_URL,
        squid_proxy_host=SQUID_PROXY_HOST,
        squid_proxy_port=SQUID_PROXY_PORT,
        cert_name=CERT_NAME,
    )


@app.route("/blocked")
def blocked():
    domain = request.args.get("domain", "Unknown Webpage")
    client_ip = get_client_ip()
    return render_template("blocked.html", domain=domain, client_ip=client_ip)


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    client_ip = get_client_ip()
    admin_client = is_admin_client()
    return jsonify({
        "authenticated": is_authenticated(),
        "user": session.get("username", "") or ("Trusted admin client" if admin_client else ""),
        "client_ip": client_ip,
        "is_admin_client": admin_client,
        "password_required": not admin_client,
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


def _activity_dates(period_start, period_end):
    return [
        period_start + timedelta(days=offset)
        for offset in range((period_end - period_start).days + 1)
    ]


def _load_or_generate_daily_reports(target_dates):
    """Load saved days and backfill missing dates still available in Squid logs."""
    today = date.today()
    reports_by_date = {}
    missing = []
    generated = False

    for target_date in target_dates:
        if target_date == today:
            if not os.path.isfile(SQUID_ACCESS_LOG):
                continue
            live = build_daily_activity_archive(
                SQUID_ACCESS_LOG, SQUID_BLOCKLIST_DIR, [target_date]
            )
            reports_by_date[target_date.isoformat()] = live.get(
                target_date.isoformat(), {}
            )
            continue

        found, reports = load_reports(SQUID_ACTIVITY_REPORT_DIR, target_date)
        if found:
            reports_by_date[target_date.isoformat()] = reports
        elif target_date >= today - timedelta(days=ACTIVITY_LOG_BACKFILL_DAYS):
            missing.append(target_date)

    if missing and os.path.isfile(SQUID_ACCESS_LOG):
        archive = build_daily_activity_archive(
            SQUID_ACCESS_LOG, SQUID_BLOCKLIST_DIR, missing
        )
        for target_date in missing:
            reports = archive.get(target_date.isoformat(), {})
            save_reports(SQUID_ACTIVITY_REPORT_DIR, target_date, reports)
            reports_by_date[target_date.isoformat()] = reports
        generated = True

    unavailable = [
        target_date.isoformat()
        for target_date in target_dates
        if target_date.isoformat() not in reports_by_date
    ]
    return reports_by_date, unavailable, generated


@app.route("/api/activity", methods=["GET"])
def get_activity():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    date_value = request.args.get("date", today_str()).strip()
    period = request.args.get("period", "day").strip().lower()
    client_ip = request.args.get("client_ip", "").strip()
    try:
        target_date = datetime.strptime(date_value, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "date must use YYYY-MM-DD format"}), 400

    if period not in ("day", "week", "month"):
        return jsonify({"error": "period must be day, week, or month"}), 400

    if (target_date > date.today() or
            target_date < date.today() - timedelta(days=ACTIVITY_RETENTION_DAYS - 1)):
        return jsonify({
            "error": f"date must be within the last {ACTIVITY_RETENTION_DAYS} days"
        }), 400
    if client_ip:
        try:
            socket.inet_pton(socket.AF_INET, client_ip)
        except OSError:
            return jsonify({"error": "client_ip must be a valid IPv4 address"}), 400
    try:
        if period != "day":
            natural_start, natural_end = activity_period_bounds(period, target_date)
            period_start = max(
                natural_start,
                date.today() - timedelta(days=ACTIVITY_RETENTION_DAYS - 1),
            )
            period_end = min(natural_end, date.today())
            can_cache_period = (
                period_start == natural_start and
                period_end == natural_end and
                period_end < date.today()
            )

            with ACTIVITY_REPORT_LOCK:
                if can_cache_period:
                    cache_found, report = load_period_report(
                        SQUID_ACTIVITY_REPORT_DIR,
                        period,
                        period_start,
                        period_end,
                        client_ip,
                    )
                    if cache_found:
                        if report is None:
                            empty_days = {
                                day.isoformat(): {}
                                for day in _activity_dates(period_start, period_end)
                            }
                            report = aggregate_activity_reports(
                                empty_days, period, period_start, period_end, client_ip
                            )
                        report["report_source"] = "saved"
                        report["coverage_complete"] = True
                        return jsonify(report)

                target_dates = _activity_dates(period_start, period_end)
                daily_reports, unavailable, generated = (
                    _load_or_generate_daily_reports(target_dates)
                )
                result = aggregate_activity_reports(
                    daily_reports, period, period_start, period_end, client_ip
                )
                result["coverage_complete"] = not unavailable
                result["unavailable_days"] = len(unavailable)
                if period_end == date.today():
                    result["report_source"] = "live"
                else:
                    result["report_source"] = "generated" if generated else "saved-daily"

                if can_cache_period and not unavailable:
                    period_reports = aggregate_activity_archive(
                        daily_reports, period, period_start, period_end
                    )
                    save_period_reports(
                        SQUID_ACTIVITY_REPORT_DIR,
                        period,
                        period_start,
                        period_end,
                        period_reports,
                    )
                    result["report_source"] = "generated"
                return jsonify(result)

        if target_date < date.today():
            with ACTIVITY_REPORT_LOCK:
                cache_found, report = load_report(
                    SQUID_ACTIVITY_REPORT_DIR, target_date, client_ip
                )
                if cache_found:
                    result = report or empty_daily_activity(target_date, client_ip)
                    result["report_source"] = "saved"
                    result["coverage_complete"] = True
                    return jsonify(result)

                if target_date < date.today() - timedelta(days=ACTIVITY_LOG_BACKFILL_DAYS):
                    return jsonify({
                        "error": "This day was not archived before it left the Squid log window"
                    }), 404
                if not os.path.isfile(SQUID_ACCESS_LOG):
                    return jsonify({"error": "Squid access log is not available and this day has not been saved"}), 503
                archive = build_daily_activity_archive(
                    SQUID_ACCESS_LOG, SQUID_BLOCKLIST_DIR, [target_date]
                )
                reports = archive.get(target_date.isoformat(), {})
                save_reports(SQUID_ACTIVITY_REPORT_DIR, target_date, reports)
                result = reports.get(client_ip) or empty_daily_activity(
                    target_date, client_ip, sorted(reports)
                )
                result["report_source"] = "generated"
                result["coverage_complete"] = True
                return jsonify(result)

        if not os.path.isfile(SQUID_ACCESS_LOG):
            return jsonify({"error": "Squid access log is not available"}), 503
        result = build_daily_activity(
            SQUID_ACCESS_LOG, SQUID_BLOCKLIST_DIR, target_date, client_ip
        )
        result["report_source"] = "live"
        result["coverage_complete"] = True
        return jsonify(result)
    except Exception as e:
        print(f"Error in activity API: {e}")
        return jsonify({"error": "Could not analyze the Squid access log"}), 500


def _load_or_generate_overall_daily_reports(target_dates):
    """Load archived overall days and generate dates still present in the log."""
    today = date.today()
    reports_by_date = {}
    missing = []
    generated = False
    for target_date in target_dates:
        if target_date == today:
            if os.path.isfile(SQUID_ACCESS_LOG):
                live = build_daily_overall_archive(SQUID_ACCESS_LOG, [target_date])
                reports_by_date[target_date.isoformat()] = live[target_date.isoformat()]
            continue
        found, report = load_overall_report(
            SQUID_ACTIVITY_REPORT_DIR, "day", target_date, target_date
        )
        if found:
            reports_by_date[target_date.isoformat()] = report
        elif target_date >= today - timedelta(days=ACTIVITY_LOG_BACKFILL_DAYS):
            missing.append(target_date)

    if missing and os.path.isfile(SQUID_ACCESS_LOG):
        archive = build_daily_overall_archive(SQUID_ACCESS_LOG, missing)
        for target_date in missing:
            report = archive[target_date.isoformat()]
            save_overall_report(
                SQUID_ACTIVITY_REPORT_DIR,
                "day",
                target_date,
                target_date,
                report,
            )
            reports_by_date[target_date.isoformat()] = report
        generated = True

    unavailable = [
        target_date.isoformat()
        for target_date in target_dates
        if target_date.isoformat() not in reports_by_date
    ]
    return reports_by_date, unavailable, generated


@app.route("/api/overall-analytics", methods=["GET"])
def get_overall_analytics():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    date_value = request.args.get("date", today_str()).strip()
    period = request.args.get("period", "day").strip().lower()
    try:
        target_date = datetime.strptime(date_value, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "date must use YYYY-MM-DD format"}), 400
    if period not in ("day", "week", "month"):
        return jsonify({"error": "period must be day, week, or month"}), 400

    today = date.today()
    oldest = today - timedelta(days=ACTIVITY_RETENTION_DAYS - 1)
    if target_date > today or target_date < oldest:
        return jsonify({
            "error": f"date must be within the last {ACTIVITY_RETENTION_DAYS} days"
        }), 400

    natural_start, natural_end = activity_period_bounds(period, target_date)
    period_start = max(natural_start, oldest)
    period_end = min(natural_end, today)
    can_cache = (
        period_start == natural_start and
        period_end == natural_end and
        period_end < today
    )
    try:
        with ACTIVITY_REPORT_LOCK:
            if can_cache:
                found, report = load_overall_report(
                    SQUID_ACTIVITY_REPORT_DIR,
                    period,
                    period_start,
                    period_end,
                )
                if found:
                    report["report_source"] = "saved"
                    report["coverage_complete"] = True
                    return jsonify(report)

            target_dates = _activity_dates(period_start, period_end)
            daily_reports, unavailable, generated = (
                _load_or_generate_overall_daily_reports(target_dates)
            )
            if not daily_reports:
                if period_end < today:
                    return jsonify({
                        "error": "This period was not archived before it left the Squid log window"
                    }), 404
                return jsonify({"error": "Squid access log is not available"}), 503

            report = aggregate_overall_reports(
                daily_reports, period, period_start, period_end
            )
            report["coverage_complete"] = not unavailable
            report["unavailable_days"] = len(unavailable)
            report["report_source"] = (
                "live" if period_end == today
                else "generated" if generated
                else "saved-daily"
            )
            if can_cache and not unavailable:
                save_overall_report(
                    SQUID_ACTIVITY_REPORT_DIR,
                    period,
                    period_start,
                    period_end,
                    report,
                )
                report["report_source"] = "generated"
            return jsonify(report)
    except Exception as e:
        print(f"Error in overall analytics API: {e}")
        return jsonify({"error": "Could not analyze overall Squid traffic"}), 500


@app.route("/api/policies", methods=["GET"])
def get_policies():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"policies": load_device_policies()})


@app.route("/api/audit-log", methods=["GET"])
def get_audit_log():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        limit = min(max(int(request.args.get("limit", "100")), 1), 500)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    try:
        raw_events = read_audit_records(SQUID_AUDIT_LOG, None)
        events = combine_audit_records(raw_events)[:limit]
        return jsonify({"events": events, "limit": limit})
    except Exception as e:
        print(f"Error reading configuration audit log: {e}")
        return jsonify({"error": "Could not read the configuration audit log"}), 500


@app.route("/api/policies", methods=["POST"])
def update_policies():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.json or {}
        previous_policies = load_device_policies()
        policies = copy.deepcopy(previous_policies)

        if "ip" in data:
            ip = data["ip"]
            new_pol = {
                "ip": ip,
                "hostname": data.get("hostname", ip),
                "ssl_bump_mode": data.get("ssl_bump_mode", "blocked_only"),
                "always_block": data.get("always_block", []),
                "always_allow": data.get("always_allow", []),
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

        ok, message = save_device_policies(policies)
        audited = record_policy_change(
            previous_policies,
            policies,
            request_audit_actor(),
            "admin_api",
            ok,
            message,
        )
        if not ok:
            # Policies are saved, but Squid rejected the generated config and the
            # previous ACLs were restored. Surface it instead of reporting success.
            return jsonify({"success": False, "error": message, "policies": policies,
                            "audited": audited}), 500
        return jsonify({"success": True, "message": message, "policies": policies,
                        "audited": audited})
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
        ok, message = compile_device_policies_acls(policies)
        if not ok:
            return jsonify({"success": False, "message": message}), 500
        return jsonify({"success": True, "message": message})
    except Exception as e:
        print(f"Error in apply_rules_api: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500


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


@app.route("/proxy.pac")
def proxy_pac():
    """Public PAC file for reliable explicit proxying of Internet traffic."""
    pac = f"""function FindProxyForURL(url, host) {{
    host = host.toLowerCase();

    // Keep loopback, private LAN addresses, and local DNS names off the proxy.
    if (isPlainHostName(host) ||
        host === "localhost" ||
        shExpMatch(host, "127.*") ||
        host === "::1" || host === "[::1]" ||
        shExpMatch(host, "fc*:*") || shExpMatch(host, "fd*:*") ||
        shExpMatch(host, "fe80:*") ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "172.16.*") || shExpMatch(host, "172.17.*") ||
        shExpMatch(host, "172.18.*") || shExpMatch(host, "172.19.*") ||
        shExpMatch(host, "172.2?.*") || shExpMatch(host, "172.30.*") ||
        shExpMatch(host, "172.31.*") ||
        dnsDomainIs(host, ".home") || dnsDomainIs(host, ".local")) {{
        return "DIRECT";
    }}

    // Do not add DIRECT as a fallback: Internet traffic must remain filtered
    // when the explicit proxy is temporarily unavailable.
    return "PROXY {SQUID_PROXY_HOST}:{SQUID_PROXY_PORT}";
}}
"""
    return pac, 200, {
        "Content-Type": "application/x-ns-proxy-autoconfig; charset=utf-8",
        "Cache-Control": "no-store, max-age=0",
    }


@app.route("/download/install-ubuntu.sh")
def download_ubuntu_script():
    """Public CA and PAC installation script for Ubuntu Linux clients."""
    chrome_policy = json.dumps({
        "ProxySettings": {
            "ProxyMode": "pac_script",
            "ProxyPacUrl": PAC_URL,
            "ProxyPacMandatory": True,
        }
    }, separators=(",", ":"))
    script = f"""#!/bin/bash
set -e
echo "========================================================="
echo "   Squid Proxy CA Certificate & PAC Installer (Ubuntu)"
echo "========================================================="

CERT_URL="{WEBUI_PUBLIC_URL}/download/cert.pem"
PAC_URL="{PAC_URL}"

echo "[*] Downloading Root CA Certificate..."
sudo wget -q -O /usr/local/share/ca-certificates/squid-proxy-ca.crt "$CERT_URL"

echo "[*] Updating System Trust Store..."
sudo update-ca-certificates

if command -v certutil > /dev/null 2>&1; then
    echo "[*] Importing into Chrome/NSS Certificate Database..."
    for user_home in /root /home/*; do
        if [ -d "$user_home/.pki/nssdb" ]; then
            sudo certutil -d "sql:$user_home/.pki/nssdb" -A -t "CT,C,C" -n "{CERT_NAME}" -i /usr/local/share/ca-certificates/squid-proxy-ca.crt 2>/dev/null || true
        fi
    done
fi

echo "[*] Installing managed Chrome/Chromium PAC policy..."
for policy_dir in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed; do
    sudo install -d -m 0755 "$policy_dir"
    printf '%s\n' '{chrome_policy}' | sudo tee "$policy_dir/squid-proxy.json" >/dev/null
done

echo "[*] Configuring the active GNOME desktop to use the PAC file when available..."
LOGIN_USER="${{SUDO_USER:-}}"
if [ -n "$LOGIN_USER" ] && command -v gsettings >/dev/null 2>&1; then
    LOGIN_UID=$(id -u "$LOGIN_USER")
    USER_BUS="/run/user/$LOGIN_UID/bus"
    if [ -S "$USER_BUS" ]; then
        sudo -u "$LOGIN_USER" env DBUS_SESSION_BUS_ADDRESS="unix:path=$USER_BUS" \
            gsettings set org.gnome.system.proxy autoconfig-url "$PAC_URL"
        sudo -u "$LOGIN_USER" env DBUS_SESSION_BUS_ADDRESS="unix:path=$USER_BUS" \
            gsettings set org.gnome.system.proxy mode 'auto'
    fi
fi

echo "[*] Cleaning up old environment-variable proxy profiles..."
sudo rm -f /etc/profile.d/squid-proxy.sh

echo "========================================================="
echo "   [+] Installation Complete. Restart Chrome if it is open."
echo "   [+] PAC URL: $PAC_URL"
echo "========================================================="
"""
    return script, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/download/install-windows.ps1")
def download_windows_script():
    """Public CA and PAC installation script for Windows clients."""
    chrome_proxy_policy = json.dumps({
        "ProxyMode": "pac_script",
        "ProxyPacUrl": PAC_URL,
        "ProxyPacMandatory": True,
    }, separators=(",", ":"))
    script = f'''#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$WebUiBase = "{WEBUI_PUBLIC_URL}"
$PacUrl = "{PAC_URL}"
$CertFile = Join-Path $env:TEMP "squid-proxy-ca.crt"
$ChromePolicyPath = "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome"
$ChromeProxySettings = '{chrome_proxy_policy}'

Write-Host "Downloading and trusting the Squid Root CA..."
Invoke-WebRequest -UseBasicParsing -Uri "$WebUiBase/download/cert.crt" -OutFile $CertFile
Import-Certificate -FilePath $CertFile -CertStoreLocation "Cert:\\LocalMachine\\Root" | Out-Null
Remove-Item -Force $CertFile

Write-Host "Installing the machine-level Chrome PAC policy..."
New-Item -Path $ChromePolicyPath -Force | Out-Null
New-ItemProperty -Path $ChromePolicyPath -Name ProxySettings -PropertyType String -Value $ChromeProxySettings -Force | Out-Null

Write-Host "Configuring the current user's Windows proxy to use $PacUrl..."
$InternetSettings = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
New-ItemProperty -Path $InternetSettings -Name AutoConfigURL -PropertyType String -Value $PacUrl -Force | Out-Null
New-ItemProperty -Path $InternetSettings -Name ProxyEnable -PropertyType DWord -Value 0 -Force | Out-Null

# Notify running WinINet/Chromium applications that proxy settings changed.
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WinInetProxyRefresh {{
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int length);
}}
"@
[WinInetProxyRefresh]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInetProxyRefresh]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null

Write-Host "Installation complete. Restart Chrome or Edge if it is open."
Write-Host "PAC URL: $PacUrl"
Write-Host "Chrome policy: $ChromePolicyPath\\ProxySettings"
'''
    return script, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=install-windows.ps1",
    }


# --- STARTUP LOGIC & BACKGROUND TASKS ---

def raw_policies_have_stale_today():
    """
    Return True when device_policies.json on disk still holds a 'today only'
    unblock window from a previous day.

    This MUST read the raw JSON. load_device_policies() runs every policy through
    ensure_policy_schema(), which already resets today_date to the current day —
    so comparing its output against today never finds a stale entry, and the
    expiry task it gated could never fire. The visible symptom was a one-off
    "unblock for today" staying compiled into rules.acl on that weekday forever.
    """
    try:
        if not os.path.exists(DEVICE_POLICIES_PATH):
            return False
        with open(DEVICE_POLICIES_PATH, "r") as f:
            raw = json.load(f)
    except Exception as e:
        print(f"[expiry] Could not read raw policies: {e}")
        return False

    current = today_str()
    for policy in raw.values():
        if not isinstance(policy, dict):
            continue
        for entry in policy.get("default_block", []) or []:
            if not isinstance(entry, dict):
                continue
            stamp = entry.get("today_date")
            if not stamp or stamp == current:
                continue
            # Only a window that actually granted access needs recompiling.
            if any(entry.get("unblock_today") or []):
                return True
    return False


def daily_expiration_task():
    """Background thread that expires 'Today Only' unblock windows after midnight."""
    while True:
        time.sleep(600)  # Check every 10 minutes so expiry lands close to midnight
        try:
            if not raw_policies_have_stale_today():
                continue
            print("[expiry] Stale 'Today Only' unblock window detected — recompiling ACLs.")
            # load_device_policies() clears the stale slots via ensure_policy_schema;
            # saving persists the cleared state and regenerates rules.acl.
            with open(DEVICE_POLICIES_PATH, "r") as f:
                before = json.load(f)
            expired = load_device_policies()
            ok, message = save_device_policies(expired)
            record_policy_change(
                before,
                expired,
                {
                    "display_name": "Automatic policy expiry",
                    "username": "",
                    "client_ip": "",
                    "authentication": "system",
                },
                "daily_expiration_task",
                ok,
                message,
            )
            if not ok:
                print(f"[expiry] Recompile failed: {message}")
        except Exception as e:
            print(f"[expiry] Error in daily_expiration_task: {e}")


def archive_activity_reports():
    """Backfill completed days still present in Squid's rotating logs."""
    prune_reports(SQUID_ACTIVITY_REPORT_DIR, ACTIVITY_RETENTION_DAYS)
    prune_period_reports(SQUID_ACTIVITY_REPORT_DIR, ACTIVITY_RETENTION_DAYS)
    if not os.path.isfile(SQUID_ACCESS_LOG):
        return
    target_dates = [
        date.today() - timedelta(days=offset)
        for offset in range(1, ACTIVITY_LOG_BACKFILL_DAYS + 1)
        if not report_exists(
            SQUID_ACTIVITY_REPORT_DIR, date.today() - timedelta(days=offset)
        )
    ]
    if not target_dates:
        return

    print(f"[activity] Archiving {len(target_dates)} completed daily report(s).")
    archive = build_daily_activity_archive(
        SQUID_ACCESS_LOG, SQUID_BLOCKLIST_DIR, target_dates
    )
    with ACTIVITY_REPORT_LOCK:
        for target_date in target_dates:
            save_reports(
                SQUID_ACTIVITY_REPORT_DIR,
                target_date,
                archive.get(target_date.isoformat(), {}),
            )


def archive_period_reports():
    """Generate complete weekly and monthly snapshots from archived daily data."""
    today = date.today()
    oldest = today - timedelta(days=ACTIVITY_RETENTION_DAYS - 1)
    candidates = set()
    for target_date in _activity_dates(oldest, today - timedelta(days=1)):
        for period in ("week", "month"):
            period_start, period_end = activity_period_bounds(period, target_date)
            if period_start >= oldest and period_end < today:
                candidates.add((period, period_start, period_end))

    with ACTIVITY_REPORT_LOCK:
        for period, period_start, period_end in sorted(candidates):
            if period_report_exists(
                    SQUID_ACTIVITY_REPORT_DIR, period, period_start):
                continue
            daily_reports = {}
            for target_date in _activity_dates(period_start, period_end):
                found, reports = load_reports(
                    SQUID_ACTIVITY_REPORT_DIR, target_date
                )
                if not found:
                    daily_reports = {}
                    break
                daily_reports[target_date.isoformat()] = reports
            if not daily_reports:
                continue
            reports = aggregate_activity_archive(
                daily_reports, period, period_start, period_end
            )
            save_period_reports(
                SQUID_ACTIVITY_REPORT_DIR,
                period,
                period_start,
                period_end,
                reports,
            )
            print(
                f"[activity] Archived {period} report "
                f"{period_start.isoformat()} through {period_end.isoformat()}."
            )


def archive_overall_reports():
    """Archive GoAccess-style all-client day/week/month summaries."""
    today = date.today()
    oldest = today - timedelta(days=ACTIVITY_RETENTION_DAYS - 1)
    prune_overall_reports(SQUID_ACTIVITY_REPORT_DIR, ACTIVITY_RETENTION_DAYS)

    if os.path.isfile(SQUID_ACCESS_LOG):
        missing_days = [
            today - timedelta(days=offset)
            for offset in range(1, ACTIVITY_LOG_BACKFILL_DAYS + 1)
            if not overall_report_exists(
                SQUID_ACTIVITY_REPORT_DIR,
                "day",
                today - timedelta(days=offset),
            )
        ]
        if missing_days:
            print(
                f"[overall] Archiving {len(missing_days)} completed daily report(s)."
            )
            archive = build_daily_overall_archive(SQUID_ACCESS_LOG, missing_days)
            with ACTIVITY_REPORT_LOCK:
                for target_date in missing_days:
                    save_overall_report(
                        SQUID_ACTIVITY_REPORT_DIR,
                        "day",
                        target_date,
                        target_date,
                        archive[target_date.isoformat()],
                    )

    candidates = set()
    for target_date in _activity_dates(oldest, today - timedelta(days=1)):
        for period in ("week", "month"):
            period_start, period_end = activity_period_bounds(period, target_date)
            if period_start >= oldest and period_end < today:
                candidates.add((period, period_start, period_end))

    with ACTIVITY_REPORT_LOCK:
        for period, period_start, period_end in sorted(candidates):
            if overall_report_exists(
                    SQUID_ACTIVITY_REPORT_DIR, period, period_start):
                continue
            daily_reports = {}
            for target_date in _activity_dates(period_start, period_end):
                found, report = load_overall_report(
                    SQUID_ACTIVITY_REPORT_DIR, "day", target_date, target_date
                )
                if not found:
                    daily_reports = {}
                    break
                daily_reports[target_date.isoformat()] = report
            if not daily_reports:
                continue
            report = aggregate_overall_reports(
                daily_reports, period, period_start, period_end
            )
            save_overall_report(
                SQUID_ACTIVITY_REPORT_DIR,
                period,
                period_start,
                period_end,
                report,
            )
            print(
                f"[overall] Archived {period} report "
                f"{period_start.isoformat()} through {period_end.isoformat()}."
            )


def activity_archive_task():
    """Keep day/week/month reports generated and expire them after one year."""
    while True:
        try:
            archive_activity_reports()
            archive_period_reports()
            archive_overall_reports()
        except Exception as e:
            print(f"[activity] Error archiving daily reports: {e}")
        time.sleep(3600)


def _is_primary_worker():
    """
    True when this process should own the singleton startup work.

    Gunicorn forks one process per worker and each imports this module, so
    without a guard every worker recompiles the ACLs and SIGHUPs Squid on boot,
    and every worker runs its own expiry thread. An advisory lock file on the
    shared config volume elects exactly one owner.
    """
    lock_path = os.path.join(SQUID_CONFIG_DIR, ".startup.lock")
    try:
        os.makedirs(SQUID_CONFIG_DIR, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Deliberately leaked: the lock is held for the lifetime of the process.
        globals()["_STARTUP_LOCK_FD"] = fd
        return True
    except (OSError, IOError):
        return False
    except Exception as e:
        print(f"[startup] Worker election unavailable ({e}); proceeding as primary.")
        return True


if _is_primary_worker():
    # Compile on startup so rules.acl always matches device_policies.json.
    try:
        ok, message = compile_device_policies_acls(load_device_policies())
        if not ok:
            print(f"[startup] Compilation reported: {message}")
    except Exception as e:
        print(f"[startup] Compilation failed: {e}")

    expiration_thread = threading.Thread(target=daily_expiration_task, daemon=True)
    expiration_thread.start()
    activity_thread = threading.Thread(target=activity_archive_task, daemon=True)
    activity_thread.start()
else:
    print("[startup] Secondary worker — skipping ACL compilation and background threads.")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("WEBUI_PORT", "3131")), debug=False)
