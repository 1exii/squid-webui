import os
import json
import secrets
import threading
import time
import socket
import http.client
from datetime import date
import paramiko
from passlib.hash import md5_crypt, sha512_crypt, sha256_crypt, des_crypt
from flask import Flask, render_template, request, jsonify, session, send_file

app = Flask(__name__)

# Configuration paths (inside container / host)
SQUID_CONFIG_DIR = os.environ.get("SQUID_CONFIG_DIR", "/etc/squid/configs")
SQUID_BLOCKLIST_DIR = os.environ.get("SQUID_BLOCKLIST_DIR", "/etc/squid/block-lists")
SQUID_CERT_DIR = os.environ.get("SQUID_CERT_DIR", "/etc/squid/certs")
ROUTER_HOSTS_CONF = os.environ.get("ROUTER_HOSTS_CONF", "/etc/squid/router/proxy-hosts.conf")

RULES_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "rules.acl")
SSL_BUMP_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "ssl_bump.acl")
# Domain list requiring SSL bumping for deep URL path inspection (data file).
BUMP_DOMAINS_ACL_PATH = os.path.join(SQUID_CONFIG_DIR, "bump_domains.acl")
# Squid directives that reference the list above. Generated alongside it so that
# when NO blocklist defines a URL path rule this file is empty, instead of
# leaving squid.conf with an `acl ... dstdomain "<empty file>"` that parses fine
# but can never match — a silently dead rule.
BUMP_DOMAINS_CONF_PATH = os.path.join(SQUID_CONFIG_DIR, "bump_domains.conf")

QNAP_IP = os.environ.get("QNAP_IP", "192.168.1.2")
SQUID_CONTAINER_NAME = os.environ.get("SQUID_CONTAINER_NAME", "squid-proxy")


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
        "ssl_bump_mode": legacy.get("ssl_bump_mode", "blocked_only"),
        "always_block": legacy.get("blocklists", []),
        "default_block": []
    }


def ensure_policy_schema(policy):
    """Ensure a policy dict has the current schema fields, migrating if necessary."""
    # Detect legacy flat format (has 'blocklists' key but not 'always_block')
    if "blocklists" in policy and "always_block" not in policy:
        policy = migrate_legacy_policy(policy)

    policy.setdefault("ssl_bump_mode", "blocked_only")
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
    """Persist policies to disk and recompile the Squid ACLs. Returns (ok, message)."""
    os.makedirs(os.path.dirname(DEVICE_POLICIES_PATH), exist_ok=True)
    for ip in policies:
        policies[ip] = ensure_policy_schema(policies[ip])
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
        policy = ensure_policy_schema(policy)
        hostname = policy.get("hostname", ip)
        always_block = policy.get("always_block", [])
        default_block = policy.get("default_block", [])
        ssl_bump_mode = policy.get("ssl_bump_mode", "blocked_only")

        if not always_block and not default_block:
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
                            acl_lines.append(f"acl {p_url_acl} urlpath_regex -i ^{ere_escape(rule['path'])}")
                            declared_path_rules.add(p_dom_acl)
        acl_lines.append("")

        # Dynamic SSL Bumping Rules for this device
        if ssl_bump_mode == "all":
            # Bump all HTTPS traffic for this specific device
            ssl_bump_lines.append(f"ssl_bump bump {src_acl_name}")
        elif ssl_bump_mode == "blocked_only":
            # Bump only the blocked category domains & path domains for this device
            for bl in all_lists:
                bl_id = bl.replace('.', '_').replace('-', '_')
                bl_acl_name = f"list_{bl_id}"
                ssl_bump_lines.append(f"ssl_bump bump {src_acl_name} {bl_acl_name}")
                if bl in parsed_blocklists:
                    path_rules = parsed_blocklists[bl].get("path_rules", [])
                    for idx in range(1, len(path_rules) + 1):
                        p_dom_acl = f"path_dom_{bl_id}_{idx}"
                        ssl_bump_lines.append(f"ssl_bump bump {src_acl_name} {p_dom_acl}")
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
                "ssl_bump_mode": data.get("ssl_bump_mode", "blocked_only"),
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

        ok, message = save_device_policies(policies)
        if not ok:
            # Policies are saved, but Squid rejected the generated config and the
            # previous ACLs were restored. Surface it instead of reporting success.
            return jsonify({"success": False, "error": message, "policies": policies}), 500
        return jsonify({"success": True, "message": message, "policies": policies})
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
            ok, message = save_device_policies(load_device_policies())
            if not ok:
                print(f"[expiry] Recompile failed: {message}")
        except Exception as e:
            print(f"[expiry] Error in daily_expiration_task: {e}")


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
else:
    print("[startup] Secondary worker — skipping ACL compilation and expiry thread.")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3131, debug=False)
