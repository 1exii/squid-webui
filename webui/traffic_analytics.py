"""Daily, per-client website summaries derived from Squid access logs."""

from collections import defaultdict
from datetime import datetime, time as datetime_time, timedelta
import gzip
import ipaddress
import os
from urllib.parse import urlsplit


IDLE_CUTOFF_SECONDS = 5 * 60
LAST_EVENT_SECONDS = 30

# A registrable-domain fallback groups ordinary subdomains. These explicit
# service families additionally join first-party CDN/API domains that do not
# share the product's main domain (for example googlevideo.com for YouTube).
SERVICE_GROUPS = (
    ("youtube", "YouTube", (
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
        "youtube-nocookie.com", "youtubekids.com",
    )),
    ("netflix", "Netflix", (
        "netflix.com", "nflxext.com", "nflxvideo.net", "nflximg.net", "nflxso.net",
    )),
    ("roblox", "Roblox", ("roblox.com", "roblox.com.br", "rbxcdn.com")),
    ("spotify", "Spotify", ("spotify.com", "spotifycdn.com", "scdn.co")),
    ("facebook", "Facebook", ("facebook.com", "fbcdn.net", "messenger.com")),
    ("instagram", "Instagram", ("instagram.com", "cdninstagram.com")),
    ("tiktok", "TikTok", ("tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com")),
)

# Common two-label public suffixes. This deliberately small fallback avoids an
# online public-suffix lookup in the home-network appliance.
MULTI_LABEL_PUBLIC_SUFFIXES = frozenset({
    "ac.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.uk", "co.za",
    "com.au", "com.br", "com.cn", "com.hk", "com.mx", "com.sg",
    "net.au", "org.au", "org.uk",
})


def extract_hostname(method, url):
    """Extract and normalize the destination host from a Squid native log URL."""
    if not url or url == "-" or url.startswith("error:"):
        return ""

    candidate = url if "://" in url else f"//{url}"
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def display_site(host):
    """Return a readable website hostname; omit IP-only proxy destinations."""
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass

    labels = host.split(".")
    if labels and labels[0] == "www" and len(labels) > 2:
        return ".".join(labels[1:])
    return host


def registrable_domain(host):
    """Return a practical eTLD+1-style grouping key for an observed hostname."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix_length = 2 if ".".join(labels[-2:]) in MULTI_LABEL_PUBLIC_SUFFIXES else 1
    return ".".join(labels[-(suffix_length + 1):])


def site_identity(host):
    """Return the stable key and friendly label for a website/service group."""
    for key, label, domains in SERVICE_GROUPS:
        if any(host == domain or host.endswith(f".{domain}") for domain in domains):
            return key, label
    domain = registrable_domain(host)
    return domain, domain


def load_category_domains(blocklist_dir):
    """Load domain suffixes from the same blocklists used by access policies."""
    categories = {}
    if not os.path.isdir(blocklist_dir):
        return categories

    for filename in sorted(os.listdir(blocklist_dir)):
        if not filename.endswith(".txt"):
            continue
        domains = set()
        path = os.path.join(blocklist_dir, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    value = raw_line.strip().lower()
                    if not value or value.startswith("#") or value.startswith("/"):
                        continue
                    value = value.split()[0].lstrip(".").rstrip(".")
                    if value and "/" not in value:
                        domains.add(value)
        except OSError:
            continue
        categories[filename.removesuffix(".txt")] = domains
    return categories


def categories_for_host(host, category_domains):
    matches = []
    for category, domains in category_domains.items():
        if any(host == domain or host.endswith(f".{domain}") for domain in domains):
            matches.append(category)
    return matches or ["uncategorized"]


def iter_access_log_paths(access_log_path):
    """Yield the active log plus any conventional numbered rotations."""
    directory = os.path.dirname(access_log_path) or "."
    basename = os.path.basename(access_log_path)
    try:
        names = os.listdir(directory)
    except OSError:
        return

    candidates = []
    for name in names:
        if name == basename:
            order = 0
        elif name.startswith(f"{basename}."):
            suffix = name[len(basename) + 1:].removesuffix(".gz")
            if not suffix.isdigit():
                continue
            order = int(suffix)
        else:
            continue
        candidates.append((order, os.path.join(directory, name)))
    for _, path in sorted(candidates, reverse=True):
        yield path


def _open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _day_epoch_bounds(target_date):
    start = datetime.combine(target_date, datetime_time.min).timestamp()
    end = datetime.combine(target_date + timedelta(days=1), datetime_time.min).timestamp()
    return start, end


def parse_daily_events(access_log_path, target_date, client_ip=""):
    """Parse relevant native-format access log lines for one local calendar day."""
    start_epoch, end_epoch = _day_epoch_bounds(target_date)
    events = defaultdict(list)

    for path in iter_access_log_paths(access_log_path):
        try:
            with _open_log(path) as handle:
                for line in handle:
                    fields = line.split()
                    if len(fields) < 7:
                        continue
                    try:
                        timestamp = float(fields[0])
                    except ValueError:
                        continue
                    if timestamp < start_epoch or timestamp >= end_epoch:
                        continue

                    source_ip = fields[2]
                    if client_ip and source_ip != client_ip:
                        continue
                    host = extract_hostname(fields[5], fields[6])
                    if not host:
                        continue
                    site = display_site(host)
                    if not site:
                        continue
                    result = fields[3]
                    events[source_ip].append({
                        "timestamp": timestamp,
                        "host": site,
                        "blocked": result.startswith("TCP_DENIED/") or result.endswith("/403"),
                    })
        except OSError:
            continue
    return events


def parse_events_for_dates(access_log_path, target_dates):
    """Parse the logs once and bucket events for several local calendar days."""
    target_dates = set(target_dates)
    if not target_dates:
        return {}

    first_epoch, _ = _day_epoch_bounds(min(target_dates))
    _, last_epoch = _day_epoch_bounds(max(target_dates))
    events_by_date = {target_date: defaultdict(list) for target_date in target_dates}

    for path in iter_access_log_paths(access_log_path):
        try:
            with _open_log(path) as handle:
                for line in handle:
                    fields = line.split()
                    if len(fields) < 7:
                        continue
                    try:
                        timestamp = float(fields[0])
                    except ValueError:
                        continue
                    if timestamp < first_epoch or timestamp >= last_epoch:
                        continue

                    target_date = datetime.fromtimestamp(timestamp).date()
                    if target_date not in target_dates:
                        continue
                    host = extract_hostname(fields[5], fields[6])
                    if not host:
                        continue
                    site = display_site(host)
                    if not site:
                        continue
                    result = fields[3]
                    events_by_date[target_date][fields[2]].append({
                        "timestamp": timestamp,
                        "host": site,
                        "blocked": result.startswith("TCP_DENIED/") or result.endswith("/403"),
                    })
        except OSError:
            continue
    return events_by_date


def summarize_client_events(events, category_domains):
    """Attribute active intervals and group hostnames into expandable websites."""
    ordered = sorted(events, key=lambda event: event["timestamp"])
    sites = {}
    total_seconds = 0

    for index, event in enumerate(ordered):
        active_seconds = LAST_EVENT_SECONDS
        if index + 1 < len(ordered):
            gap = ordered[index + 1]["timestamp"] - event["timestamp"]
            if 0 < gap <= IDLE_CUTOFF_SECONDS:
                active_seconds = max(1, round(gap))

        host = event["host"]
        site_key, site_label = site_identity(host)
        row = sites.setdefault(site_key, {
            "site_key": site_key,
            "site": site_label,
            "categories": set(),
            "requests": 0,
            "blocked_requests": 0,
            "estimated_seconds": 0,
            "last_seen_epoch": event["timestamp"],
            "domains": {},
        })
        domain_categories = categories_for_host(host, category_domains)
        domain = row["domains"].setdefault(host, {
            "domain": host,
            "categories": domain_categories,
            "requests": 0,
            "blocked_requests": 0,
            "estimated_seconds": 0,
            "last_seen_epoch": event["timestamp"],
        })
        row["categories"].update(domain_categories)
        row["requests"] += 1
        row["blocked_requests"] += int(event["blocked"])
        row["estimated_seconds"] += active_seconds
        row["last_seen_epoch"] = max(row["last_seen_epoch"], event["timestamp"])
        domain["requests"] += 1
        domain["blocked_requests"] += int(event["blocked"])
        domain["estimated_seconds"] += active_seconds
        domain["last_seen_epoch"] = max(domain["last_seen_epoch"], event["timestamp"])
        total_seconds += active_seconds

    for row in sites.values():
        if len(row["categories"]) > 1:
            row["categories"].discard("uncategorized")
        row["categories"] = sorted(row["categories"])
        row["domains"] = sorted(
            row["domains"].values(),
            key=lambda domain: (
                -domain["estimated_seconds"], -domain["requests"], domain["domain"]
            ),
        )
        row["domain_count"] = len(row["domains"])

    rows = sorted(
        sites.values(),
        key=lambda row: (-row["estimated_seconds"], -row["requests"], row["site"]),
    )
    return {
        "unique_sites": len(rows),
        "unique_domains": sum(row["domain_count"] for row in rows),
        "requests": len(ordered),
        "blocked_requests": sum(int(event["blocked"]) for event in ordered),
        "estimated_seconds": total_seconds,
        "sites": rows,
    }


def _activity_metadata(target_date, client_ip, clients_with_activity=None):
    return {
        "date": target_date.isoformat(),
        "client_ip": client_ip,
        "clients_with_activity": clients_with_activity or [],
        "estimation": {
            "idle_cutoff_seconds": IDLE_CUTOFF_SECONDS,
            "last_event_seconds": LAST_EVENT_SECONDS,
            "description": "Estimated from gaps between proxy requests; gaps over 5 minutes count as 30 seconds.",
        },
    }


def empty_daily_activity(target_date, client_ip, clients_with_activity=None):
    summary = summarize_client_events([], {})
    summary.update(_activity_metadata(target_date, client_ip, clients_with_activity))
    return summary


def build_daily_activity(access_log_path, blocklist_dir, target_date, client_ip=""):
    category_domains = load_category_domains(blocklist_dir)
    events_by_client = parse_daily_events(access_log_path, target_date, client_ip)
    clients = sorted(events_by_client)
    selected_events = events_by_client.get(client_ip, []) if client_ip else []
    summary = summarize_client_events(selected_events, category_domains)
    summary.update(_activity_metadata(target_date, client_ip, clients))
    return summary


def build_daily_activity_archive(access_log_path, blocklist_dir, target_dates):
    """Build all per-client reports for several dates with one log scan."""
    target_dates = list(dict.fromkeys(target_dates))
    category_domains = load_category_domains(blocklist_dir)
    events_by_date = parse_events_for_dates(access_log_path, target_dates)
    archive = {}
    for target_date in target_dates:
        daily_events = events_by_date.get(target_date, {})
        clients = sorted(daily_events)
        reports = {}
        for client_ip in clients:
            summary = summarize_client_events(daily_events[client_ip], category_domains)
            summary.update(_activity_metadata(target_date, client_ip, clients))
            reports[client_ip] = summary
        archive[target_date.isoformat()] = reports
    return archive
