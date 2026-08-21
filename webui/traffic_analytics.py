"""Daily, per-client website summaries derived from Squid access logs."""

from collections import defaultdict
from datetime import datetime, time as datetime_time, timedelta
import gzip
import ipaddress
import os
from urllib.parse import urlsplit


IDLE_CUTOFF_SECONDS = 5 * 60
LAST_EVENT_SECONDS = 30


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


def summarize_client_events(events, category_domains):
    """Attribute active intervals to each destination and return UI-ready rows."""
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
        row = sites.setdefault(host, {
            "site": host,
            "categories": categories_for_host(host, category_domains),
            "requests": 0,
            "blocked_requests": 0,
            "estimated_seconds": 0,
            "last_seen_epoch": event["timestamp"],
        })
        row["requests"] += 1
        row["blocked_requests"] += int(event["blocked"])
        row["estimated_seconds"] += active_seconds
        row["last_seen_epoch"] = max(row["last_seen_epoch"], event["timestamp"])
        total_seconds += active_seconds

    rows = sorted(
        sites.values(),
        key=lambda row: (-row["estimated_seconds"], -row["requests"], row["site"]),
    )
    return {
        "unique_sites": len(rows),
        "requests": len(ordered),
        "blocked_requests": sum(int(event["blocked"]) for event in ordered),
        "estimated_seconds": total_seconds,
        "sites": rows,
    }


def build_daily_activity(access_log_path, blocklist_dir, target_date, client_ip=""):
    category_domains = load_category_domains(blocklist_dir)
    events_by_client = parse_daily_events(access_log_path, target_date, client_ip)
    clients = sorted(events_by_client)
    selected_events = events_by_client.get(client_ip, []) if client_ip else []
    summary = summarize_client_events(selected_events, category_domains)
    summary.update({
        "date": target_date.isoformat(),
        "client_ip": client_ip,
        "clients_with_activity": clients,
        "estimation": {
            "idle_cutoff_seconds": IDLE_CUTOFF_SECONDS,
            "last_event_seconds": LAST_EVENT_SECONDS,
            "description": "Estimated from gaps between proxy requests; gaps over 5 minutes count as 30 seconds.",
        },
    })
    return summary
