"""Analysis of non-policy Squid access failures with explanation and caching."""

from collections import defaultdict
from datetime import date, datetime, time as datetime_time, timedelta, timezone
import gzip
import json
import os
import re
from traffic_analytics import extract_hostname, iter_access_log_paths


FAILURE_SCHEMA_VERSION = 1

# Quick window mappings in seconds
WINDOW_SECONDS = {
    "5m": 5 * 60,
    "10m": 10 * 60,
    "30m": 30 * 60,
    "1h": 60 * 60,
    "2h": 2 * 60 * 60,
    "3h": 3 * 60 * 60,
    "5h": 5 * 60 * 60,
}

FAILURE_CATEGORIES = {
    "503": (
        "Upstream Unreachable / DNS Failure",
        "Squid could not resolve the destination hostname or connect to the upstream server "
        "(DNS resolution failed, IPv6 destination unreachable, or upstream host is offline)."
    ),
    "502": (
        "Bad Gateway / Upstream Reset",
        "Squid received an invalid response, TCP reset, or unexpected closure from the upstream "
        "server or gateway during connection establishment."
    ),
    "504": (
        "Gateway Timeout",
        "The upstream web server or gateway did not complete the connection or respond "
        "within Squid's read/connect timeout threshold."
    ),
    "408": (
        "Request Timeout",
        "The connection timed out before the client or server completed sending the request."
    ),
    "500": (
        "Internal Error / TLS Tunnel Terminated",
        "The server returned an internal error (500), or the TLS tunnel terminated abnormally "
        "before data transfer was finished."
    ),
    "409": (
        "Host Header / SNI Mismatch",
        "Squid detected a conflict between the client TLS SNI/Host header and destination IP "
        "(host forgery guard or DNS rebinding prevention)."
    ),
    "400": (
        "Malformed Request / Protocol Error",
        "The client transmitted invalid HTTP syntax, corrupted request headers, or non-HTTP "
        "traffic directly to an HTTP proxy port."
    ),
    "429": (
        "Upstream Rate Limited",
        "The upstream server temporarily rejected requests due to rate limiting."
    ),
    "000": (
        "Connection Closed Before Headers",
        "The connection was closed before any HTTP headers were transmitted. This frequently occurs "
        "when client applications enforce SSL/TLS certificate pinning or reject Squid's CA certificate."
    ),
}

ERROR_CODE_PATTERNS = [
    (r"error:dns-lookup-failed", "503"),
    (r"error:connect-fail", "502"),
    (r"error:invalid-request", "400"),
    (r"error:transaction-end-before-headers", "000"),
    (r"error:secure-accept-fail", "000"),
    (r"error:host-header-mismatch", "409"),
]


def classify_failure(status, result, url):
    """Classify the failure into category, explanation, and diagnostic tag."""
    matched_key = None
    if status in FAILURE_CATEGORIES:
        matched_key = status
    elif url:
        for pattern, key in ERROR_CODE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                matched_key = key
                break

    if not matched_key:
        if status.startswith("5"):
            matched_key = "500"
        elif status.startswith("4"):
            matched_key = "400"
        elif status in ("0", "-", "000"):
            matched_key = "000"

    if matched_key and matched_key in FAILURE_CATEGORIES:
        category, explanation = FAILURE_CATEGORIES[matched_key]
        return category, explanation, matched_key

    return (
        f"HTTP Error {status}",
        f"The connection failed with Squid result code '{result}' and HTTP status '{status}'.",
        status
    )


def is_policy_block(result, status, url):
    """Return True if this request was blocked by access control policies."""
    if result.startswith("TCP_DENIED/") or status == "403":
        return True
    if "/blocked?" in url or "/blocked.html" in url:
        return True
    return False


def is_failure_event(result, status, url):
    """Determine if a log record represents a non-policy connection failure."""
    if is_policy_block(result, status, url):
        return False

    if status.isdigit():
        code = int(status)
        if code >= 500:
            return True
        if code in (400, 408, 409, 429):
            return True

    if status in ("000", "0", "-"):
        return True

    if "error:" in url:
        return True

    if "TCP_SWAPFAIL_MISS" in result or "TCP_RESET" in result:
        return True

    return False


def build_copyable_prompt(event):
    """Construct an AI prompt snippet ready to paste into Gemini / ChatGPT."""
    parts = [
        "### Squid Proxy Access Failure Report",
        f"- **Timestamp**: {event['datetime_local']} (epoch: {event['timestamp']})",
        f"- **Client Device**: {event['client_name']} ({event['client_ip']})",
        f"- **Target Domain**: {event['domain']}",
        f"- **Destination**: {event['method']} {event['url']}",
        f"- **Squid Result Code**: {event['result']} (HTTP Status: {event['status']})",
        f"- **Error Category**: {event['category']}",
        f"- **Preliminary Diagnostic**: {event['explanation']}",
        "",
        "#### Raw Squid Access Log Line:",
        "```text",
        event["raw_log"],
        "```",
        "",
        "#### Diagnostic Prompt:",
        "Please analyze the root cause of this failure in the Squid proxy environment. "
        "Could this be caused by SSL inspection/certificate pinning, an upstream network or DNS issue, "
        "or a Squid configuration issue? What are the specific troubleshooting steps or recommended ACL/splice fixes?"
    ]
    return "\n".join(parts)


def _open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_failure_events(
    access_log_path,
    start_epoch,
    end_epoch,
    client_ip="",
    devices_by_ip=None,
    limit=500,
):
    """
    Scan access logs for non-policy connection failures within [start_epoch, end_epoch].
    Returns (summary_dict, list_of_event_dicts).
    """
    devices = devices_by_ip or {}
    events = []
    domain_counts = defaultdict(int)
    domain_categories = defaultdict(lambda: defaultdict(int))
    client_counts = defaultdict(int)
    category_counts = defaultdict(int)
    status_counts = defaultdict(int)

    for path in iter_access_log_paths(access_log_path):
        try:
            with _open_log(path) as handle:
                for line in handle:
                    raw_line = line.strip()
                    if not raw_line:
                        continue
                    fields = raw_line.split()
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

                    result = fields[3]
                    status = result.rsplit("/", 1)[-1] if "/" in result else "-"
                    method = fields[5]
                    url = fields[6]

                    if not is_failure_event(result, status, url):
                        continue

                    domain = extract_hostname(method, url)
                    if not domain:
                        clean = url.split(":", 1)[0].replace("http://", "").replace("https://", "").split("/")[0]
                        domain = clean if clean and not clean.startswith("error:") else "unknown-destination"

                    category, explanation, status_key = classify_failure(status, result, url)

                    device_info = devices.get(source_ip)
                    if isinstance(device_info, dict):
                        client_name = device_info.get("name") or device_info.get("hostname") or source_ip
                    elif isinstance(device_info, str):
                        client_name = device_info
                    else:
                        client_name = source_ip

                    dt_local = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

                    event = {
                        "timestamp": timestamp,
                        "datetime_local": dt_local,
                        "client_ip": source_ip,
                        "client_name": client_name,
                        "domain": domain,
                        "method": method,
                        "url": url,
                        "result": result,
                        "status": status,
                        "category": category,
                        "explanation": explanation,
                        "raw_log": raw_line,
                    }
                    event["copyable_prompt"] = build_copyable_prompt(event)
                    events.append(event)

                    domain_counts[domain] += 1
                    domain_categories[domain][category] += 1
                    client_counts[source_ip] += 1
                    category_counts[category] += 1
                    status_counts[status] += 1

        except OSError:
            continue

    events.sort(key=lambda item: item["timestamp"], reverse=True)

    top_domains = []
    for dom, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:25]:
        cats = sorted(domain_categories[dom].items(), key=lambda x: x[1], reverse=True)
        top_domains.append({
            "domain": dom,
            "failures": count,
            "primary_category": cats[0][0] if cats else "Unknown",
        })

    top_clients = []
    for ip, count in sorted(client_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
        dev = devices.get(ip)
        name = dev.get("name") if isinstance(dev, dict) else dev if isinstance(dev, str) else ip
        top_clients.append({
            "client_ip": ip,
            "client_name": name,
            "failures": count,
        })

    summary = {
        "total_failures": len(events),
        "unique_domains": len(domain_counts),
        "unique_clients": len(client_counts),
        "category_counts": dict(category_counts),
        "status_counts": dict(status_counts),
        "top_domains": top_domains,
        "top_clients": top_clients,
        "start_epoch": start_epoch,
        "end_epoch": end_epoch,
    }

    if limit and len(events) > limit:
        events = events[:limit]

    return summary, events


def report_file_path(cache_dir, target_date):
    return os.path.join(cache_dir, "daily", f"{target_date.isoformat()}.json")


def load_daily_failure_report(cache_dir, target_date):
    """Load cached daily failure report if present and valid."""
    path = report_file_path(cache_dir, target_date)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (payload.get("schema_version") != FAILURE_SCHEMA_VERSION or
                payload.get("date") != target_date.isoformat()):
            return False, None
        return True, payload.get("data")
    except (OSError, ValueError, TypeError):
        return False, None


def save_daily_failure_report(cache_dir, target_date, data):
    """Atomically cache a daily failure report."""
    daily_dir = os.path.join(cache_dir, "daily")
    os.makedirs(daily_dir, mode=0o700, exist_ok=True)
    path = report_file_path(cache_dir, target_date)
    temp_path = f"{path}.tmp.{os.getpid()}"
    payload = {
        "schema_version": FAILURE_SCHEMA_VERSION,
        "date": target_date.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    try:
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(temp_path, path)
    except OSError:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def prune_failure_reports(cache_dir, retention_days, today=None):
    """Prune cached daily failure reports outside the retention window."""
    today = today or date.today()
    oldest = today - timedelta(days=retention_days - 1)
    daily_dir = os.path.join(cache_dir, "daily")
    if not os.path.isdir(daily_dir):
        return 0

    removed = 0
    try:
        for name in os.listdir(daily_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(daily_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                report_date = date.fromisoformat(payload["date"])
            except (OSError, ValueError, KeyError, TypeError):
                continue

            if report_date < oldest or report_date > today:
                try:
                    os.unlink(path)
                    removed += 1
                except OSError:
                    pass
    except OSError:
        pass
    return removed
