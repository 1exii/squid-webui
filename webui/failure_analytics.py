"""Analysis of non-policy Squid access failures with explanation and caching."""

from collections import Counter, defaultdict
from datetime import date, datetime, time as datetime_time, timedelta, timezone
import gzip
import json
import os
import re
import threading
from traffic_analytics import extract_hostname, iter_access_log_paths


FAILURE_SCHEMA_VERSION = 2

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


def parse_failure_line(raw_line, devices=None):
    """Parse a single Squid access log line into a failure event dict, or None if not a failure."""
    raw_line = raw_line.strip()
    if not raw_line:
        return None
    fields = raw_line.split()
    if len(fields) < 7:
        return None

    try:
        timestamp = float(fields[0])
    except ValueError:
        return None

    source_ip = fields[2]
    result = fields[3]
    status = result.rsplit("/", 1)[-1] if "/" in result else "-"
    method = fields[5]
    url = fields[6]

    if not is_failure_event(result, status, url):
        return None

    domain = extract_hostname(method, url)
    if not domain:
        clean = url.split(":", 1)[0].replace("http://", "").replace("https://", "").split("/")[0]
        domain = clean if clean and not clean.startswith("error:") else "unknown-destination"

    category, explanation, status_key = classify_failure(status, result, url)

    devices = devices or {}
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
    return event


FAILURE_CANDIDATE_STRINGS = ("/5", "/400", "/408", "/409", "/429", "/000", "/0 ", "/-", "error:", "TCP_SWAPFAIL", "TCP_RESET")
FAILURE_CANDIDATE_BYTES = tuple(s.encode("utf-8") for s in FAILURE_CANDIDATE_STRINGS)


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
    Employs binary reading, candidate pre-filtering, file boundary skips,
    and fast seeking to achieve sub-second response times across large rotated logs.
    Returns (summary_dict, list_of_event_dicts).
    """
    devices = devices_by_ip or {}
    events = []

    for path in iter_access_log_paths(access_log_path):
        is_gz = path.endswith(".gz")
        try:
            if not is_gz:
                size = os.path.getsize(path)
                if size == 0:
                    continue
                with open(path, "rb") as handle:
                    # Quick boundary check: read first line timestamp
                    first_line = handle.readline()
                    sp1 = first_line.find(b" ")
                    if sp1 > 0:
                        try:
                            t1 = float(first_line[:sp1])
                            if t1 >= end_epoch:
                                continue  # Entire file is after target range
                        except ValueError:
                            pass
                    # Read last line timestamp
                    handle.seek(max(0, size - 4096))
                    tail_lines = handle.readlines()
                    last_line = tail_lines[-1] if tail_lines else b""
                    sp2 = last_line.find(b" ")
                    if sp2 > 0:
                        try:
                            t2 = float(last_line[:sp2])
                            if t2 < start_epoch:
                                continue  # Entire file is before target range
                        except ValueError:
                            pass

                    # Seek to start of target range
                    offset = find_midnight_offset(handle, size, start_epoch)
                    handle.seek(offset)

                    for raw_line in handle:
                        if not raw_line.endswith(b"\n"):
                            break
                        sp = raw_line.find(b" ")
                        if sp > 0:
                            try:
                                ts = float(raw_line[:sp])
                                if ts < start_epoch:
                                    continue
                                if ts >= end_epoch:
                                    break
                            except ValueError:
                                continue
                        if not any(tok in raw_line for tok in FAILURE_CANDIDATE_BYTES):
                            continue
                        line_str = raw_line.decode("utf-8", errors="replace")
                        ev = parse_failure_line(line_str, devices=devices)
                        if ev:
                            if not client_ip or ev["client_ip"] == client_ip:
                                events.append(ev)
            else:
                with gzip.open(path, "rb") as handle:
                    first_line = handle.readline()
                    sp1 = first_line.find(b" ")
                    if sp1 > 0:
                        try:
                            t1 = float(first_line[:sp1])
                            if t1 >= end_epoch:
                                continue  # Entire compressed file is after target range
                        except ValueError:
                            pass
                    handle.seek(0)
                    for raw_line in handle:
                        sp = raw_line.find(b" ")
                        if sp > 0:
                            try:
                                ts = float(raw_line[:sp])
                                if ts < start_epoch:
                                    continue
                                if ts >= end_epoch:
                                    break
                            except ValueError:
                                continue
                        if not any(tok in raw_line for tok in FAILURE_CANDIDATE_BYTES):
                            continue
                        line_str = raw_line.decode("utf-8", errors="replace")
                        ev = parse_failure_line(line_str, devices=devices)
                        if ev:
                            if not client_ip or ev["client_ip"] == client_ip:
                                events.append(ev)
        except OSError:
            continue

    events.sort(key=lambda item: item["timestamp"], reverse=True)
    return build_failure_summary_from_events(
        events,
        start_epoch=start_epoch,
        end_epoch=end_epoch,
        devices_by_ip=devices,
        limit=limit,
    )


def find_midnight_offset(handle, file_size, midnight_epoch):
    """
    Quickly find the byte offset near midnight in an active access log using binary search.
    Avoids reading days of old log entries from the beginning of a large file.
    """
    if file_size <= 65536:
        return 0

    low = 0
    high = file_size

    while high - low > 32768:
        mid = (low + high) // 2
        handle.seek(mid)
        handle.readline()  # discard partial line
        line = handle.readline()
        if not line:
            high = mid
            continue
        sp = line.find(b" ")
        if sp > 0:
            try:
                ts = float(line[:sp])
                if ts < midnight_epoch:
                    low = mid
                else:
                    high = mid
            except ValueError:
                low = mid
        else:
            low = mid

    handle.seek(low)
    if low > 0:
        handle.readline()  # align to start of next full line
    return handle.tell()


class TodayFailureTracker:
    """
    In-memory live cache of today's non-policy failure events.
    Tracks file offset and size of the active access.log, persisted to disk cache.
    Subsequent calls only parse the delta appended since the last check,
    minimizing calculation time to sub-milliseconds.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.cached_date = None
        self.last_inode = None
        self.last_size = 0
        self.last_offset = 0
        self.today_events = []
        self.today_summary = None

    def reset(self, today_date):
        self.cached_date = today_date.isoformat()
        self.last_inode = None
        self.last_size = 0
        self.last_offset = 0
        self.today_events = []
        self.today_summary = None

    def get_today_summary(self):
        with self.lock:
            return dict(self.today_summary) if self.today_summary else None

    def get_today_events(self, access_log_path, devices_by_ip=None, force_refresh=False, cache_dir=None, target_date=None):
        today = target_date or date.today()
        today_iso = today.isoformat()
        midnight_epoch = datetime.combine(today, datetime_time.min).timestamp()
        end_of_day_epoch = datetime.combine(today + timedelta(days=1), datetime_time.min).timestamp()

        with self.lock:
            if force_refresh:
                self.reset(today)
            elif self.cached_date != today_iso:
                self.reset(today)
                if cache_dir:
                    found, cached_data = load_daily_failure_report(cache_dir, today)
                    if found and isinstance(cached_data, dict):
                        self.today_events = cached_data.get("events", [])
                        self.today_summary = cached_data.get("summary")
                        self.last_inode = cached_data.get("last_inode")
                        self.last_size = cached_data.get("last_size", 0)
                        self.last_offset = cached_data.get("last_offset", 0)

            if not os.path.exists(access_log_path):
                return list(self.today_events)

            try:
                st = os.stat(access_log_path)
            except OSError:
                return list(self.today_events)

            # Detect log rotation or truncation
            if self.last_inode is not None and (st.st_ino != self.last_inode or st.st_size < self.last_size):
                self.reset(today)

            # If file size and inode haven't changed, return cached events immediately (0ms)
            if self.last_inode == st.st_ino and st.st_size == self.last_size:
                if devices_by_ip:
                    for ev in self.today_events:
                        cip = ev.get("client_ip")
                        dev = devices_by_ip.get(cip)
                        if isinstance(dev, dict):
                            ev["client_name"] = dev.get("name") or dev.get("hostname") or cip
                        elif isinstance(dev, str):
                            ev["client_name"] = dev
                return list(self.today_events)

            # Can we do an incremental delta read?
            # Yes, if the file inode is unchanged, offset is valid, and we already hold today's baseline events.
            is_delta = (
                self.last_inode == st.st_ino and
                0 < self.last_offset <= st.st_size and
                bool(self.today_events)
            )

            new_events = []
            if is_delta:
                try:
                    with open(access_log_path, "rb") as handle:
                        handle.seek(self.last_offset)
                        offset = self.last_offset
                        for raw_line in handle:
                            if not raw_line.endswith(b"\n"):
                                break
                            offset += len(raw_line)
                            if not any(tok in raw_line for tok in FAILURE_CANDIDATE_BYTES):
                                continue
                            line_str = raw_line.decode("utf-8", errors="replace")
                            ev = parse_failure_line(line_str, devices=devices_by_ip)
                            if ev and midnight_epoch <= ev["timestamp"] < end_of_day_epoch:
                                new_events.append(ev)

                        self.last_offset = offset
                        self.last_size = st.st_size
                except OSError:
                    pass

                if new_events:
                    # New events are more recent than existing events; sort newest-first and prepend
                    new_events.sort(key=lambda item: item["timestamp"], reverse=True)
                    self.today_events = new_events + self.today_events
            else:
                # Cold start, rotation, or empty cache:
                # Parse full day across all log files (including rotated access.log.0) to establish complete baseline.
                baseline_summary, baseline_events = parse_failure_events(
                    access_log_path,
                    start_epoch=midnight_epoch,
                    end_epoch=end_of_day_epoch,
                    client_ip="",
                    devices_by_ip=devices_by_ip,
                    limit=None,
                )
                self.today_events = baseline_events
                self.today_summary = baseline_summary
                self.last_inode = st.st_ino
                self.last_size = st.st_size
                last_offset = st.st_size
                try:
                    with open(access_log_path, "rb") as handle:
                        if st.st_size > 0:
                            handle.seek(max(0, st.st_size - 4096))
                            chunk = handle.read()
                            last_nl = chunk.rfind(b"\n")
                            if last_nl != -1:
                                last_offset = max(0, st.st_size - 4096) + last_nl + 1
                            else:
                                last_offset = 0
                except OSError:
                    pass
                self.last_offset = last_offset

            if devices_by_ip:
                for ev in self.today_events:
                    cip = ev.get("client_ip")
                    dev = devices_by_ip.get(cip)
                    if isinstance(dev, dict):
                        ev["client_name"] = dev.get("name") or dev.get("hostname") or cip
                    elif isinstance(dev, str):
                        ev["client_name"] = dev

            # Persist updated today cache to disk so restarts and redeploys load instantly
            if cache_dir and (new_events or not is_delta):
                try:
                    summary, _ = build_failure_summary_from_events(
                        self.today_events,
                        start_epoch=midnight_epoch,
                        end_epoch=end_of_day_epoch,
                        devices_by_ip=devices_by_ip,
                        limit=None,
                    )
                    self.today_summary = summary
                    today_payload = {
                        "mode": "date",
                        "date": today_iso,
                        "start_epoch": midnight_epoch,
                        "end_epoch": end_of_day_epoch,
                        "last_inode": self.last_inode,
                        "last_size": self.last_size,
                        "last_offset": self.last_offset,
                        "cached": True,
                        "summary": summary,
                        "events": self.today_events[:5000],
                    }
                    save_daily_failure_report(cache_dir, today, today_payload)
                except Exception:
                    pass

            return list(self.today_events)


today_tracker = TodayFailureTracker()


def build_failure_summary_from_events(events, start_epoch=None, end_epoch=None, devices_by_ip=None, limit=None):
    """
    Compute structured summary KPI metrics and breakdown distributions from a list of failure events.
    """
    devices = devices_by_ip or {}
    domain_counts = Counter()
    domain_categories = defaultdict(Counter)
    client_counts = Counter()
    category_counts = Counter()
    status_counts = Counter()

    for event in events:
        dom = event.get("domain", "")
        cat = event.get("category", "Unknown")
        cip = event.get("client_ip", "")
        st = str(event.get("status", ""))

        domain_counts[dom] += 1
        domain_categories[dom][cat] += 1
        client_counts[cip] += 1
        category_counts[cat] += 1
        status_counts[st] += 1

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

    result_events = events
    if limit and len(result_events) > limit:
        result_events = result_events[:limit]

    return summary, result_events


def filter_cached_failure_report(cached_data, client_ip=None, limit=None):
    """
    Filter a full daily cached failure report in-memory by client_ip.
    Recalculates summary statistics in < 1ms without touching disk logs.
    """
    if not cached_data:
        return cached_data

    all_events = cached_data.get("events", [])
    if not client_ip:
        result_events = all_events[:limit] if (limit and len(all_events) > limit) else all_events
        return {
            **cached_data,
            "cached": True,
            "events": result_events,
        }

    filtered_events = [e for e in all_events if e.get("client_ip") == client_ip]

    devices_by_ip = {}
    for cl in cached_data.get("summary", {}).get("top_clients", []):
        if cl.get("client_ip"):
            devices_by_ip[cl["client_ip"]] = {"name": cl.get("client_name")}

    summary, events = build_failure_summary_from_events(
        filtered_events,
        start_epoch=cached_data.get("start_epoch"),
        end_epoch=cached_data.get("end_epoch"),
        devices_by_ip=devices_by_ip,
        limit=limit,
    )

    return {
        "mode": cached_data.get("mode", "date"),
        "date": cached_data.get("date"),
        "start_epoch": cached_data.get("start_epoch"),
        "end_epoch": cached_data.get("end_epoch"),
        "cached": True,
        "summary": summary,
        "events": events,
    }


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
