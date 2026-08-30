"""GoAccess-style overall statistics derived from native Squid access logs."""

from collections import defaultdict
from datetime import datetime
import gzip

from traffic_analytics import extract_hostname, iter_access_log_paths


CACHE_HIT_PREFIXES = (
    "TCP_HIT/",
    "TCP_MEM_HIT/",
    "TCP_REFRESH_HIT/",
    "TCP_IMS_HIT/",
    "TCP_NEGATIVE_HIT/",
    "TCP_OFFLINE_HIT/",
)


def _open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _empty_accumulator():
    return {
        "requests": 0,
        "bandwidth_bytes": 0,
        "blocked_requests": 0,
        "cache_hits": 0,
        "error_requests": 0,
        "elapsed_ms": 0,
        "domains": {},
        "clients": {},
        "results": {},
        "methods": {},
        "hourly": {},
    }


def _counter_row(container, key, **identity):
    return container.setdefault(key, {
        **identity,
        "requests": 0,
        "bandwidth_bytes": 0,
        "blocked_requests": 0,
        "last_seen_epoch": 0,
    })


def _add_record(summary, timestamp, elapsed_ms, client_ip, result, bytes_sent, method, host):
    status = result.rsplit("/", 1)[-1] if "/" in result else "-"
    blocked = result.startswith("TCP_DENIED/") or status == "403"
    cache_hit = result.startswith(CACHE_HIT_PREFIXES)
    error = status.isdigit() and int(status) >= 400

    summary["requests"] += 1
    summary["bandwidth_bytes"] += bytes_sent
    summary["blocked_requests"] += int(blocked)
    summary["cache_hits"] += int(cache_hit)
    summary["error_requests"] += int(error)
    summary["elapsed_ms"] += elapsed_ms

    domain = _counter_row(summary["domains"], host, domain=host)
    client = _counter_row(summary["clients"], client_ip, client_ip=client_ip)
    result_row = _counter_row(summary["results"], result, result=result)
    method_row = _counter_row(summary["methods"], method, method=method)
    hour = datetime.fromtimestamp(timestamp).hour
    hour_row = _counter_row(summary["hourly"], hour, hour=hour)
    for row in (domain, client, result_row, method_row, hour_row):
        row["requests"] += 1
        row["bandwidth_bytes"] += bytes_sent
        row["blocked_requests"] += int(blocked)
        row["last_seen_epoch"] = max(row["last_seen_epoch"], timestamp)


def _finalize(summary, period, period_start, period_end, days_covered):
    def rows(name, identity):
        return sorted(
            summary[name].values(),
            key=lambda row: (-row["requests"], -row["bandwidth_bytes"], row[identity]),
        )

    requests = summary["requests"]
    return {
        "period": period,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "days_expected": (period_end - period_start).days + 1,
        "days_covered": days_covered,
        "requests": requests,
        "bandwidth_bytes": summary["bandwidth_bytes"],
        "blocked_requests": summary["blocked_requests"],
        "cache_hits": summary["cache_hits"],
        "cache_hit_percent": round(summary["cache_hits"] * 100 / requests, 1) if requests else 0,
        "error_requests": summary["error_requests"],
        "elapsed_ms": summary["elapsed_ms"],
        "average_response_ms": round(summary["elapsed_ms"] / requests) if requests else 0,
        "unique_clients": len(summary["clients"]),
        "unique_domains": len(summary["domains"]),
        "domains": rows("domains", "domain"),
        "clients": rows("clients", "client_ip"),
        "results": rows("results", "result"),
        "methods": rows("methods", "method"),
        "hourly": sorted(summary["hourly"].values(), key=lambda row: row["hour"]),
    }


def build_daily_overall_archive(access_log_path, target_dates):
    """Parse logs once and return one all-client report per requested date."""
    target_dates = set(target_dates)
    summaries = {target_date: _empty_accumulator() for target_date in target_dates}
    if not target_dates:
        return {}

    for path in iter_access_log_paths(access_log_path):
        try:
            with _open_log(path) as handle:
                for line in handle:
                    fields = line.split()
                    if len(fields) < 7:
                        continue
                    try:
                        timestamp = float(fields[0])
                        elapsed_ms = max(0, int(fields[1]))
                        bytes_sent = max(0, int(fields[4]))
                    except ValueError:
                        continue
                    target_date = datetime.fromtimestamp(timestamp).date()
                    if target_date not in target_dates:
                        continue
                    host = extract_hostname(fields[5], fields[6]) or "-"
                    _add_record(
                        summaries[target_date],
                        timestamp,
                        elapsed_ms,
                        fields[2],
                        fields[3],
                        bytes_sent,
                        fields[5],
                        host,
                    )
        except OSError:
            continue

    return {
        target_date.isoformat(): _finalize(
            summaries[target_date], "day", target_date, target_date, 1
        )
        for target_date in sorted(target_dates)
    }


def aggregate_overall_reports(daily_reports, period, period_start, period_end):
    """Merge complete or partial daily overall reports into a calendar period."""
    summary = _empty_accumulator()
    for report in daily_reports.values():
        for field in (
            "requests", "bandwidth_bytes", "blocked_requests", "cache_hits",
            "error_requests",
        ):
            summary[field] += report.get(field, 0)
        summary["elapsed_ms"] += report.get(
            "elapsed_ms",
            report.get("average_response_ms", 0) * report.get("requests", 0),
        )
        for collection, identity in (
            ("domains", "domain"),
            ("clients", "client_ip"),
            ("results", "result"),
            ("methods", "method"),
            ("hourly", "hour"),
        ):
            for source in report.get(collection, []):
                key = source[identity]
                target = _counter_row(summary[collection], key, **{identity: key})
                for field in ("requests", "bandwidth_bytes", "blocked_requests"):
                    target[field] += source.get(field, 0)
                target["last_seen_epoch"] = max(
                    target["last_seen_epoch"], source.get("last_seen_epoch", 0)
                )
    return _finalize(
        summary, period, period_start, period_end, len(daily_reports)
    )
