"""Durable, privacy-sensitive cache for completed daily activity reports."""

import json
import os
from datetime import date, datetime, timedelta, timezone


SCHEMA_VERSION = 1


def report_path(cache_dir, target_date):
    return os.path.join(cache_dir, f"{target_date.isoformat()}.json")


def report_exists(cache_dir, target_date):
    return os.path.isfile(report_path(cache_dir, target_date))


def load_report(cache_dir, target_date, client_ip):
    """Return (cache_found, client_report). A cached quiet client is None."""
    path = report_path(cache_dir, target_date)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (payload.get("schema_version") != SCHEMA_VERSION or
                payload.get("date") != target_date.isoformat()):
            return False, None
        return True, payload.get("reports", {}).get(client_ip)
    except (OSError, ValueError, TypeError):
        return False, None


def load_reports(cache_dir, target_date):
    """Return (cache_found, all_client_reports) for one completed day."""
    path = report_path(cache_dir, target_date)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (payload.get("schema_version") != SCHEMA_VERSION or
                payload.get("date") != target_date.isoformat()):
            return False, {}
        reports = payload.get("reports", {})
        return (True, reports) if isinstance(reports, dict) else (False, {})
    except (OSError, ValueError, TypeError):
        return False, {}


def save_reports(cache_dir, target_date, reports):
    """Atomically store every client report for a completed day."""
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(cache_dir, 0o700)
    except OSError:
        pass

    payload = {
        "schema_version": SCHEMA_VERSION,
        "date": target_date.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }
    _save_payload(cache_dir, report_path(cache_dir, target_date), payload)


def period_report_path(cache_dir, period, period_start):
    if period not in ("week", "month"):
        raise ValueError("period must be week or month")
    return os.path.join(cache_dir, f"{period}ly", f"{period_start.isoformat()}.json")


def period_report_exists(cache_dir, period, period_start):
    return os.path.isfile(period_report_path(cache_dir, period, period_start))


def load_period_report(cache_dir, period, period_start, period_end, client_ip):
    """Return a selected client report from a saved weekly/monthly snapshot."""
    path = period_report_path(cache_dir, period, period_start)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (payload.get("schema_version") != SCHEMA_VERSION or
                payload.get("period") != period or
                payload.get("period_start") != period_start.isoformat() or
                payload.get("period_end") != period_end.isoformat()):
            return False, None
        return True, payload.get("reports", {}).get(client_ip)
    except (OSError, ValueError, TypeError):
        return False, None


def save_period_reports(cache_dir, period, period_start, period_end, reports):
    """Atomically store all client reports for one completed calendar period."""
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(cache_dir, 0o700)
    except OSError:
        pass
    directory = os.path.dirname(period_report_path(cache_dir, period, period_start))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "period": period,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }
    _save_payload(
        directory,
        period_report_path(cache_dir, period, period_start),
        payload,
    )


def _save_payload(directory, path, payload):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

    temporary = f"{path}.{os.getpid()}.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def prune_reports(cache_dir, retention_days, today=None):
    """Delete dated cache files outside the inclusive retention window."""
    today = today or date.today()
    oldest = today - timedelta(days=retention_days - 1)
    try:
        names = os.listdir(cache_dir)
    except OSError:
        return 0

    removed = 0
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            target_date = date.fromisoformat(name[:-5])
        except ValueError:
            continue
        if target_date < oldest or target_date > today:
            try:
                os.unlink(os.path.join(cache_dir, name))
                removed += 1
            except OSError:
                pass
    return removed


def prune_period_reports(cache_dir, retention_days, today=None):
    """Delete weekly/monthly snapshots whose calendar period is outside retention."""
    today = today or date.today()
    oldest = today - timedelta(days=retention_days - 1)
    removed = 0
    for period in ("week", "month"):
        directory = os.path.join(cache_dir, f"{period}ly")
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(directory, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                period_end = date.fromisoformat(payload["period_end"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if period_end < oldest or period_end > today:
                try:
                    os.unlink(path)
                    removed += 1
                except OSError:
                    pass
    return removed


def overall_report_path(cache_dir, period, period_start):
    if period not in ("day", "week", "month"):
        raise ValueError("period must be day, week, or month")
    directory = "daily" if period == "day" else f"{period}ly"
    return os.path.join(
        cache_dir, "overall", directory, f"{period_start.isoformat()}.json"
    )


def overall_report_exists(cache_dir, period, period_start):
    return os.path.isfile(overall_report_path(cache_dir, period, period_start))


def load_overall_report(cache_dir, period, period_start, period_end):
    path = overall_report_path(cache_dir, period, period_start)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (payload.get("schema_version") != SCHEMA_VERSION or
                payload.get("period") != period or
                payload.get("period_start") != period_start.isoformat() or
                payload.get("period_end") != period_end.isoformat()):
            return False, None
        report = payload.get("report")
        return (True, report) if isinstance(report, dict) else (False, None)
    except (OSError, ValueError, TypeError):
        return False, None


def save_overall_report(cache_dir, period, period_start, period_end, report):
    """Atomically save one all-client day/week/month analytics report."""
    path = overall_report_path(cache_dir, period, period_start)
    directory = os.path.dirname(path)
    overall_root = os.path.join(cache_dir, "overall")
    for private_dir in (cache_dir, overall_root):
        os.makedirs(private_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(private_dir, 0o700)
        except OSError:
            pass
    payload = {
        "schema_version": SCHEMA_VERSION,
        "period": period,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report": report,
    }
    _save_payload(directory, path, payload)


def prune_overall_reports(cache_dir, retention_days, today=None):
    """Delete all-client reports whose period falls outside the retention window."""
    today = today or date.today()
    oldest = today - timedelta(days=retention_days - 1)
    removed = 0
    for directory_name in ("daily", "weekly", "monthly"):
        directory = os.path.join(cache_dir, "overall", directory_name)
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(directory, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                period_end = date.fromisoformat(payload["period_end"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if period_end < oldest or period_end > today:
                try:
                    os.unlink(path)
                    removed += 1
                except OSError:
                    pass
    return removed
