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


def save_reports(cache_dir, target_date, reports):
    """Atomically store every client report for a completed day."""
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(cache_dir, 0o700)
    except OSError:
        pass

    path = report_path(cache_dir, target_date)
    temporary = f"{path}.{os.getpid()}.tmp"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "date": target_date.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(cache_dir, os.O_RDONLY)
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
