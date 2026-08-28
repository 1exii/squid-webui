"""Append-only audit records for Squid policy configuration changes."""

from collections import deque
from datetime import datetime
import fcntl
import json
import os
import secrets


POLICY_FIELDS = ("hostname", "ssl_bump_mode", "always_block", "always_allow", "default_block")


def policy_changes(before, after):
    """Return exact, per-device before/after changes; omit no-op saves."""
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    changes = []
    for ip in sorted(set(before) | set(after)):
        old = before.get(ip)
        new = after.get(ip)
        if old == new:
            continue
        if old is None:
            kind = "device_added"
        elif new is None:
            kind = "device_removed"
        else:
            kind = "device_updated"
        changed_fields = [
            field for field in POLICY_FIELDS
            if (old or {}).get(field) != (new or {}).get(field)
        ]
        changes.append({
            "device_ip": ip,
            "hostname": (new or old or {}).get("hostname", ip),
            "kind": kind,
            "changed_fields": changed_fields,
            "before": old,
            "after": new,
        })
    return changes


def make_audit_record(actor, source, changes, success, message):
    """Build one versioned audit event using the server's local timezone."""
    return {
        "version": 1,
        "id": secrets.token_hex(12),
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "actor": actor,
        "source": source,
        "action": "policy_configuration_changed",
        "success": bool(success),
        "message": message,
        "changes": changes,
    }


def append_audit_record(path, record):
    """Append and fsync one JSONL record under an inter-process file lock."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_audit_records(path, limit=100):
    """Return newest-first records, ignoring an incomplete/corrupt line."""
    if not os.path.isfile(path):
        return []
    recent = deque(maxlen=limit)
    with open(path, "r", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        for line in handle:
            try:
                record = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(record, dict):
                recent.append(record)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return list(reversed(recent))
