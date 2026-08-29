"""Append-only audit records for Squid policy configuration changes."""

from collections import deque
import copy
from datetime import datetime, timedelta
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
    recent = deque(maxlen=limit) if limit is not None else []
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


def _timestamp(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _actor_key(record):
    actor = record.get("actor") or {}
    return (
        actor.get("authentication", ""),
        actor.get("username", ""),
        actor.get("client_ip", ""),
    )


def _single_target(record):
    changes = record.get("changes") or []
    if len(changes) != 1 or not isinstance(changes[0], dict):
        return None
    return changes[0].get("device_ip")


def _can_combine(group, event, window_seconds):
    if _single_target(group) is None or _single_target(group) != _single_target(event):
        return False
    if _actor_key(group) != _actor_key(event):
        return False
    # Automated tasks remain independent from human/trusted-client changes.
    if _actor_key(event)[0] == "system" or group.get("source") != event.get("source"):
        return False
    first = _timestamp(group.get("first_timestamp", group.get("timestamp")))
    current = _timestamp(event.get("timestamp"))
    if first is None or current is None:
        return False
    elapsed = current - first
    return timedelta(0) <= elapsed <= timedelta(seconds=window_seconds)


def _combine_pair(group, event):
    combined = copy.deepcopy(group)
    old_change = combined["changes"][0]
    new_change = event["changes"][0]
    device_ip = old_change["device_ip"]
    before = old_change.get("before")
    after = new_change.get("after")
    net_changes = policy_changes({device_ip: before}, {device_ip: after})
    touched_fields = sorted(set(combined.get("touched_fields", old_change.get("changed_fields", []))) |
                            set(new_change.get("changed_fields", [])))

    if net_changes:
        change = net_changes[0]
        change["changed_fields"] = touched_fields
        net_zero = False
    else:
        # Preserve the touched fields when several changes ultimately revert to
        # the starting configuration; the raw JSONL events retain every step.
        change = copy.deepcopy(old_change)
        change.update({
            "hostname": (after or before or {}).get("hostname", device_ip),
            "kind": "device_updated",
            "before": before,
            "after": after,
            "changed_fields": touched_fields,
        })
        net_zero = True

    combined.update({
        "timestamp": event.get("timestamp"),
        "success": bool(combined.get("success")) and bool(event.get("success")),
        "message": event.get("message", combined.get("message", "")),
        "changes": [change],
        "event_count": combined.get("event_count", 1) + event.get("event_count", 1),
        "combined": True,
        "net_zero": net_zero,
        "touched_fields": touched_fields,
    })
    combined.setdefault("first_timestamp", group.get("timestamp"))
    combined_ids = list(combined.get("combined_event_ids", [group.get("id")]))
    combined_ids.extend(event.get("combined_event_ids", [event.get("id")]))
    combined["combined_event_ids"] = [event_id for event_id in combined_ids if event_id]
    return combined


def combine_audit_records(records, window_seconds=120):
    """Combine newest-first events within one fixed actor/device time window.

    Raw JSONL records are never changed. A group spans at most ``window_seconds``
    from its first event, so a long sequence of edits cannot extend forever.
    """
    groups = []
    for event in reversed(records):
        event = copy.deepcopy(event)
        matching_index = next(
            (index for index in range(len(groups) - 1, -1, -1)
             if _can_combine(groups[index], event, window_seconds)),
            None,
        )
        if matching_index is None:
            groups.append(event)
            continue

        combined = _combine_pair(groups[matching_index], event)
        # This event is now the group's latest timestamp. Move the group to the
        # end so reversing below still returns correct newest-first ordering.
        del groups[matching_index]
        groups.append(combined)
    return list(reversed(groups))
