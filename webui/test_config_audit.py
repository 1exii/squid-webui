import json
import os
import tempfile
import unittest

from config_audit import (
    append_audit_record,
    combine_audit_records,
    policy_changes,
    read_audit_records,
)


def audit_event(event_id, timestamp, target="192.0.2.1", username="admin",
                client_ip="192.0.2.200", before_value=0, after_value=1):
    return {
        "id": event_id,
        "timestamp": timestamp,
        "actor": {
            "authentication": "nas_session",
            "username": username,
            "client_ip": client_ip,
        },
        "source": "admin_api",
        "success": True,
        "message": "compiled",
        "changes": [{
            "device_ip": target,
            "hostname": "test-device",
            "kind": "device_updated",
            "changed_fields": ["always_block"],
            "before": {"hostname": "test-device", "value": before_value},
            "after": {"hostname": "test-device", "value": after_value},
        }],
    }


class ConfigAuditTests(unittest.TestCase):
    def test_policy_changes_omits_noop_and_keeps_exact_values(self):
        old = {"192.0.2.1": {"hostname": "kid", "always_block": ["games.txt"]}}
        self.assertEqual(policy_changes(old, old), [])

        new = {"192.0.2.1": {"hostname": "kid", "always_block": ["adult.txt"]}}
        changes = policy_changes(old, new)
        self.assertEqual(changes[0]["kind"], "device_updated")
        self.assertEqual(changes[0]["changed_fields"], ["always_block"])
        self.assertEqual(changes[0]["before"], old["192.0.2.1"])
        self.assertEqual(changes[0]["after"], new["192.0.2.1"])

    def test_added_and_removed_devices(self):
        old = {"192.0.2.1": {"hostname": "old"}}
        new = {"192.0.2.2": {"hostname": "new"}}
        changes = policy_changes(old, new)
        self.assertEqual([item["kind"] for item in changes], ["device_removed", "device_added"])

    def test_jsonl_is_newest_first_and_skips_corrupt_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "audit.jsonl")
            append_audit_record(path, {"id": "first"})
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("not-json\n")
            append_audit_record(path, {"id": "second"})
            self.assertEqual(
                [record["id"] for record in read_audit_records(path, limit=2)],
                ["second", "first"],
            )
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.readline()), {"id": "first"})

    def test_combines_three_same_actor_target_events_within_fixed_two_minutes(self):
        records = [
            audit_event("outside", "2026-08-26T10:02:01-07:00", before_value=3, after_value=4),
            audit_event("third", "2026-08-26T10:01:59-07:00", before_value=2, after_value=3),
            audit_event("second", "2026-08-26T10:01:00-07:00", before_value=1, after_value=2),
            audit_event("first", "2026-08-26T10:00:00-07:00", before_value=0, after_value=1),
        ]
        combined = combine_audit_records(records)
        self.assertEqual(len(combined), 2)
        self.assertEqual(combined[0]["id"], "outside")
        group = combined[1]
        self.assertEqual(group["event_count"], 3)
        self.assertEqual(group["first_timestamp"], "2026-08-26T10:00:00-07:00")
        self.assertEqual(group["timestamp"], "2026-08-26T10:01:59-07:00")
        self.assertEqual(group["changes"][0]["before"]["value"], 0)
        self.assertEqual(group["changes"][0]["after"]["value"], 3)

    def test_different_actor_ip_or_target_does_not_combine(self):
        records = [
            audit_event("target", "2026-08-26T10:00:30-07:00", target="192.0.2.2"),
            audit_event("ip", "2026-08-26T10:00:20-07:00", client_ip="192.0.2.201"),
            audit_event("user", "2026-08-26T10:00:10-07:00", username="other-admin"),
            audit_event("base", "2026-08-26T10:00:00-07:00"),
        ]
        self.assertEqual(len(combine_audit_records(records)), 4)

    def test_same_target_combines_across_an_intervening_other_target(self):
        records = [
            audit_event("a-second", "2026-08-26T10:01:00-07:00",
                        target="192.0.2.1", before_value=1, after_value=2),
            audit_event("b", "2026-08-26T10:00:30-07:00", target="192.0.2.2"),
            audit_event("a-first", "2026-08-26T10:00:00-07:00",
                        target="192.0.2.1", before_value=0, after_value=1),
        ]
        combined = combine_audit_records(records)
        self.assertEqual(len(combined), 2)
        self.assertEqual(combined[0]["event_count"], 2)
        self.assertEqual(combined[0]["changes"][0]["device_ip"], "192.0.2.1")
        self.assertEqual(combined[1]["id"], "b")

    def test_combined_revert_keeps_one_entry_and_marks_net_zero(self):
        records = [
            audit_event("revert", "2026-08-26T10:01:00-07:00", before_value=1, after_value=0),
            audit_event("change", "2026-08-26T10:00:00-07:00", before_value=0, after_value=1),
        ]
        combined = combine_audit_records(records)
        self.assertEqual(len(combined), 1)
        self.assertEqual(combined[0]["event_count"], 2)
        self.assertTrue(combined[0]["net_zero"])
        self.assertEqual(combined[0]["changes"][0]["before"],
                         combined[0]["changes"][0]["after"])


if __name__ == "__main__":
    unittest.main()
