import json
import os
import tempfile
import unittest

from config_audit import append_audit_record, policy_changes, read_audit_records


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


if __name__ == "__main__":
    unittest.main()
