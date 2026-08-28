import copy
import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch

FLASK_AVAILABLE = importlib.util.find_spec("flask") is not None
if FLASK_AVAILABLE:
    import app as app_module
else:
    app_module = None


@unittest.skipUnless(FLASK_AVAILABLE, "Flask is not installed in the local test environment")
class AuditApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.audit_path = os.path.join(self.directory.name, "configuration_audit.jsonl")
        self.path_patch = patch.object(app_module, "SQUID_AUDIT_LOG", self.audit_path)
        self.path_patch.start()
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.path_patch.stop()
        self.directory.cleanup()

    def authenticate(self, username="admin-user"):
        with self.client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = username

    def test_policy_write_records_user_ip_timestamp_and_exact_change(self):
        self.authenticate()
        existing = {
            "192.0.2.10": {
                "ip": "192.0.2.10",
                "hostname": "test-client",
                "ssl_bump_mode": "blocked_only",
                "always_block": ["games.txt"],
                "always_allow": [],
                "default_block": [],
            }
        }
        with patch.object(app_module, "load_device_policies", return_value=copy.deepcopy(existing)), \
                patch.object(app_module, "save_device_policies", return_value=(True, "compiled")):
            response = self.client.post(
                "/api/policies",
                json={
                    "ip": "192.0.2.10",
                    "hostname": "test-client",
                    "always_block": ["adult.txt"],
                },
                environ_base={"REMOTE_ADDR": "192.0.2.200"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["audited"])
        with open(self.audit_path, "r", encoding="utf-8") as handle:
            event = json.loads(handle.readline())
        self.assertTrue(event["timestamp"])
        self.assertEqual(event["actor"]["username"], "admin-user")
        self.assertEqual(event["actor"]["client_ip"], "192.0.2.200")
        self.assertEqual(event["changes"][0]["before"], existing["192.0.2.10"])
        self.assertEqual(event["changes"][0]["after"]["always_block"], ["adult.txt"])
        self.assertEqual(os.stat(self.audit_path).st_mode & 0o777, 0o600)

    def test_audit_endpoint_requires_authentication_and_returns_newest_first(self):
        response = self.client.get("/api/audit-log")
        self.assertEqual(response.status_code, 401)

        self.authenticate()
        app_module.append_audit_record(self.audit_path, {"id": "older"})
        app_module.append_audit_record(self.audit_path, {"id": "newer"})
        response = self.client.get("/api/audit-log?limit=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([event["id"] for event in response.get_json()["events"]], ["newer"])


if __name__ == "__main__":
    unittest.main()
