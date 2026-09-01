import os
import tempfile
import unittest
from datetime import date

from activity_reports import load_report, prune_reports, report_exists, save_reports


class ActivityReportCacheTests(unittest.TestCase):
    def test_round_trip_uses_private_permissions(self):
        target = date(2026, 8, 20)
        report = {"client_ip": "192.0.2.11", "requests": 3}
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = os.path.join(directory, "reports")
            save_reports(cache_dir, target, {"192.0.2.11": report})
            found, loaded = load_report(cache_dir, target, "192.0.2.11")

            self.assertTrue(found)
            self.assertEqual(loaded, report)
            self.assertEqual(os.stat(cache_dir).st_mode & 0o777, 0o700)
            self.assertEqual(
                os.stat(os.path.join(cache_dir, "2026-08-20.json")).st_mode & 0o777,
                0o600,
            )

    def test_cached_day_distinguishes_quiet_client_from_missing_file(self):
        target = date(2026, 8, 20)
        with tempfile.TemporaryDirectory() as directory:
            save_reports(directory, target, {})
            self.assertEqual(load_report(directory, target, "192.0.2.11"), (True, None))
            self.assertEqual(
                load_report(directory, date(2026, 8, 19), "192.0.2.11"),
                (False, None),
            )

    def test_prune_keeps_exactly_inclusive_retention_window(self):
        today = date(2026, 8, 27)
        with tempfile.TemporaryDirectory() as directory:
            save_reports(directory, date(2026, 5, 19), {})
            save_reports(directory, date(2026, 5, 20), {})
            save_reports(directory, today, {})
            self.assertEqual(prune_reports(directory, 100, today=today), 1)
            self.assertFalse(report_exists(directory, date(2026, 5, 19)))
            self.assertTrue(report_exists(directory, date(2026, 5, 20)))
            self.assertTrue(report_exists(directory, today))


if __name__ == "__main__":
    unittest.main()
