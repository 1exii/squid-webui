import os
import tempfile
import unittest
from datetime import date

from activity_reports import (
    load_period_report,
    load_overall_report,
    load_report,
    load_reports,
    period_report_exists,
    overall_report_exists,
    prune_period_reports,
    prune_reports,
    report_exists,
    save_period_reports,
    save_overall_report,
    save_reports,
)


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

    def test_load_reports_returns_all_clients_for_period_aggregation(self):
        target = date(2026, 8, 20)
        reports = {
            "192.0.2.11": {"requests": 3},
            "192.0.2.12": {"requests": 5},
        }
        with tempfile.TemporaryDirectory() as directory:
            save_reports(directory, target, reports)
            self.assertEqual(load_reports(directory, target), (True, reports))

    def test_period_round_trip_and_pruning_use_private_subdirectories(self):
        today = date(2026, 8, 29)
        old_start = date(2025, 8, 18)
        old_end = date(2025, 8, 24)
        kept_start = date(2025, 9, 1)
        kept_end = date(2025, 9, 7)
        report = {"client_ip": "192.0.2.11", "requests": 7}
        with tempfile.TemporaryDirectory() as directory:
            save_period_reports(
                directory, "week", old_start, old_end, {"192.0.2.11": report}
            )
            save_period_reports(
                directory, "week", kept_start, kept_end, {"192.0.2.11": report}
            )
            found, loaded = load_period_report(
                directory, "week", kept_start, kept_end, "192.0.2.11"
            )

            self.assertTrue(found)
            self.assertEqual(loaded, report)
            self.assertEqual(os.stat(os.path.join(directory, "weekly")).st_mode & 0o777, 0o700)
            self.assertEqual(
                os.stat(os.path.join(directory, "weekly", "2025-09-01.json")).st_mode & 0o777,
                0o600,
            )
            self.assertEqual(prune_period_reports(directory, 365, today=today), 1)
            self.assertFalse(period_report_exists(directory, "week", old_start))
            self.assertTrue(period_report_exists(directory, "week", kept_start))

    def test_overall_report_round_trip_uses_private_storage(self):
        target = date(2026, 8, 29)
        report = {"period": "day", "requests": 42, "bandwidth_bytes": 2048}
        with tempfile.TemporaryDirectory() as directory:
            save_overall_report(
                directory, "day", target, target, report
            )
            found, loaded = load_overall_report(
                directory, "day", target, target
            )

            self.assertTrue(found)
            self.assertEqual(loaded, report)
            self.assertTrue(overall_report_exists(directory, "day", target))
            self.assertEqual(
                os.stat(os.path.join(directory, "overall")).st_mode & 0o777,
                0o700,
            )
            self.assertEqual(
                os.stat(os.path.join(
                    directory, "overall", "daily", "2026-08-29.json"
                )).st_mode & 0o777,
                0o600,
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
