import os
import tempfile
import unittest
from datetime import date, datetime

from overall_analytics import (
    aggregate_overall_reports,
    build_daily_overall_archive,
)


class OverallAnalyticsTests(unittest.TestCase):
    def test_daily_report_matches_goaccess_style_global_totals(self):
        target = date(2026, 8, 29)
        timestamp = datetime(2026, 8, 29, 10, 30).timestamp()
        lines = [
            f"{timestamp} 10 192.0.2.11 TCP_TUNNEL/200 100 CONNECT example.com:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{timestamp + 60} 20 192.0.2.12 TCP_DENIED/403 50 GET http://blocked.test/path - HIER_NONE/- -\n",
            f"{timestamp + 120} 30 192.0.2.11 TCP_HIT/200 200 GET http://example.com/file - HIER_NONE/- -\n",
            f"{datetime(2026, 8, 28, 10, 30).timestamp()} 10 192.0.2.11 TCP_TUNNEL/200 999 CONNECT old.test:443 - HIER_DIRECT/1.2.3.4 -\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "access.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(lines)
            report = build_daily_overall_archive(path, [target])[target.isoformat()]

        self.assertEqual(report["requests"], 3)
        self.assertEqual(report["bandwidth_bytes"], 350)
        self.assertEqual(report["unique_clients"], 2)
        self.assertEqual(report["unique_domains"], 2)
        self.assertEqual(report["blocked_requests"], 1)
        self.assertEqual(report["cache_hits"], 1)
        self.assertEqual(report["error_requests"], 1)
        self.assertEqual(report["average_response_ms"], 20)
        self.assertEqual(report["elapsed_ms"], 60)
        self.assertEqual(report["hourly"][0]["hour"], 10)

    def test_period_aggregation_preserves_unique_clients_and_destinations(self):
        first_day = date(2026, 8, 24)
        second_day = date(2026, 8, 25)
        lines = [
            f"{datetime(2026, 8, 24, 8).timestamp()} 10 192.0.2.11 TCP_TUNNEL/200 100 CONNECT example.com:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{datetime(2026, 8, 25, 9).timestamp()} 30 192.0.2.11 TCP_HIT/200 300 CONNECT example.com:443 - HIER_NONE/- -\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "access.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(lines)
            archive = build_daily_overall_archive(path, [first_day, second_day])

        report = aggregate_overall_reports(
            archive, "week", first_day, date(2026, 8, 30)
        )
        self.assertEqual(report["requests"], 2)
        self.assertEqual(report["bandwidth_bytes"], 400)
        self.assertEqual(report["unique_clients"], 1)
        self.assertEqual(report["unique_domains"], 1)
        self.assertEqual(report["days_covered"], 2)
        self.assertEqual(report["average_response_ms"], 20)
        self.assertEqual(report["domains"][0]["requests"], 2)


if __name__ == "__main__":
    unittest.main()
