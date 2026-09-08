import os
import tempfile
import unittest
from datetime import date, timedelta
from failure_analytics import (
    classify_failure,
    is_policy_block,
    is_failure_event,
    build_copyable_prompt,
    parse_failure_events,
    load_daily_failure_report,
    save_daily_failure_report,
    prune_failure_reports,
    filter_cached_failure_report,
    build_failure_summary_from_events,
    find_midnight_offset,
    TodayFailureTracker,
)


SAMPLE_LOG_LINES = [
    # Normal success (should be ignored)
    "1788678010.373 4 192.168.2.1 NONE_NONE/200 0 CONNECT www.google.com:443 - HIER_NONE/- -",
    # Policy block (should be ignored)
    "1788678015.100 2 192.168.2.1 TCP_DENIED/403 3584 CONNECT tiktok.com:443 - HIER_NONE/- -",
    # Block redirect (should be ignored)
    "1788678016.100 5 192.168.2.1 TCP_MISS/302 450 GET http://192.168.1.91:3131/blocked?domain=gaming.com - HIER_DIRECT/192.168.1.91 text/html",
    # 500 Internal error / tunnel terminated (failure)
    "1788678019.588 120972 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT ac-api.x-camp.xinyoudui.com:443 - HIER_DIRECT/128.1.26.196 -",
    # 503 DNS / IPv6 unreachable (failure)
    "1788678037.505 4 192.168.2.1 TCP_MISS/503 3488 GET http://ipv6.msftconnecttest.com/connecttest.txt - HIER_DIRECT/2600:1406:bc00:d::1742:351 text/html",
    # 400 Invalid request (failure)
    "1788678039.850 0 192.168.2.2 NONE_NONE/400 3366 - error:invalid-request - HIER_NONE/- text/html",
    # 502 Bad gateway (failure)
    "1788678045.200 15 192.168.2.1 TCP_MISS/502 1200 GET http://badgateway.example.com/ - HIER_DIRECT/93.184.216.34 text/html",
    # 504 Gateway timeout (failure)
    "1788678050.300 60000 192.168.2.1 TCP_MISS/504 1200 GET http://slowservice.example.com/ - HIER_DIRECT/93.184.216.34 text/html",
    # 409 Host header mismatch (failure)
    "1788678055.400 8 192.168.2.1 NONE_NONE/409 1500 CONNECT catalog.gamepass.com:443 - error:host-header-mismatch text/html",
]


class FailureClassificationTests(unittest.TestCase):
    def test_policy_blocks_are_identified(self):
        self.assertTrue(is_policy_block("TCP_DENIED/403", "403", "https://example.com"))
        self.assertTrue(is_policy_block("TCP_DENIED/200", "200", "https://example.com"))
        self.assertTrue(is_policy_block("TCP_MISS/302", "302", "http://proxy.local/blocked?domain=foo"))
        self.assertFalse(is_policy_block("TCP_TUNNEL/500", "500", "https://example.com"))
        self.assertFalse(is_policy_block("TCP_MISS/503", "503", "https://example.com"))

    def test_failure_event_detection(self):
        self.assertTrue(is_failure_event("TCP_TUNNEL/500", "500", "https://example.com"))
        self.assertTrue(is_failure_event("TCP_MISS/502", "502", "https://example.com"))
        self.assertTrue(is_failure_event("TCP_MISS/503", "503", "https://example.com"))
        self.assertTrue(is_failure_event("TCP_MISS/504", "504", "https://example.com"))
        self.assertTrue(is_failure_event("NONE_NONE/400", "400", "error:invalid-request"))
        self.assertTrue(is_failure_event("NONE_NONE/409", "409", "https://example.com"))
        self.assertTrue(is_failure_event("TCP_RESET/000", "000", "https://example.com"))

        # Successes and policy blocks are not unexpected failures
        self.assertFalse(is_failure_event("TCP_TUNNEL/200", "200", "https://example.com"))
        self.assertFalse(is_failure_event("TCP_DENIED/403", "403", "https://example.com"))

    def test_classify_failure_categories(self):
        cat_503, exp_503, _ = classify_failure("503", "TCP_MISS/503", "")
        self.assertIn("DNS", cat_503)

        cat_502, exp_502, _ = classify_failure("502", "TCP_MISS/502", "")
        self.assertIn("Gateway", cat_502)

        cat_500, exp_500, _ = classify_failure("500", "TCP_TUNNEL/500", "")
        self.assertIn("Tunnel", cat_500)

        cat_409, exp_409, _ = classify_failure("409", "NONE_NONE/409", "")
        self.assertIn("Mismatch", cat_409)

        cat_err, _, _ = classify_failure("-", "NONE_NONE/-", "error:invalid-request")
        self.assertIn("Malformed", cat_err)


class FailureLogParsingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "access.log")
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(SAMPLE_LOG_LINES) + "\n")
        self.devices = {
            "192.168.2.1": {"name": "Gaming-PC", "ip": "192.168.2.1"},
            "192.168.2.2": {"name": "Laptop", "ip": "192.168.2.2"},
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_parsing_extracts_only_failures(self):
        summary, events = parse_failure_events(
            self.log_path,
            start_epoch=1788678000.0,
            end_epoch=1788678100.0,
            devices_by_ip=self.devices,
        )
        # Expected failures: 500, 503, 400, 502, 504, 409 -> 6 failures
        self.assertEqual(summary["total_failures"], 6)
        self.assertEqual(len(events), 6)

        # Check device mapping
        event_domains = {e["domain"] for e in events}
        self.assertIn("ac-api.x-camp.xinyoudui.com", event_domains)
        self.assertIn("ipv6.msftconnecttest.com", event_domains)
        self.assertIn("catalog.gamepass.com", event_domains)

        # Check prompt generation
        prompt = events[0]["copyable_prompt"]
        self.assertIn("### Squid Proxy Access Failure Report", prompt)
        self.assertIn("#### Raw Squid Access Log Line:", prompt)
        self.assertIn("#### Diagnostic Prompt:", prompt)

    def test_client_ip_filtering(self):
        summary, events = parse_failure_events(
            self.log_path,
            start_epoch=1788678000.0,
            end_epoch=1788678100.0,
            client_ip="192.168.2.2",
            devices_by_ip=self.devices,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["client_ip"], "192.168.2.2")
        self.assertEqual(events[0]["client_name"], "Laptop")

    def test_find_midnight_offset_large_file(self):
        import io
        from datetime import datetime, time as dt_time
        midnight_epoch = datetime.combine(date.today(), dt_time.min).timestamp()

        buf = io.BytesIO()
        # 3,000 lines before midnight
        for i in range(3000):
            ts = midnight_epoch - 3000 + i
            buf.write(f"{ts:.3f} 10 192.168.1.1 TCP_MISS/500 100 GET http://before{i}.com/ - HIER_NONE/- -\n".encode("utf-8"))

        pos_midnight = buf.tell()

        # 3,000 lines after midnight
        for i in range(3000):
            ts = midnight_epoch + i
            buf.write(f"{ts:.3f} 10 192.168.1.1 TCP_MISS/500 100 GET http://after{i}.com/ - HIER_NONE/- -\n".encode("utf-8"))

        file_size = buf.tell()
        offset = find_midnight_offset(buf, file_size, midnight_epoch)
        self.assertLessEqual(offset, pos_midnight)
        buf.seek(offset)
        line = buf.readline()
        ts = float(line.split()[0])
        self.assertLessEqual(ts, midnight_epoch)


class FailureCacheAndPruningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache_dir = os.path.join(self.tmp.name, "failure-reports")

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_and_load_daily_report(self):
        target_date = date(2026, 8, 15)
        report_data = {
            "summary": {"total_failures": 3},
            "events": [{"domain": "failed.com", "status": "503"}],
        }
        save_daily_failure_report(self.cache_dir, target_date, report_data)

        found, loaded = load_daily_failure_report(self.cache_dir, target_date)
        self.assertTrue(found)
        self.assertEqual(loaded["summary"]["total_failures"], 3)
        self.assertEqual(loaded["events"][0]["domain"], "failed.com")

    def test_pruning_removes_reports_older_than_retention_days(self):
        today = date(2026, 9, 7)
        recent_date = today - timedelta(days=5)
        expired_date = today - timedelta(days=35)

        save_daily_failure_report(self.cache_dir, recent_date, {"summary": {}})
        save_daily_failure_report(self.cache_dir, expired_date, {"summary": {}})

        removed = prune_failure_reports(self.cache_dir, retention_days=30, today=today)
        self.assertEqual(removed, 1)

        found_recent, _ = load_daily_failure_report(self.cache_dir, recent_date)
        found_expired, _ = load_daily_failure_report(self.cache_dir, expired_date)

        self.assertTrue(found_recent)
        self.assertFalse(found_expired)

    def test_filter_cached_failure_report_by_client(self):
        cached_data = {
            "mode": "date",
            "date": "2026-09-06",
            "start_epoch": 1000.0,
            "end_epoch": 2000.0,
            "summary": {
                "total_failures": 3,
                "top_clients": [
                    {"client_ip": "192.168.1.50", "client_name": "Phone"},
                    {"client_ip": "192.168.1.60", "client_name": "Laptop"},
                ],
            },
            "events": [
                {"domain": "siteA.com", "client_ip": "192.168.1.50", "status": "503", "category": "Upstream Unreachable"},
                {"domain": "siteB.com", "client_ip": "192.168.1.50", "status": "502", "category": "Bad Gateway"},
                {"domain": "siteC.com", "client_ip": "192.168.1.60", "status": "504", "category": "Gateway Timeout"},
            ],
        }

        # Filter for Phone (192.168.1.50)
        res_phone = filter_cached_failure_report(cached_data, client_ip="192.168.1.50")
        self.assertTrue(res_phone["cached"])
        self.assertEqual(res_phone["summary"]["total_failures"], 2)
        self.assertEqual(res_phone["summary"]["unique_domains"], 2)
        self.assertEqual(res_phone["summary"]["unique_clients"], 1)
        self.assertEqual(len(res_phone["events"]), 2)
        self.assertEqual(res_phone["summary"]["category_counts"]["Upstream Unreachable"], 1)
        self.assertEqual(res_phone["summary"]["category_counts"]["Bad Gateway"], 1)

        # Filter for Laptop (192.168.1.60)
        res_laptop = filter_cached_failure_report(cached_data, client_ip="192.168.1.60")
        self.assertEqual(res_laptop["summary"]["total_failures"], 1)
        self.assertEqual(len(res_laptop["events"]), 1)
        self.assertEqual(res_laptop["events"][0]["domain"], "siteC.com")

        # Without client filter: returns all 3
        res_all = filter_cached_failure_report(cached_data, client_ip="")
        self.assertEqual(len(res_all["events"]), 3)


class TodayFailureTrackerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "access.log")
        self.tracker = TodayFailureTracker()
        self.devices = {
            "192.168.2.1": {"name": "PC-1"},
            "192.168.2.2": {"name": "Phone-2"},
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_incremental_reading_and_caching(self):
        import time
        now = time.time()
        line1 = f"{now - 100:.3f} 120 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT api1.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line1)

        # Initial read
        events1 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events1), 1)
        self.assertEqual(events1[0]["domain"], "api1.example.com")
        self.assertEqual(events1[0]["client_name"], "PC-1")

        # Second read without file changes: returns cached instantly
        events2 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events2), 1)

        # Append new failure line (delta)
        line2 = f"{now - 50:.3f} 10 192.168.2.2 TCP_MISS/503 3488 GET http://api2.example.com/test - HIER_DIRECT/1.2.3.5 text/html\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line2)

        # Incremental read should pick up delta
        events3 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events3), 2)
        domains = [e["domain"] for e in events3]
        self.assertIn("api1.example.com", domains)
        self.assertIn("api2.example.com", domains)

    def test_log_truncation_or_rotation_triggers_reset(self):
        import time
        now = time.time()
        line1 = f"{now - 10:.3f} 120 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT api1.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line1 * 10)

        events1 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events1), 10)

        # Truncate file (smaller size)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line1 * 2)

        # Tracker detects truncation (size < last_size) and resets
        events2 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events2), 2)

    def test_partial_line_at_eof_not_lost(self):
        import time
        now = time.time()
        complete_line = f"{now - 10:.3f} 120 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT api1.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        partial_line = f"{now - 5:.3f} 10 192.168.2.2 TCP_MISS/503 3488 GET http://api2.example.com/test" # no trailing newline

        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(complete_line + partial_line)

        # First read: only complete_line is parsed
        events1 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events1), 1)
        self.assertEqual(events1[0]["domain"], "api1.example.com")

        # Later, rest of line is appended with newline
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(" - HIER_DIRECT/1.2.3.5 text/html\n")

        # Second read: now complete line 2 is parsed without skipping
        events2 = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events2), 2)
        domains = [e["domain"] for e in events2]
        self.assertIn("api1.example.com", domains)
        self.assertIn("api2.example.com", domains)

    def test_rotated_log_files_included_in_baseline(self):
        import time
        now = time.time()
        # Older failure earlier today in rotated access.log.0
        rotated_log = f"{self.log_path}.0"
        line0 = f"{now - 200:.3f} 120 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT old-today.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(rotated_log, "w", encoding="utf-8") as f:
            f.write(line0)

        # Recent failure in active access.log
        line1 = f"{now - 50:.3f} 120 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT recent.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line1)

        events = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        domains = [e["domain"] for e in events]
        self.assertEqual(len(events), 2)
        self.assertIn("old-today.example.com", domains)
        self.assertIn("recent.example.com", domains)
        # Should be newest first
        self.assertEqual(events[0]["domain"], "recent.example.com")
        self.assertEqual(events[1]["domain"], "old-today.example.com")

    def test_get_today_summary_caching(self):
        import time
        now = time.time()
        line = f"{now - 10:.3f} 50 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT summary.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        events = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices)
        self.assertEqual(len(events), 1)

        summary = self.tracker.get_today_summary()
        self.assertIsNotNone(summary)
        self.assertEqual(summary["total_failures"], 1)
        self.assertEqual(summary["unique_domains"], 1)
        self.assertEqual(summary["top_domains"][0]["domain"], "summary.example.com")

    def test_today_disk_caching_and_event_capping(self):
        import time
        now = time.time()
        cache_dir = os.path.join(self.tmp.name, "cache")
        line = f"{now - 5:.3f} 50 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT capped.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        # Reads and writes to disk cache
        events = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices, cache_dir=cache_dir)
        self.assertEqual(len(events), 1)

        # Verify cached report was saved to disk
        found, cached_payload = load_daily_failure_report(cache_dir, date.today())
        self.assertTrue(found)
        self.assertEqual(cached_payload["summary"]["total_failures"], 1)
        self.assertIn("capped.example.com", [e["domain"] for e in cached_payload["events"]])

    def test_explicit_target_date_parameter(self):
        import time
        now = time.time()
        past_target = date.today() - timedelta(days=2)
        # Event timestamp exactly inside past_target calendar day
        from datetime import datetime, time as dt_time
        target_epoch = datetime.combine(past_target, dt_time(12, 0)).timestamp()
        line = f"{target_epoch:.3f} 50 192.168.2.1 TCP_TUNNEL/500 3088 CONNECT pastday.example.com:443 - HIER_DIRECT/1.2.3.4 -\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line)

        events = self.tracker.get_today_events(self.log_path, devices_by_ip=self.devices, target_date=past_target)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["domain"], "pastday.example.com")


try:
    from app import app
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


@unittest.skipUnless(HAS_FLASK, "Flask not installed in local test environment")
class FailureApiEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_api_failure_analytics_window(self):
        resp = self.client.get("/api/failure-analytics?window=1h")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["mode"], "window")
        self.assertIn("summary", data)
        self.assertIn("events", data)

    def test_api_failure_analytics_date(self):
        today_str = date.today().isoformat()
        resp = self.client.get(f"/api/failure-analytics?date={today_str}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["mode"], "date")
        self.assertEqual(data["date"], today_str)
        self.assertIn("summary", data)
        self.assertIn("events", data)

    def test_api_failure_analytics_limit_parameter(self):
        today_str = date.today().isoformat()
        resp = self.client.get(f"/api/failure-analytics?date={today_str}&limit=2")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertLessEqual(len(data.get("events", [])), 2)

    def test_api_failure_analytics_timezone_tolerance(self):
        tomorrow_str = (date.today() + timedelta(days=1)).isoformat()
        resp = self.client.get(f"/api/failure-analytics?date={tomorrow_str}")
        # Next-day date should be tolerated due to timezone differences and return 200 OK
        self.assertEqual(resp.status_code, 200)

    def test_api_failure_analytics_client_filter(self):
        today_str = date.today().isoformat()
        resp = self.client.get(f"/api/failure-analytics?date={today_str}&client_ip=192.168.1.99")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("summary", data)
        self.assertIn("events", data)
        for ev in data.get("events", []):
            self.assertEqual(ev.get("client_ip"), "192.168.1.99")


if __name__ == "__main__":
    unittest.main()
