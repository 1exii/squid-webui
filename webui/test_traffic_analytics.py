import os
import tempfile
import unittest
from datetime import date, datetime

from traffic_analytics import (
    categories_for_host,
    extract_hostname,
    parse_daily_events,
    summarize_client_events,
)


class TrafficAnalyticsTests(unittest.TestCase):
    def test_extract_hostname_from_connect_and_url(self):
        self.assertEqual(extract_hostname("CONNECT", "www.Example.com:443"), "www.example.com")
        self.assertEqual(extract_hostname("GET", "https://video.example.com/watch?v=1"), "video.example.com")
        self.assertEqual(extract_hostname("GET", "error:transaction-end-before-headers"), "")

    def test_category_suffix_matching(self):
        categories = {"gaming": {"roblox.com"}, "videos": {"youtube.com"}}
        self.assertEqual(categories_for_host("users.roblox.com", categories), ["gaming"])
        self.assertEqual(categories_for_host("notroblox.com", categories), ["uncategorized"])

    def test_estimated_time_uses_next_request_and_idle_tail(self):
        events = [
            {"timestamp": 100.0, "host": "example.com", "blocked": False},
            {"timestamp": 160.0, "host": "video.test", "blocked": False},
            {"timestamp": 1000.0, "host": "example.com", "blocked": True},
        ]
        summary = summarize_client_events(events, {})
        self.assertEqual(summary["estimated_seconds"], 120)
        self.assertEqual(summary["blocked_requests"], 1)
        self.assertEqual(summary["sites"][0]["estimated_seconds"], 90)

    def test_parser_filters_day_client_and_ip_only_destinations(self):
        target = date(2026, 8, 21)
        stamp = datetime(2026, 8, 21, 12, 0).timestamp()
        other_day = datetime(2026, 8, 20, 12, 0).timestamp()
        lines = [
            f"{stamp} 10 192.168.1.11 TCP_TUNNEL/200 100 CONNECT example.com:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{stamp} 10 192.168.1.11 TCP_TUNNEL/200 100 CONNECT 1.2.3.4:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{stamp} 10 192.168.1.12 TCP_TUNNEL/200 100 CONNECT other.test:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{other_day} 10 192.168.1.11 TCP_TUNNEL/200 100 CONNECT old.test:443 - HIER_DIRECT/1.2.3.4 -\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "access.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(lines)
            events = parse_daily_events(path, target, "192.168.1.11")

        self.assertEqual([event["host"] for event in events["192.168.1.11"]], ["example.com"])

    def test_parser_includes_numbered_rotations(self):
        target = date(2026, 8, 21)
        stamp = datetime(2026, 8, 21, 12, 0).timestamp()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "access.log")
            for filename, host in (("access.log", "current.test"), ("access.log.0", "rotated.test")):
                with open(os.path.join(directory, filename), "w", encoding="utf-8") as handle:
                    handle.write(
                        f"{stamp} 10 192.168.1.11 TCP_TUNNEL/200 100 "
                        f"CONNECT {host}:443 - HIER_DIRECT/1.2.3.4 -\n"
                    )
            events = parse_daily_events(path, target, "192.168.1.11")

        self.assertEqual(
            sorted(event["host"] for event in events["192.168.1.11"]),
            ["current.test", "rotated.test"],
        )


if __name__ == "__main__":
    unittest.main()
