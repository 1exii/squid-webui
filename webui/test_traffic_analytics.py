import os
import tempfile
import unittest
from datetime import date, datetime

from traffic_analytics import (
    categories_for_host,
    extract_hostname,
    parse_daily_events,
    registrable_domain,
    site_identity,
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

    def test_site_identity_groups_services_and_regular_subdomains(self):
        self.assertEqual(site_identity("r3---sn.example.googlevideo.com"), ("youtube", "YouTube"))
        self.assertEqual(site_identity("i.ytimg.com"), ("youtube", "YouTube"))
        self.assertEqual(site_identity("api.example.com"), ("example.com", "example.com"))
        self.assertEqual(registrable_domain("news.bbc.co.uk"), "bbc.co.uk")

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

    def test_summary_groups_domains_and_keeps_expandable_details(self):
        events = [
            {"timestamp": 100.0, "host": "youtube.com", "blocked": False},
            {"timestamp": 160.0, "host": "r1.googlevideo.com", "blocked": False},
            {"timestamp": 200.0, "host": "api.example.com", "blocked": False},
            {"timestamp": 220.0, "host": "www.example.com", "blocked": True},
        ]
        categories = {"videos": {"youtube.com", "googlevideo.com"}}
        summary = summarize_client_events(events, categories)
        youtube = next(site for site in summary["sites"] if site["site"] == "YouTube")
        example = next(site for site in summary["sites"] if site["site"] == "example.com")

        self.assertEqual(summary["unique_sites"], 2)
        self.assertEqual(summary["unique_domains"], 4)
        self.assertEqual(youtube["estimated_seconds"], 100)
        self.assertEqual(youtube["categories"], ["videos"])
        self.assertEqual(youtube["domain_count"], 2)
        self.assertEqual(example["blocked_requests"], 1)

    def test_parser_filters_day_client_and_ip_only_destinations(self):
        target = date(2026, 8, 21)
        stamp = datetime(2026, 8, 21, 12, 0).timestamp()
        other_day = datetime(2026, 8, 20, 12, 0).timestamp()
        lines = [
            f"{stamp} 10 192.0.2.11 TCP_TUNNEL/200 100 CONNECT example.com:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{stamp} 10 192.0.2.11 TCP_TUNNEL/200 100 CONNECT 1.2.3.4:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{stamp} 10 192.0.2.12 TCP_TUNNEL/200 100 CONNECT other.test:443 - HIER_DIRECT/1.2.3.4 -\n",
            f"{other_day} 10 192.0.2.11 TCP_TUNNEL/200 100 CONNECT old.test:443 - HIER_DIRECT/1.2.3.4 -\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "access.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(lines)
            events = parse_daily_events(path, target, "192.0.2.11")

        self.assertEqual([event["host"] for event in events["192.0.2.11"]], ["example.com"])

    def test_parser_includes_numbered_rotations(self):
        target = date(2026, 8, 21)
        stamp = datetime(2026, 8, 21, 12, 0).timestamp()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "access.log")
            for filename, host in (("access.log", "current.test"), ("access.log.0", "rotated.test")):
                with open(os.path.join(directory, filename), "w", encoding="utf-8") as handle:
                    handle.write(
                        f"{stamp} 10 192.0.2.11 TCP_TUNNEL/200 100 "
                        f"CONNECT {host}:443 - HIER_DIRECT/1.2.3.4 -\n"
                    )
            events = parse_daily_events(path, target, "192.0.2.11")

        self.assertEqual(
            sorted(event["host"] for event in events["192.0.2.11"]),
            ["current.test", "rotated.test"],
        )


if __name__ == "__main__":
    unittest.main()
