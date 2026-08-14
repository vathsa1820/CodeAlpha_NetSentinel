"""
NetSentinel — Alert Parser Test Suite
Phase 4 — Alert Parser

Tests Snort fast-alert line parsing for ICMP, TCP, HTTP, and malformed inputs.
"""

import unittest
from engine.alert_parser import parse_alert_line, SnortAlertParser


class TestSnortAlertParser(unittest.TestCase):

    def test_1_icmp_alert_parsing(self):
        """Test parsing of ICMP alert (SID 9000001)."""
        raw_line = (
            "08/14-22:36:30.977554  [**] [1:9000001:1] [NetSentinel] ICMP Activity Detected "
            "[**] [Classification: Detection of a Network Scan] [Priority: 3] {ICMP} 127.0.0.1 -> 127.0.0.1"
        )
        alert = parse_alert_line(raw_line)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["sid"], 9000001)
        self.assertEqual(alert["revision"], 1)
        self.assertEqual(alert["message"], "[NetSentinel] ICMP Activity Detected")
        self.assertEqual(alert["classification"], "Detection of a Network Scan")
        self.assertEqual(alert["priority"], 3)
        self.assertEqual(alert["protocol"], "ICMP")
        self.assertEqual(alert["source_ip"], "127.0.0.1")
        self.assertIsNone(alert["source_port"])
        self.assertEqual(alert["destination_ip"], "127.0.0.1")
        self.assertIsNone(alert["destination_port"])

    def test_2_tcp_alert_parsing(self):
        """Test parsing of TCP alert (SID 9000002)."""
        raw_line = (
            "08/14-22:36:37.072228  [**] [1:9000002:1] [NetSentinel] Suspicious TCP Connection Attempt on Port 4444 "
            "[**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 127.0.0.1:55319 -> 127.0.0.1:4444"
        )
        alert = parse_alert_line(raw_line)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["sid"], 9000002)
        self.assertEqual(alert["protocol"], "TCP")
        self.assertEqual(alert["source_ip"], "127.0.0.1")
        self.assertEqual(alert["source_port"], 55319)
        self.assertEqual(alert["destination_ip"], "127.0.0.1")
        self.assertEqual(alert["destination_port"], 4444)
        self.assertEqual(alert["priority"], 2)

    def test_3_http_alert_parsing(self):
        """Test parsing of HTTP alert (SID 9000003)."""
        raw_line = (
            "08/14-22:36:39.154624  [**] [1:9000003:1] [NetSentinel] Suspicious HTTP Test Pattern Detected "
            "[**] [Classification: Web Application Attack] [Priority: 1] {TCP} 127.0.0.1:55320 -> 127.0.0.1:8080"
        )
        alert = parse_alert_line(raw_line)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["sid"], 9000003)
        self.assertEqual(alert["message"], "[NetSentinel] Suspicious HTTP Test Pattern Detected")
        self.assertEqual(alert["classification"], "Web Application Attack")
        self.assertEqual(alert["priority"], 1)
        self.assertEqual(alert["protocol"], "TCP")
        self.assertEqual(alert["source_ip"], "127.0.0.1")
        self.assertEqual(alert["source_port"], 55320)
        self.assertEqual(alert["destination_ip"], "127.0.0.1")
        self.assertEqual(alert["destination_port"], 8080)

    def test_4_malformed_input_handling(self):
        """Test that malformed lines, empty strings, and partial headers return None without crashing."""
        invalid_lines = [
            "",
            "   ",
            "Not a snort alert log line at all",
            "08/14-22:36:30.977554 [**] Broken line without SID",
            "08/14-22:36:30.977554  [**] [1:abc:1] [NetSentinel] Bad SID [**] {ICMP} 127.0.0.1 -> 127.0.0.1",
            "08/14-22:36:30.977554  [**] [1:9000001:1] Partial message",
        ]
        for line in invalid_lines:
            with self.subTest(line=line):
                result = parse_alert_line(line)
                self.assertIsNone(result, f"Expected None for line: {line}")


if __name__ == "__main__":
    unittest.main()
