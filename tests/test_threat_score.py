"""
NetSentinel — Threat Scoring Test Suite
Phase 5 — Threat Scoring

Tests deterministic threat scoring, risk level mapping, and boundary clamping.
"""

import unittest
from engine.threat_score import calculate_threat_score, calculate_risk_level


class TestThreatScoringEngine(unittest.TestCase):

    def test_1_icmp_scoring(self):
        """Test ICMP alert (SID 9000001) returns Score 30 and MEDIUM risk."""
        alert = {
            "timestamp": "08/14-22:36:30.977554",
            "sid": 9000001,
            "revision": 1,
            "message": "[NetSentinel] ICMP Activity Detected",
            "classification": "Detection of a Network Scan",
            "priority": 3,
            "protocol": "ICMP",
            "source_ip": "127.0.0.1",
            "source_port": None,
            "destination_ip": "127.0.0.1",
            "destination_port": None,
        }
        result = calculate_threat_score(alert)
        self.assertEqual(result["score"], 30)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertIn("ICMP activity detected", result["reason"])

    def test_2_tcp_port_4444_scoring(self):
        """Test TCP Port 4444 alert (SID 9000002) returns Score 60 and HIGH risk."""
        alert = {
            "timestamp": "08/14-22:36:37.072228",
            "sid": 9000002,
            "revision": 1,
            "message": "[NetSentinel] Suspicious TCP Connection Attempt on Port 4444",
            "classification": "Attempted Information Leak",
            "priority": 2,
            "protocol": "TCP",
            "source_ip": "127.0.0.1",
            "source_port": 55319,
            "destination_ip": "127.0.0.1",
            "destination_port": 4444,
        }
        result = calculate_threat_score(alert)
        self.assertEqual(result["score"], 60)  # 50 base + 10 port modifier = 60
        self.assertEqual(result["risk_level"], "HIGH")

    def test_3_http_scoring(self):
        """Test HTTP alert (SID 9000003) returns Score 75 and HIGH risk."""
        alert = {
            "timestamp": "08/14-22:36:39.154624",
            "sid": 9000003,
            "revision": 1,
            "message": "[NetSentinel] Suspicious HTTP Test Pattern Detected",
            "classification": "Web Application Attack",
            "priority": 1,
            "protocol": "TCP",
            "source_ip": "127.0.0.1",
            "source_port": 55320,
            "destination_ip": "127.0.0.1",
            "destination_port": 8080,
        }
        result = calculate_threat_score(alert)
        self.assertEqual(result["score"], 75)  # 70 base + 5 HTTP modifier = 75
        self.assertEqual(result["risk_level"], "HIGH")

    def test_4_unknown_sid_fallback(self):
        """Test unknown SID falls back to Snort priority score."""
        alert = {
            "timestamp": "08/14-22:40:00.000000",
            "sid": 9999999,
            "revision": 1,
            "message": "Custom Unknown Alert",
            "classification": "Generic Threat",
            "priority": 2,
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "source_port": 12345,
            "destination_ip": "192.168.1.5",
            "destination_port": 80,
        }
        result = calculate_threat_score(alert)
        self.assertEqual(result["score"], 50)  # Priority 2 -> Base 50
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_5_missing_priority_fallback(self):
        """Test alert with missing priority falls back to base score 20."""
        alert = {
            "timestamp": "08/14-22:40:00.000000",
            "sid": 9999999,
            "revision": 1,
            "message": "Alert Without Priority",
            "classification": None,
            "priority": None,
            "protocol": "UDP",
            "source_ip": "10.0.0.1",
            "source_port": 53,
            "destination_ip": "10.0.0.2",
            "destination_port": 53,
        }
        result = calculate_threat_score(alert)
        self.assertEqual(result["score"], 20)
        self.assertEqual(result["risk_level"], "LOW")

    def test_6_score_boundary(self):
        """Test that threat scores are clamped to [0, 100] boundary."""
        alert = {
            "timestamp": "08/14-22:40:00.000000",
            "sid": 9000003,
            "revision": 1,
            "message": "High Priority Test",
            "classification": "Web Application Attack",
            "priority": 1,
            "protocol": "TCP",
            "source_ip": "10.0.0.1",
            "source_port": 80,
            "destination_ip": "10.0.0.2",
            "destination_port": 8080,
        }
        result = calculate_threat_score(alert)
        self.assertLessEqual(result["score"], 100)
        self.assertGreaterEqual(result["score"], 0)

        # Test risk level boundaries mapping helper
        self.assertEqual(calculate_risk_level(10), "LOW")
        self.assertEqual(calculate_risk_level(30), "MEDIUM")
        self.assertEqual(calculate_risk_level(60), "HIGH")
        self.assertEqual(calculate_risk_level(85), "CRITICAL")
        self.assertEqual(calculate_risk_level(100), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
