"""
NetSentinel — Response Engine Test Suite
Phase 6 — Response Engine

Tests response actions (LOG, FLAG, SUSPICIOUS, SIMULATED_BLOCK, ALREADY_BLOCKED),
in-memory IP tracking, duplicate block handling, and OS safety.
"""

import unittest
from engine.response_engine import ResponseEngine


class TestResponseEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ResponseEngine()

    def test_1_low_risk_log_action(self):
        """Test LOW risk alert produces LOG action."""
        alert = {
            "timestamp": "08/14-22:36:30.977554",
            "sid": 9999999,
            "source_ip": "127.0.0.1",
            "score": 20,
            "risk_level": "LOW",
        }
        res = self.engine.process_alert(alert)
        self.assertEqual(res["action"], "LOG")
        self.assertEqual(res["status"], "RECORDED")

    def test_2_medium_risk_flag_action(self):
        """Test MEDIUM risk alert produces FLAG action."""
        alert = {
            "timestamp": "08/14-22:36:30.977554",
            "sid": 9000001,
            "source_ip": "127.0.0.1",
            "score": 50,
            "risk_level": "MEDIUM",
        }
        res = self.engine.process_alert(alert)
        self.assertEqual(res["action"], "FLAG")
        self.assertEqual(res["status"], "FLAGGED")

    def test_3_high_risk_suspicious_action(self):
        """Test HIGH risk alert produces SUSPICIOUS action and adds IP to suspicious set."""
        alert = {
            "timestamp": "08/14-22:36:37.072228",
            "sid": 9000002,
            "source_ip": "192.168.1.50",
            "score": 75,
            "risk_level": "HIGH",
        }
        res = self.engine.process_alert(alert)
        self.assertEqual(res["action"], "SUSPICIOUS")
        self.assertEqual(res["status"], "MARKED_SUSPICIOUS")
        self.assertIn("192.168.1.50", self.engine.get_suspicious_ips())

    def test_4_critical_risk_simulated_block(self):
        """Test CRITICAL risk alert produces SIMULATED_BLOCK and adds IP to blocked set."""
        alert = {
            "timestamp": "08/14-22:36:39.154624",
            "sid": 9000003,
            "source_ip": "192.168.1.60",
            "score": 90,
            "risk_level": "CRITICAL",
        }
        res = self.engine.process_alert(alert)
        self.assertEqual(res["action"], "SIMULATED_BLOCK")
        self.assertEqual(res["status"], "BLOCKED_SIMULATED")
        self.assertIn("192.168.1.60", self.engine.get_blocked_ips())

    def test_5_duplicate_critical_block_handling(self):
        """Test repeated CRITICAL alert from same IP produces ALREADY_BLOCKED."""
        alert = {
            "timestamp": "08/14-22:36:39.154624",
            "sid": 9000003,
            "source_ip": "192.168.1.60",
            "score": 90,
            "risk_level": "CRITICAL",
        }
        res1 = self.engine.process_alert(alert)
        self.assertEqual(res1["action"], "SIMULATED_BLOCK")

        res2 = self.engine.process_alert(alert)
        self.assertEqual(res2["action"], "ALREADY_BLOCKED")
        self.assertEqual(res2["status"], "BLOCKED_SIMULATED")
        # Ensure only 1 instance of the IP exists in blocked_ips
        self.assertEqual(len(self.engine.get_blocked_ips()), 1)

    def test_6_localhost_safety(self):
        """Test localhost (127.0.0.1) CRITICAL alert is processed safely without OS changes."""
        alert = {
            "timestamp": "08/14-22:36:39.154624",
            "sid": 9000003,
            "source_ip": "127.0.0.1",
            "score": 90,
            "risk_level": "CRITICAL",
        }
        res = self.engine.process_alert(alert)
        self.assertEqual(res["action"], "SIMULATED_BLOCK")
        self.assertEqual(res["status"], "BLOCKED_SIMULATED")
        self.assertIn("127.0.0.1", self.engine.get_blocked_ips())
        # Ensure response history length is updated safely
        self.assertEqual(len(self.engine.get_response_history()), 1)


if __name__ == "__main__":
    unittest.main()
