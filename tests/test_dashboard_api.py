"""
NetSentinel — Dashboard API Test Suite
Phase 7 — Security Dashboard

Tests Flask REST API endpoints (/health, /api/alerts, /api/stats, /api/responses)
and verifies duplicate-response side effect prevention on repeated calls.
"""

import unittest
from backend.app import app, pipeline


class TestDashboardAPI(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_1_health_endpoint(self):
        """Test GET /health returns 200 OK and expected status dict."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "NetSentinel")

    def test_2_api_alerts_endpoint(self):
        """Test GET /api/alerts returns 200 OK and JSON list of alerts."""
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)

    def test_3_api_stats_endpoint(self):
        """Test GET /api/stats returns 200 OK and valid summary stats."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("total_alerts", data)
        self.assertIn("low", data)
        self.assertIn("medium", data)
        self.assertIn("high", data)
        self.assertIn("critical", data)
        self.assertIn("suspicious_ips", data)
        self.assertIn("simulated_blocked_ips", data)

    def test_4_api_responses_endpoint(self):
        """Test GET /api/responses returns 200 OK and JSON list of responses."""
        response = self.client.get("/api/responses")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)

    def test_5_duplicate_response_prevention_on_repeated_requests(self):
        """Verify repeated API calls do not duplicate response entries in history."""
        # Initial request
        res1 = self.client.get("/api/responses").get_json()
        count_initial = len(res1)

        # Repeated requests
        self.client.get("/api/alerts")
        self.client.get("/api/stats")
        res2 = self.client.get("/api/responses").get_json()
        count_repeated = len(res2)

        self.assertEqual(
            count_initial,
            count_repeated,
            "Repeated API calls must not create duplicate response history entries.",
        )


if __name__ == "__main__":
    unittest.main()
