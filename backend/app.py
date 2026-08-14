"""
NetSentinel — Flask Backend Server & Dashboard API
Phase 7 — Security Dashboard

Serves read-only REST API endpoints for the Security Dashboard
and hosts static dashboard frontend assets.
"""

import os
import sys
import json
from typing import Dict, List, Any
from flask import Flask, jsonify, send_from_directory

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from engine.alert_parser import parse_log_file, get_default_log_path
from engine.threat_score import calculate_threat_score
from engine.response_engine import ResponseEngine

# Dashboard static files path
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")

app = Flask(__name__, static_folder=DASHBOARD_DIR, static_url_path="")


def get_mode() -> str:
    """Determine runtime deployment mode: 'local' (Snort IDS) or 'demo' (Vercel demonstration)."""
    mode = os.environ.get("NETSENTINEL_MODE", "").lower().strip()
    if not mode:
        if os.environ.get("VERCEL"):
            return "demo"
        return "local"
    return mode


# Stateful pipeline runner instance to prevent duplicate response processing on refresh
class PipelineManager:
    def __init__(self):
        self.engine = ResponseEngine()
        self.processed_signatures = set()
        self.scored_alerts: List[Dict[str, Any]] = []

    def refresh(self):
        """Parse log file or load demo alerts, score new alerts, and process new alerts through Response Engine."""
        mode = get_mode()
        parsed_alerts = []

        if mode == "demo":
            demo_path = os.path.join(PROJECT_ROOT, "data", "demo_alerts.json")
            if os.path.exists(demo_path):
                try:
                    with open(demo_path, "r", encoding="utf-8") as f:
                        parsed_alerts = json.load(f)
                except Exception as e:
                    print(f"[NetSentinel Warning] Failed to load demo_alerts.json: {e}")
        else:
            log_path = get_default_log_path()
            if os.path.exists(log_path):
                parsed_alerts, _ = parse_log_file(log_path)

        for alert in parsed_alerts:
            sig = (
                alert.get("timestamp"),
                alert.get("sid"),
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get("source_port"),
                alert.get("destination_port"),
            )
            if sig not in self.processed_signatures:
                scored = calculate_threat_score(alert)
                self.scored_alerts.append(scored)
                self.engine.process_alert(scored)
                self.processed_signatures.add(sig)

    def get_alerts(self) -> List[Dict[str, Any]]:
        self.refresh()
        # Return newest first
        return list(reversed(self.scored_alerts))

    def get_stats(self) -> Dict[str, Any]:
        self.refresh()
        alerts = self.scored_alerts
        low_count = sum(1 for a in alerts if a.get("risk_level") == "LOW")
        medium_count = sum(1 for a in alerts if a.get("risk_level") == "MEDIUM")
        high_count = sum(1 for a in alerts if a.get("risk_level") == "HIGH")
        critical_count = sum(1 for a in alerts if a.get("risk_level") == "CRITICAL")

        return {
            "mode": get_mode(),
            "total_alerts": len(alerts),
            "low": low_count,
            "medium": medium_count,
            "high": high_count,
            "critical": critical_count,
            "suspicious_ips": len(self.engine.get_suspicious_ips()),
            "simulated_blocked_ips": len(self.engine.get_blocked_ips()),
            "suspicious_ip_list": self.engine.get_suspicious_ips(),
            "simulated_blocked_ip_list": self.engine.get_blocked_ips(),
        }

    def get_responses(self) -> List[Dict[str, Any]]:
        self.refresh()
        return list(reversed(self.engine.get_response_history()))


pipeline = PipelineManager()


@app.route("/")
def index():
    """Serve the Security Dashboard HTML."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/health")
def health():
    """Health check endpoint. Confirms the NetSentinel backend is running."""
    return jsonify({"status": "ok", "service": "NetSentinel", "mode": get_mode()})


@app.route("/api/alerts")
def get_alerts():
    """Return parsed & scored alerts (newest first)."""
    return jsonify(pipeline.get_alerts())


@app.route("/api/stats")
def get_stats():
    """Return summary security statistics."""
    return jsonify(pipeline.get_stats())


@app.route("/api/responses")
def get_responses():
    """Return application-level response history."""
    return jsonify(pipeline.get_responses())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
