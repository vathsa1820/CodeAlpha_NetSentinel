"""
NetSentinel — Response Engine Runner Demonstration
Phase 6 — Response Engine

Demonstrates the complete pipeline:
  Snort Alert Log -> Alert Parser -> Threat Scoring -> Response Engine
"""

import os
import sys

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from engine.alert_parser import parse_log_file, get_default_log_path
from engine.threat_score import calculate_threat_score
from engine.response_engine import ResponseEngine


def main():
    log_file = sys.argv[1] if len(sys.argv) > 1 else get_default_log_path()
    print("NetSentinel Response Engine")
    print("============================")
    print(f"Log source: {log_file}\n")

    if not os.path.exists(log_file):
        print(f"[Warning] Log file not found at: {log_file}")
        print("Please run Snort live capture or test simulation first.")
        return

    alerts, _ = parse_log_file(log_file)
    if not alerts:
        print("No alerts found in log file.")
        return

    engine = ResponseEngine()
    print(f"Processing {len(alerts)} alerts through Response Engine...\n")

    for i, alert in enumerate(alerts, 1):
        scored = calculate_threat_score(alert)
        response = engine.process_alert(scored)

        print(f"Alert {i}:")
        print(f"SID: {scored['sid']}")
        print(f"Score: {scored['score']}")
        print(f"Risk: {scored['risk_level']}")
        print(f"Source: {scored['source_ip']}")
        print(f"Action: {response['action']}")
        print(f"Status: {response['status']}")
        print(f"Reason: {response['reason']}")
        print()

    print("--------------------------------------------------")
    print(f"Suspicious IPs tracked: {engine.get_suspicious_ips()}")
    print(f"Simulated Blocked IPs tracked: {engine.get_blocked_ips()}")
    print(f"Total Response Records: {len(engine.get_response_history())}")
    print("--------------------------------------------------")


if __name__ == "__main__":
    main()
