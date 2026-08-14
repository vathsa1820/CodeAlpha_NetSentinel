"""
NetSentinel — Threat Scoring Engine Runner Demonstration
Phase 5 — Threat Scoring

Demonstrates passing parsed Snort alerts to the threat scoring engine
and displaying deterministic scores, risk levels, and explanations.
"""

import os
import sys

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from engine.alert_parser import parse_log_file, get_default_log_path
from engine.threat_score import calculate_threat_score


def main():
    log_file = sys.argv[1] if len(sys.argv) > 1 else get_default_log_path()
    print("NetSentinel Threat Scoring")
    print("===========================")
    print(f"Log source: {log_file}\n")

    if not os.path.exists(log_file):
        print(f"[Warning] Log file not found at: {log_file}")
        print("Please run Snort live capture or test simulation first.")
        return

    alerts, _ = parse_log_file(log_file)
    if not alerts:
        print("No alerts found in log file.")
        return

    print(f"Scoring {len(alerts)} alerts...\n")

    for i, alert in enumerate(alerts, 1):
        scored = calculate_threat_score(alert)
        clean_msg = scored["message"].replace("[NetSentinel] ", "").strip()
        print(f"Alert {i}")
        print(f"SID: {scored['sid']}")
        print(f"Attack: {clean_msg}")
        print(f"Score: {scored['score']}")
        print(f"Risk: {scored['risk_level']}")
        print(f"Reason: {scored['reason']}")
        print()


if __name__ == "__main__":
    main()
