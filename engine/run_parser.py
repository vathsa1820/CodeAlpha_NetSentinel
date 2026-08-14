"""
NetSentinel — Alert Parser Runner Demonstration
Phase 4 — Alert Parser

Demonstrates parsing Snort fast-alert logs into structured objects.
"""

import os
import sys

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from engine.alert_parser import parse_log_file, get_default_log_path


def main():
    log_file = sys.argv[1] if len(sys.argv) > 1 else get_default_log_path()
    print("NetSentinel Alert Parser")
    print("------------------------")
    print(f"Log source: {log_file}")

    if not os.path.exists(log_file):
        print(f"\n[Warning] Log file not found at: {log_file}")
        print("Please ensure Snort has generated alerts in Phase 3.")
        return

    alerts, _ = parse_log_file(log_file)
    print(f"\nAlerts found: {len(alerts)}\n")

    for i, alert in enumerate(alerts, 1):
        src = (
            f"{alert['source_ip']}:{alert['source_port']}"
            if alert["source_port"]
            else alert["source_ip"]
        )
        dst = (
            f"{alert['destination_ip']}:{alert['destination_port']}"
            if alert["destination_port"]
            else alert["destination_ip"]
        )
        print(f"[{i}]")
        print(f"SID: {alert['sid']}")
        print(f"Revision: {alert['revision']}")
        print(f"Message: {alert['message']}")
        print(f"Classification: {alert['classification']}")
        print(f"Priority: {alert['priority']}")
        print(f"Protocol: {alert['protocol']}")
        print(f"Source: {src}")
        print(f"Destination: {dst}")
        print()


if __name__ == "__main__":
    main()
