"""
NetSentinel — Snort Alert Parser
Phase 4 — Alert Parser

Parses Snort fast-alert log lines into clean, structured Python dictionaries.
Supports safe malformed-line handling and incremental file reading to prevent duplicate processing.
"""

import os
import re
from typing import Dict, List, Optional, Tuple, Any

# Snort alert_fast format regex pattern:
# Example: 08/14-22:36:30.977554  [**] [1:9000001:1] [NetSentinel] ICMP Activity Detected [**] [Classification: Detection of a Network Scan] [Priority: 3] {ICMP} 127.0.0.1 -> 127.0.0.1
SNORT_ALERT_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<revision>\d+)\]\s+"
    r"(?P<message>.+?)\s+"
    r"\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]+)\]\s*)?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s*)?"
    r"\{(?P<protocol>\w+)\}\s+"
    r"(?P<source_ip>[^\s:]+)(?::(?P<source_port>\d+))?\s+->\s+"
    r"(?P<destination_ip>[^\s:]+)(?::(?P<destination_port>\d+))?$"
)

def get_default_log_path() -> str:
    env_path = os.environ.get("NETSENTINEL_SNORT_LOG")
    if env_path:
        return env_path
    primary = r"C:\Snort\log\netsentinel_alerts.txt"
    secondary = r"C:\Snort\log\alert.ids"
    if os.path.exists(primary):
        return primary
    if os.path.exists(secondary):
        return secondary
    return primary


DEFAULT_SNORT_LOG_PATH = get_default_log_path()


def parse_alert_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single Snort alert_fast log line into a structured dictionary.

    Returns:
        Structured alert dict if valid, or None if empty/malformed.
    """
    if not line or not line.strip():
        return None

    line = line.strip()
    match = SNORT_ALERT_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()

    try:
        return {
            "timestamp": groups["timestamp"],
            "sid": int(groups["sid"]),
            "revision": int(groups["revision"]),
            "message": groups["message"].strip(),
            "classification": groups["classification"].strip() if groups["classification"] else None,
            "priority": int(groups["priority"]) if groups["priority"] else None,
            "protocol": groups["protocol"].upper(),
            "source_ip": groups["source_ip"],
            "source_port": int(groups["source_port"]) if groups["source_port"] else None,
            "destination_ip": groups["destination_ip"],
            "destination_port": int(groups["destination_port"]) if groups["destination_port"] else None,
        }
    except (ValueError, TypeError):
        # Handle conversion errors safely without crashing
        return None


class SnortAlertParser:
    """
    Lightweight stateful parser that reads a Snort log file and tracks byte offset
    to avoid returning duplicate alerts on repeated calls.
    """

    def __init__(self, log_file_path: Optional[str] = None):
        self.log_file_path = log_file_path or DEFAULT_SNORT_LOG_PATH
        self.last_offset: int = 0

    def parse_new_alerts(self) -> List[Dict[str, Any]]:
        """Reads and parses newly appended lines from the log file since the last call."""
        alerts, new_offset = parse_log_file(self.log_file_path, start_offset=self.last_offset)
        self.last_offset = new_offset
        return alerts

    def reset_offset(self):
        """Resets the byte offset to re-read the log file from the beginning."""
        self.last_offset = 0


def parse_log_file(
    file_path: Optional[str] = None, start_offset: int = 0
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parse Snort fast-alert log file starting from a given byte offset.

    Args:
        file_path: Path to the Snort alert log file.
        start_offset: Byte offset to start reading from (for incremental parsing).

    Returns:
        Tuple of (list of parsed alert dicts, final byte offset).
    """
    target_path = file_path or DEFAULT_SNORT_LOG_PATH
    alerts = []

    if not os.path.exists(target_path):
        return alerts, start_offset

    try:
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(start_offset)
            while True:
                line = f.readline()
                if not line:
                    break
                parsed = parse_alert_line(line)
                if parsed:
                    alerts.append(parsed)
            new_offset = f.tell()
            return alerts, new_offset
    except Exception as e:
        print(f"[NetSentinel Parser Warning] Failed to read log file '{target_path}': {e}")
        return alerts, start_offset
