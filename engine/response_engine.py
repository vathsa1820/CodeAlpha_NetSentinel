"""
NetSentinel — Application-Level Simulated Response Engine
Phase 6 — Response Engine

Processes scored alerts and executes simulated, application-level responses
(LOG, FLAG, SUSPICIOUS, SIMULATED_BLOCK, ALREADY_BLOCKED) without making
any operating-system or network firewall modifications.
"""

from typing import Dict, List, Set, Any, Optional


class ResponseEngine:
    """
    Stateful in-memory response engine that maps alert risk levels to simulated
    defensive actions and tracks suspicious & blocked IP addresses.
    """

    def __init__(self):
        self.suspicious_ips: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.response_history: List[Dict[str, Any]] = []

    def reset(self):
        """Reset in-memory state (useful between unit test runs)."""
        self.suspicious_ips.clear()
        self.blocked_ips.clear()
        self.response_history.clear()

    def process_alert(self, scored_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a scored alert dictionary and record an application-level response.

        Args:
            scored_alert: Dictionary produced by engine/threat_score.py

        Returns:
            Response record dictionary with action, status, and summary reason.
        """
        timestamp = scored_alert.get("timestamp", "")
        source_ip = scored_alert.get("source_ip", "0.0.0.0")
        sid = scored_alert.get("sid")
        score = scored_alert.get("score", 0)
        risk_level = scored_alert.get("risk_level", "LOW")

        action = "LOG"
        status = "RECORDED"
        reason = "Low-risk activity logged."

        if risk_level == "LOW":
            action = "LOG"
            status = "RECORDED"
            reason = "Low-risk activity logged."
        elif risk_level == "MEDIUM":
            action = "FLAG"
            status = "FLAGGED"
            reason = "Medium-risk activity flagged for monitoring."
        elif risk_level == "HIGH":
            action = "SUSPICIOUS"
            status = "MARKED_SUSPICIOUS"
            reason = "High-risk activity detected; source marked suspicious."
            if source_ip:
                self.suspicious_ips.add(source_ip)
        elif risk_level == "CRITICAL":
            if source_ip and source_ip in self.blocked_ips:
                action = "ALREADY_BLOCKED"
                status = "BLOCKED_SIMULATED"
                reason = "Source IP already in simulated blocklist."
            else:
                action = "SIMULATED_BLOCK"
                status = "BLOCKED_SIMULATED"
                reason = "Critical risk activity detected; simulated block applied."
                if source_ip:
                    self.blocked_ips.add(source_ip)

        response_record = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "sid": sid,
            "score": score,
            "risk_level": risk_level,
            "action": action,
            "status": status,
            "reason": reason,
        }

        self.response_history.append(response_record)
        return response_record

    def get_suspicious_ips(self) -> List[str]:
        """Return list of current suspicious IP addresses."""
        return sorted(list(self.suspicious_ips))

    def get_blocked_ips(self) -> List[str]:
        """Return list of current simulated blocked IP addresses."""
        return sorted(list(self.blocked_ips))

    def get_response_history(self) -> List[Dict[str, Any]]:
        """Return complete response history list."""
        return list(self.response_history)


# Global default instance for convenience
_default_engine = ResponseEngine()


def process_alert(scored_alert: Dict[str, Any]) -> Dict[str, Any]:
    return _default_engine.process_alert(scored_alert)


def get_suspicious_ips() -> List[str]:
    return _default_engine.get_suspicious_ips()


def get_blocked_ips() -> List[str]:
    return _default_engine.get_blocked_ips()


def get_response_history() -> List[Dict[str, Any]]:
    return _default_engine.get_response_history()
