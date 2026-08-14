"""
NetSentinel — Deterministic Threat Scoring Engine
Phase 5 — Threat Scoring

Assigns a deterministic threat score (0–100), risk level (LOW, MEDIUM, HIGH, CRITICAL),
and human-readable reason to structured Snort alerts produced by the Phase 4 parser.
"""

from typing import Dict, Any


def calculate_risk_level(score: int) -> str:
    """
    Maps a numerical threat score (0–100) to a risk level category.

    Categories:
        0–29   : LOW
        30–59  : MEDIUM
        60–79  : HIGH
        80–100 : CRITICAL
    """
    if score < 30:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 80:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_threat_score(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate threat score, risk level, and human-readable explanation for a given alert dict.

    Args:
        alert: Structured alert dictionary from engine/alert_parser.py

    Returns:
        Updated dictionary containing original alert fields plus score, risk_level, and reason.
    """
    # Create a copy so we don't mutate input unexpectedly
    scored_alert = dict(alert)

    sid = alert.get("sid")
    priority = alert.get("priority")
    protocol = alert.get("protocol")
    dest_port = alert.get("destination_port")
    message = alert.get("message", "")

    # 1. Base Score calculation based on Snort Priority
    if priority == 1:
        base_score = 70
    elif priority == 2:
        base_score = 50
    elif priority == 3:
        base_score = 30
    else:
        base_score = 20

    # 2. SID specific baseline & modifiers
    score = base_score
    reason_parts = []

    if sid == 9000001:
        # ICMP Activity
        score = 30
        reason = "ICMP activity detected."
    elif sid == 9000002:
        # Suspicious TCP Connection Attempt
        score = 50
        reason_parts.append("Suspicious TCP connection attempt")
        if dest_port == 4444:
            score += 10
            reason_parts.append("to port 4444.")
        else:
            reason_parts.append("detected.")
        reason = " ".join(reason_parts)
    elif sid == 9000003:
        # Suspicious HTTP Test Pattern
        score = 70
        reason_parts.append("Suspicious HTTP activity detected with high Snort priority.")
        if protocol == "TCP" and dest_port is not None:
            score += 5
        reason = " ".join(reason_parts)
    else:
        # Unknown SID fallback
        if priority is not None:
            reason = f"Alert triggered with Snort priority {priority}."
        else:
            reason = "Alert triggered without specified priority."

    # 3. Contextual Modifiers
    # Note: Localhost source IP traffic remains at its assigned base score (no extra penalty)

    # 4. Clamp score to 0–100 boundary
    final_score = max(0, min(100, score))

    # 5. Determine Risk Level
    risk_level = calculate_risk_level(final_score)

    scored_alert["score"] = final_score
    scored_alert["risk_level"] = risk_level
    scored_alert["reason"] = reason

    return scored_alert
