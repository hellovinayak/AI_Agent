"""False-positive evaluation engine.

Adjusts the raw confidence score of each alert by evaluating contextual signals
(MFA status, device trust, geolocation, working hours, historical patterns).
If the final confidence drops below 0.3, the alert is auto-suppressed.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Context signal weights ───────────────────────────────────────────────────

SIGNAL_WEIGHTS: Dict[str, float] = {
    "mfa_passed": -0.20,
    "trusted_device": -0.15,
    "known_vpn_exit": -0.10,
    "normal_working_hours": -0.05,
    "historical_match": -0.25,
    "admin_targeted": +0.20,
    "new_device_new_country": +0.30,
    "multi_rule_sequence": +0.25,
}

# Suppression threshold – alerts below this are auto-suppressed.
SUPPRESSION_THRESHOLD: float = 0.3

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_FROM_INDEX = {v: k for k, v in SEVERITY_ORDER.items()}


@dataclass
class FPResult:
    """Result of a false-positive evaluation."""

    confidence_score: float
    adjusted_severity: str
    fp_reason: Optional[str]
    suppressed: bool
    signals_applied: List[str]


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _downgrade_severity(original: str, confidence: float) -> str:
    """Lower severity by one level when confidence is below 0.4."""
    idx = SEVERITY_ORDER.get(original, 1)
    if confidence < 0.4 and idx > 0:
        return SEVERITY_FROM_INDEX[idx - 1]
    return original


def generate_context_signals(rule_id: str) -> Dict[str, bool]:
    """Generate realistic context signals for a given detection rule.

    The simulator calls this so that brute-force attacks, for example, will
    *not* have MFA passed and *will* come from a new country + new device.
    """
    base: Dict[str, bool] = {
        "mfa_passed": False,
        "trusted_device": False,
        "known_vpn_exit": False,
        "normal_working_hours": True,
        "historical_match": False,
        "admin_targeted": False,
        "new_device_new_country": False,
        "multi_rule_sequence": False,
    }

    if rule_id == "DET-001":  # Brute force
        base["new_device_new_country"] = True
        base["normal_working_hours"] = False
        base["multi_rule_sequence"] = random.random() > 0.5
    elif rule_id == "DET-002":  # Geo anomaly
        base["new_device_new_country"] = True
        base["known_vpn_exit"] = random.random() > 0.6
    elif rule_id == "DET-003":  # Admin targeted
        base["admin_targeted"] = True
        base["new_device_new_country"] = True
        base["multi_rule_sequence"] = True
        base["normal_working_hours"] = False
    elif rule_id == "DET-004":  # API abuse
        base["normal_working_hours"] = random.random() > 0.5
        base["multi_rule_sequence"] = True
    elif rule_id == "DET-005":  # DB exfil
        base["normal_working_hours"] = False
        base["admin_targeted"] = random.random() > 0.5
    elif rule_id == "DET-006":  # Large download
        base["normal_working_hours"] = False
        base["trusted_device"] = random.random() > 0.7
    elif rule_id == "DET-007":  # Token reuse
        base["multi_rule_sequence"] = True
        base["new_device_new_country"] = True
    elif rule_id == "DET-008":  # Privilege escalation
        base["admin_targeted"] = True
        base["multi_rule_sequence"] = True
        base["normal_working_hours"] = False

    return base


def evaluate(
    alert_severity: str,
    rule_id: str,
    context_signals: Dict[str, bool] | None = None,
) -> FPResult:
    """Run the false-positive evaluation for an alert.

    Args:
        alert_severity: Original severity assigned by the detection rule.
        rule_id: The detection rule ID that fired.
        context_signals: Optional explicit signals; if *None*, signals are
            auto-generated based on the rule_id for realistic simulation.

    Returns:
        An :class:`FPResult` with the adjusted confidence and severity.
    """
    if context_signals is None:
        context_signals = generate_context_signals(rule_id)

    confidence = 0.5
    applied: List[str] = []

    for signal_name, is_present in context_signals.items():
        if is_present and signal_name in SIGNAL_WEIGHTS:
            confidence += SIGNAL_WEIGHTS[signal_name]
            applied.append(signal_name)

    confidence = _clamp(confidence)

    adjusted_severity = _downgrade_severity(alert_severity, confidence)
    suppressed = confidence < SUPPRESSION_THRESHOLD

    fp_reason: Optional[str] = None
    if suppressed:
        reason_parts = [s.replace("_", " ").title() for s in applied if SIGNAL_WEIGHTS.get(s, 0) < 0]
        fp_reason = (
            f"Auto-suppressed (confidence {confidence:.2f}): "
            + ", ".join(reason_parts) if reason_parts
            else f"Auto-suppressed (confidence {confidence:.2f}): benign context signals detected"
        )

    logger.info(
        "FP evaluation for %s: confidence=%.2f adjusted_severity=%s suppressed=%s signals=%s",
        rule_id,
        confidence,
        adjusted_severity,
        suppressed,
        applied,
    )

    return FPResult(
        confidence_score=round(confidence, 3),
        adjusted_severity=adjusted_severity,
        fp_reason=fp_reason,
        suppressed=suppressed,
        signals_applied=applied,
    )
