"""Core detection engine — implements all 8 detection rules, incident
correlation, and global risk-score management.

The engine maintains in-memory state for windowed counters (failed-login
counts, API request rates, etc.) and exposes :func:`process_log` as the
single entry point for the entire alert pipeline:

    log → detection rules → false-positive engine → AI analysis → DB → WebSocket
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.database.db import insert_row, fetch_many, execute_sql, update_row
from app.models.alert import AIAnalysis, Alert, LogEntry
from app.models.incident import Incident, TimelineEvent
from app.services import false_positive_engine as fp_engine
from app.services import ai_reasoning
from app.websocket.manager import manager

logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════════════════════════════════════
#  GLOBAL RISK SCORE
# ═════════════════════════════════════════════════════════════════════════════

_risk_score: float = 0.0
_last_risk_update: float = time.time()

SEVERITY_RISK_POINTS = {"critical": 15, "high": 10, "medium": 5, "low": 2}
RISK_DECAY_PER_MINUTE: float = 1.0


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def get_risk_score() -> float:
    """Return the current risk score after applying time-based decay."""
    global _risk_score, _last_risk_update
    now = time.time()
    elapsed_minutes = (now - _last_risk_update) / 60.0
    _risk_score = _clamp(_risk_score - elapsed_minutes * RISK_DECAY_PER_MINUTE)
    _last_risk_update = now
    return round(_risk_score, 1)


def _bump_risk(severity: str) -> float:
    """Increase the risk score by the severity weight and return new value."""
    global _risk_score, _last_risk_update
    # first apply decay
    now = time.time()
    elapsed = (now - _last_risk_update) / 60.0
    _risk_score = _clamp(_risk_score - elapsed * RISK_DECAY_PER_MINUTE)
    _last_risk_update = now
    # then bump
    _risk_score = _clamp(_risk_score + SEVERITY_RISK_POINTS.get(severity, 2))
    return round(_risk_score, 1)


def reset_risk_score() -> None:
    """Reset the risk score to zero (used by demo reset)."""
    global _risk_score, _last_risk_update
    _risk_score = 0.0
    _last_risk_update = time.time()


# ═════════════════════════════════════════════════════════════════════════════
#  IN-MEMORY STATE for windowed detection
# ═════════════════════════════════════════════════════════════════════════════

# DET-001: {ip: [(timestamp, user), ...]}
_failed_logins: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

# DET-002: {user: set(country)}
_user_countries: Dict[str, set] = defaultdict(set)

# DET-003: same as DET-001 but filtered for admin accounts
# (reuses _failed_logins)

# DET-004: {token/user: [(timestamp,), ...]}
_api_requests: Dict[str, List[float]] = defaultdict(list)

# DET-005: {user: {"baseline": int, "recent": int, "window_start": float}}
_db_queries: Dict[str, Dict[str, Any]] = defaultdict(
    lambda: {"baseline": 10, "recent": 0, "window_start": time.time()}
)

# DET-006: {user: float (bytes this session)}
_download_bytes: Dict[str, float] = defaultdict(float)

# DET-007: {token: [(timestamp, ip), ...]}
_token_usage: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

# Incident grouping: {user: [(alert, timestamp), ...]}
_recent_alerts_by_user: Dict[str, List[Tuple[Alert, float]]] = defaultdict(list)
_recent_alerts_by_ip: Dict[str, List[Tuple[Alert, float]]] = defaultdict(list)

ADMIN_KEYWORDS = {"admin", "root", "sysadmin", "administrator", "superuser", "sa"}


def _is_admin(user: str) -> bool:
    return any(kw in user.lower() for kw in ADMIN_KEYWORDS)


def _clean_window(entries: list, window_seconds: float) -> list:
    """Remove entries older than *window_seconds*."""
    cutoff = time.time() - window_seconds
    return [e for e in entries if e[0] > cutoff]


def clear_state() -> None:
    """Reset all in-memory detection state (demo reset)."""
    _failed_logins.clear()
    _user_countries.clear()
    _api_requests.clear()
    _db_queries.clear()
    _download_bytes.clear()
    _token_usage.clear()
    _recent_alerts_by_user.clear()
    _recent_alerts_by_ip.clear()
    reset_risk_score()


# ═════════════════════════════════════════════════════════════════════════════
#  DETECTION RULES
# ═════════════════════════════════════════════════════════════════════════════

def _check_det001(log: LogEntry) -> Optional[Alert]:
    """DET-001: ≥5 failed logins in 2 min from same IP."""
    if "fail" not in log.event_type.lower() and "failed" not in log.raw_message.lower():
        return None

    ip = log.ip_address
    now = time.time()
    _failed_logins[ip] = _clean_window(_failed_logins[ip], 120)
    _failed_logins[ip].append((now, log.user))

    if len(_failed_logins[ip]) >= 5:
        return _make_alert("DET-001", "high", log,
                           f"Brute force detected: {len(_failed_logins[ip])} failed logins "
                           f"from {ip} in 2 minutes targeting user(s): "
                           f"{', '.join(set(e[1] for e in _failed_logins[ip]))}")
    return None


def _check_det002(log: LogEntry) -> Optional[Alert]:
    """DET-002: Login from country not in user's history."""
    if "login" not in log.event_type.lower() or "fail" in log.event_type.lower():
        return None

    country = log.location.get("country", "")
    user = log.user
    if not country:
        return None

    if country not in _user_countries[user] and len(_user_countries[user]) > 0:
        alert = _make_alert("DET-002", "medium", log,
                            f"Geographic anomaly: '{user}' logged in from {country} "
                            f"({log.location.get('city', 'unknown')}), "
                            f"not seen in history: {_user_countries[user]}")
        _user_countries[user].add(country)
        return alert

    _user_countries[user].add(country)
    return None


def _check_det003(log: LogEntry) -> Optional[Alert]:
    """DET-003: Admin account targeted in failed login sequence."""
    if "fail" not in log.event_type.lower() and "failed" not in log.raw_message.lower():
        return None
    if not _is_admin(log.user):
        return None

    ip = log.ip_address
    now = time.time()
    # reuse _failed_logins which already tracked this
    admin_attempts = [e for e in _failed_logins.get(ip, []) if _is_admin(e[1])]
    if len(admin_attempts) >= 3:
        return _make_alert("DET-003", "critical", log,
                           f"Admin account '{log.user}' targeted: {len(admin_attempts)} "
                           f"failed attempts from {ip}")
    return None


def _check_det004(log: LogEntry) -> Optional[Alert]:
    """DET-004: API request rate > 500/min from single token."""
    if "api" not in log.event_type.lower():
        return None

    user = log.user
    now = time.time()
    _api_requests[user] = [t for t in _api_requests[user] if t > now - 60]
    _api_requests[user].append(now)

    if len(_api_requests[user]) > 500:
        return _make_alert("DET-004", "high", log,
                           f"API abuse: {len(_api_requests[user])} requests/min "
                           f"from token '{user}' (threshold: 500)")
    return None


def _check_det005(log: LogEntry) -> Optional[Alert]:
    """DET-005: Database query volume > 10× user baseline."""
    if "database" not in log.event_type.lower() and "query" not in log.event_type.lower() \
       and "db_" not in log.event_type.lower():
        return None

    user = log.user
    state = _db_queries[user]
    now = time.time()

    # Reset window every hour
    if now - state["window_start"] > 3600:
        state["baseline"] = max(state["baseline"], state["recent"])
        state["recent"] = 0
        state["window_start"] = now

    state["recent"] += 1

    if state["recent"] > state["baseline"] * 10:
        return _make_alert("DET-005", "high", log,
                           f"Anomalous DB activity: '{user}' executed {state['recent']} "
                           f"queries (baseline: {state['baseline']})")
    return None


def _check_det006(log: LogEntry) -> Optional[Alert]:
    """DET-006: File download > 500 MB in single session."""
    if "download" not in log.event_type.lower() and "file_download" not in log.event_type.lower():
        return None

    user = log.user
    # Extract MB from raw_message if present; otherwise assume 100 MB per event.
    import re
    mb_match = re.search(r'(\d+)\s*MB', log.raw_message, re.IGNORECASE)
    mb = int(mb_match.group(1)) if mb_match else 100
    _download_bytes[user] += mb

    if _download_bytes[user] > 500:
        return _make_alert("DET-006", "medium", log,
                           f"Large download: '{user}' downloaded {_download_bytes[user]:.0f} MB "
                           f"in this session (threshold: 500 MB)")
    return None


def _check_det007(log: LogEntry) -> Optional[Alert]:
    """DET-007: Token reused from different IP within 60 seconds."""
    if "token" not in log.event_type.lower() and "api" not in log.event_type.lower():
        return None

    user = log.user
    ip = log.ip_address
    now = time.time()
    _token_usage[user] = _clean_window(_token_usage[user], 60)
    _token_usage[user].append((now, ip))

    ips_in_window = set(e[1] for e in _token_usage[user])
    if len(ips_in_window) > 1:
        return _make_alert("DET-007", "critical", log,
                           f"Token replay: '{user}' token used from {len(ips_in_window)} "
                           f"IPs within 60s: {', '.join(ips_in_window)}")
    return None


def _check_det008(log: LogEntry) -> Optional[Alert]:
    """DET-008: Privilege escalation command executed."""
    escalation_keywords = [
        "sudo", "su -", "runas", "net localgroup administrators",
        "chmod u+s", "privilege_escalation", "priv_esc", "escalat",
        "net user /add", "dsenl", "setuid",
    ]
    msg_lower = log.raw_message.lower()
    evt_lower = log.event_type.lower()

    if not any(kw in msg_lower or kw in evt_lower for kw in escalation_keywords):
        return None

    return _make_alert("DET-008", "critical", log,
                       f"Privilege escalation attempt by '{log.user}' on device "
                       f"'{log.device}': {log.raw_message[:200]}")


# Ordered list of all detection checks.
_RULES = [
    _check_det001,
    _check_det002,
    _check_det003,
    _check_det004,
    _check_det005,
    _check_det006,
    _check_det007,
    _check_det008,
]


# ═════════════════════════════════════════════════════════════════════════════
#  ALERT CONSTRUCTION
# ═════════════════════════════════════════════════════════════════════════════

def _make_alert(rule_id: str, severity: str, log: LogEntry, raw_message: str) -> Alert:
    """Create an :class:`Alert` from a detection rule match."""
    return Alert(
        id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=log.timestamp,
        rule_id=rule_id,
        event_type=log.event_type,
        user=log.user,
        ip_address=log.ip_address,
        location=log.location,
        device=log.device,
        severity=severity,
        raw_message=raw_message,
        confidence_score=0.5,
        status="open",
    )


# ═════════════════════════════════════════════════════════════════════════════
#  INCIDENT CORRELATION
# ═════════════════════════════════════════════════════════════════════════════

INCIDENT_WINDOW_SECONDS = 30 * 60  # 30 minutes

# Attack-chain patterns: sequential rule triggers that indicate a multi-stage attack.
_ATTACK_CHAINS = [
    ["DET-001", "DET-002"],  # brute-force → geo-anomaly login
    ["DET-001", "DET-003"],  # brute-force → admin targeted
    ["DET-001", "DET-008"],  # brute-force → priv-esc
    ["DET-003", "DET-008"],  # admin targeted → priv-esc
    ["DET-004", "DET-007"],  # API abuse → token replay
    ["DET-005", "DET-006"],  # DB queries → large download
]


async def _try_group_into_incident(alert: Alert) -> Optional[str]:
    """Attempt to group the new alert into an existing or new incident.

    Grouping criteria (any match):
      1. Same user within 30-min window
      2. Same source IP within 30-min window
      3. Sequential rule triggers matching attack patterns
    """
    now = time.time()

    # Collect recent alerts for the same user and IP.
    user_alerts = _recent_alerts_by_user.get(alert.user, [])
    ip_alerts = _recent_alerts_by_ip.get(alert.ip_address, [])

    # Clean old entries.
    user_alerts = [(a, t) for a, t in user_alerts if now - t < INCIDENT_WINDOW_SECONDS]
    ip_alerts = [(a, t) for a, t in ip_alerts if now - t < INCIDENT_WINDOW_SECONDS]
    _recent_alerts_by_user[alert.user] = user_alerts
    _recent_alerts_by_ip[alert.ip_address] = ip_alerts

    # Check if any existing alert already belongs to an incident.
    existing_incident_id: Optional[str] = None
    for prev_alert, _ in user_alerts + ip_alerts:
        if prev_alert.incident_id:
            existing_incident_id = prev_alert.incident_id
            break

    # Check for attack chain match.
    chain_match = False
    recent_rules = [a.rule_id for a, _ in user_alerts]
    for chain in _ATTACK_CHAINS:
        if alert.rule_id in chain:
            other_rules = [r for r in chain if r != alert.rule_id]
            if any(r in recent_rules for r in other_rules):
                chain_match = True
                break

    should_group = len(user_alerts) > 0 or len(ip_alerts) > 0 or chain_match

    if not should_group:
        # Store for future correlation.
        _recent_alerts_by_user[alert.user].append((alert, now))
        _recent_alerts_by_ip[alert.ip_address].append((alert, now))
        return None

    if existing_incident_id:
        # Add to existing incident.
        incident_row = await _get_incident(existing_incident_id)
        if incident_row:
            alert_ids = json.loads(incident_row.get("alert_ids", "[]"))
            alert_ids.append(alert.id)
            timeline = json.loads(incident_row.get("timeline", "[]"))
            timeline.append({
                "timestamp": alert.timestamp,
                "event_type": alert.event_type,
                "description": alert.raw_message,
                "severity": alert.severity,
                "alert_id": alert.id,
            })
            # Escalate severity if needed.
            sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            current_sev = incident_row.get("severity", "low")
            new_sev = current_sev if sev_order.get(current_sev, 0) >= sev_order.get(alert.severity, 0) else alert.severity

            await update_row("incidents", existing_incident_id, {
                "alert_ids": json.dumps(alert_ids),
                "timeline": json.dumps(timeline),
                "severity": new_sev,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "status": "investigating",
            })

            alert.incident_id = existing_incident_id
            alert.status = "in_incident"

            # Broadcast incident update.
            await manager.broadcast_incident_update({
                "id": existing_incident_id,
                "alert_count": len(alert_ids),
                "severity": new_sev,
                "status": "investigating",
            })

            _recent_alerts_by_user[alert.user].append((alert, now))
            _recent_alerts_by_ip[alert.ip_address].append((alert, now))
            return existing_incident_id

    # Create a new incident.
    all_alert_ids = [a.id for a, _ in user_alerts] + [alert.id]
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    timeline_events = []
    for prev_alert, _ in user_alerts:
        timeline_events.append({
            "timestamp": prev_alert.timestamp,
            "event_type": prev_alert.event_type,
            "description": prev_alert.raw_message,
            "severity": prev_alert.severity,
            "alert_id": prev_alert.id,
        })
    timeline_events.append({
        "timestamp": alert.timestamp,
        "event_type": alert.event_type,
        "description": alert.raw_message,
        "severity": alert.severity,
        "alert_id": alert.id,
    })

    # Determine highest severity.
    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    all_sevs = [a.severity for a, _ in user_alerts] + [alert.severity]
    max_sev = max(all_sevs, key=lambda s: sev_order.get(s, 0))

    all_rules = list(set([a.rule_id for a, _ in user_alerts] + [alert.rule_id]))
    mitre_tactics_set: set[str] = set()
    for r in all_rules:
        if r in ("DET-001", "DET-002", "DET-003"):
            mitre_tactics_set.update(["Initial Access", "Credential Access"])
        elif r in ("DET-004", "DET-005", "DET-006"):
            mitre_tactics_set.update(["Collection", "Exfiltration"])
        elif r == "DET-007":
            mitre_tactics_set.update(["Credential Access", "Lateral Movement"])
        elif r == "DET-008":
            mitre_tactics_set.update(["Privilege Escalation", "Execution"])

    now_iso = datetime.now(timezone.utc).isoformat()
    incident_data = {
        "id": incident_id,
        "title": f"Multi-stage attack targeting {alert.user} from {alert.ip_address}",
        "severity": max_sev,
        "status": "investigating",
        "created_at": now_iso,
        "updated_at": now_iso,
        "affected_user": alert.user,
        "affected_ip": alert.ip_address,
        "alert_ids": json.dumps(all_alert_ids),
        "timeline": json.dumps(timeline_events),
        "ai_narrative": (
            f"SentinelAI has correlated {len(all_alert_ids)} alerts into a single "
            f"incident. Detection rules {', '.join(all_rules)} fired against user "
            f"'{alert.user}' from IP {alert.ip_address} within a "
            f"{INCIDENT_WINDOW_SECONDS // 60}-minute window, indicating a coordinated "
            f"multi-stage attack."
        ),
        "mitre_tactics": json.dumps(sorted(mitre_tactics_set)),
        "recommended_actions": json.dumps([
            f"Block IP {alert.ip_address} at the perimeter",
            f"Disable account '{alert.user}' pending investigation",
            "Preserve all logs and forensic evidence",
            "Notify the incident response team",
            "Begin containment procedures",
        ]),
        "business_impact": (
            f"Potential compromise of user '{alert.user}' and associated systems. "
            f"Estimated blast radius: multiple connected services and data stores."
        ),
        "response_actions": json.dumps([]),
    }

    await insert_row("incidents", incident_data)

    # Update all grouped alerts.
    alert.incident_id = incident_id
    alert.status = "in_incident"
    for prev_alert, _ in user_alerts:
        prev_alert.incident_id = incident_id
        prev_alert.status = "in_incident"
        await update_row("alerts", prev_alert.id, {
            "incident_id": incident_id,
            "status": "in_incident",
        })

    # Broadcast.
    await manager.broadcast_incident_update({
        "id": incident_id,
        "title": incident_data["title"],
        "severity": max_sev,
        "alert_count": len(all_alert_ids),
        "status": "investigating",
    })

    _recent_alerts_by_user[alert.user].append((alert, now))
    _recent_alerts_by_ip[alert.ip_address].append((alert, now))

    logger.info("Created incident %s with %d alerts", incident_id, len(all_alert_ids))
    return incident_id


async def _get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Fetch an incident row by ID."""
    from app.database.db import fetch_one
    return await fetch_one("incidents", incident_id)


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═════════════════════════════════════════════════════════════════════════════

async def process_log(log: LogEntry, simulation_type: str = "manual") -> List[Alert]:
    """Run a log entry through the full detection pipeline.

    Steps:
      1. Store the raw log in the ``logs`` table.
      2. Broadcast the log via WebSocket.
      3. Evaluate all detection rules.
      4. For each triggered alert: false-positive evaluation → AI analysis →
         incident grouping → persist → broadcast.

    Returns the list of alerts generated (may be empty).
    """
    # 1. Persist the raw log.
    await insert_row("logs", {
        "timestamp": log.timestamp,
        "user_name": log.user,
        "ip_address": log.ip_address,
        "location": json.dumps(log.location),
        "device": log.device,
        "event_type": log.event_type,
        "severity": log.severity,
        "raw_message": log.raw_message,
        "simulation_type": simulation_type,
    })

    # 2. Broadcast raw log.
    await manager.broadcast_new_log(log.model_dump())

    # 3. Evaluate detection rules.
    generated_alerts: List[Alert] = []
    for rule_fn in _RULES:
        alert = rule_fn(log)
        if alert is not None:
            # 4a. False-positive evaluation.
            fp_result = fp_engine.evaluate(alert.severity, alert.rule_id)
            alert.confidence_score = fp_result.confidence_score
            alert.adjusted_severity = fp_result.adjusted_severity
            alert.fp_reason = fp_result.fp_reason

            if fp_result.suppressed:
                alert.status = "suppressed"

            # 4b. AI analysis.
            try:
                analysis = await ai_reasoning.analyze_alert(alert)
                alert.ai_analysis = analysis
            except Exception as exc:
                logger.warning("AI analysis failed for %s: %s", alert.id, exc)

            # 4c. Incident grouping (only for non-suppressed alerts).
            if alert.status != "suppressed":
                incident_id = await _try_group_into_incident(alert)
                if incident_id:
                    alert.incident_id = incident_id
                    alert.status = "in_incident"

            # 4d. Bump risk score.
            new_risk = _bump_risk(alert.adjusted_severity or alert.severity)

            # 4e. Persist alert.
            ai_json = alert.ai_analysis.model_dump_json() if alert.ai_analysis else None
            await insert_row("alerts", {
                "id": alert.id,
                "timestamp": alert.timestamp,
                "rule_id": alert.rule_id,
                "event_type": alert.event_type,
                "user_name": alert.user,
                "ip_address": alert.ip_address,
                "location": json.dumps(alert.location),
                "device": alert.device,
                "severity": alert.severity,
                "raw_message": alert.raw_message,
                "confidence_score": alert.confidence_score,
                "adjusted_severity": alert.adjusted_severity,
                "fp_reason": alert.fp_reason,
                "status": alert.status,
                "ai_analysis": ai_json,
                "incident_id": alert.incident_id,
            })

            # 4f. Broadcast.
            if alert.status == "suppressed":
                await manager.broadcast_fp_suppressed(alert.model_dump(mode="json"))
            else:
                await manager.broadcast_new_alert(alert.model_dump(mode="json"))

            await manager.broadcast_risk_score(new_risk)

            generated_alerts.append(alert)
            logger.info(
                "Alert %s (%s) — severity=%s confidence=%.2f status=%s",
                alert.id, alert.rule_id, alert.severity,
                alert.confidence_score, alert.status,
            )

    return generated_alerts
