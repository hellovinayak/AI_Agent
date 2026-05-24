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
from app.services import zero_knowledge_engine
from app.services.threat_intel import threat_intel
from app.services.ml_queue import ml_queue
from app.services.persona_engine import persona_engine
from app.services.ioc_enrichment import ioc_enrichment_engine
from app.services.triage_engine import triage_engine
from app.services.lateral_movement import lateral_movement_detector
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

# Alert Throttling: {rule_id_user: timestamp}
_recent_fired_rules: Dict[str, float] = {}

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
    _recent_fired_rules.clear()
    reset_risk_score()
    
    # Clear zero-day engine state if needed
    zero_knowledge_engine._user_sessions.clear()


# ═════════════════════════════════════════════════════════════════════════════
#  DETECTION RULES
# ═════════════════════════════════════════════════════════════════════════════

def _compute_velocity_score(events: list, now: float) -> float:
    w2m = sum(1 for e in events if (now - e) <= 120)
    w1h = sum(1 for e in events if (now - e) <= 3600)
    w24h = sum(1 for e in events if (now - e) <= 86400)
    
    # Adaptive weights: as global risk score increases, the system becomes more sensitive
    # If risk is 0, multiplier is 1x. If risk is 100, multiplier is 2x.
    current_risk = get_risk_score()
    risk_multiplier = 1.0 + (current_risk / 100.0)
    
    score = ((w2m * 0.5) + (w1h * 0.1) + (w24h * 0.02)) * risk_multiplier
    return score

def _check_det001(log: LogEntry) -> Optional[Alert]:
    """DET-001: Multi-window cumulative brute force detection."""
    if "fail" not in log.event_type.lower() and "failed" not in log.raw_message.lower():
        return None

    ip = log.ip_address
    now = time.time()
    # Clean old entries (> 24h)
    _failed_logins[ip] = _clean_window(_failed_logins[ip], 86400)
    _failed_logins[ip].append((now, log.user))

    # Extract just timestamps for the velocity score
    timestamps = [e[0] for e in _failed_logins[ip]]
    score = _compute_velocity_score(timestamps, now)
    
    # Threshold for composite score
    if score >= 2.5:
        # Prevent spamming alerts if score is continuously above threshold
        # (This is mostly handled by throttling now, but we can reset the history to prevent continuous firing)
        _failed_logins[ip] = []
        return _make_alert("DET-001", "high", log,
                           f"Brute force detected (Velocity Score: {score:.1f}) "
                           f"from {ip} targeting user(s): "
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
    """DET-004: API request multi-window velocity scoring."""
    if "api" not in log.event_type.lower():
        return None

    user = log.user
    now = time.time()
    _api_requests[user] = [t for t in _api_requests[user] if t > now - 86400]
    _api_requests[user].append(now)

    score = _compute_velocity_score(_api_requests[user], now)
    
    if score > 250: # Threshold for API abuse score
        _api_requests[user] = []
        return _make_alert("DET-004", "high", log,
                           f"API abuse detected (Velocity Score: {score:.1f}) "
                           f"from token '{user}'")
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


HONEYPOT_ENDPOINTS = [
    '/admin-backup-2023',
    '/internal/employee-data',
    '/.env',
    '/api/v1/admin/users/export'
]

def _check_det010(log: LogEntry) -> Optional[Alert]:
    """DET-010: Deception Technology (Honeypot) Trigger."""
    msg_lower = log.raw_message.lower()
    if any(hp in msg_lower for hp in HONEYPOT_ENDPOINTS):
        return _make_alert("DET-010", "critical", log,
                           f"Deception Technology Triggered: Access to honeypot endpoint detected by '{log.user}' from {log.ip_address}: {log.raw_message[:200]}")
    return None

_spray_tracker: Dict[str, List[str]] = defaultdict(list)

def _check_det011(log: LogEntry) -> Optional[Alert]:
    """DET-011: Password Spray."""
    if log.event_type != 'failed_login':
        return None
        
    now = time.time()
    ip = log.ip_address
    
    # Filter out old logins (>10 minutes)
    _spray_tracker[ip] = [(t, u) for (t, u) in _spray_tracker[ip] if now - t < 600]
    _spray_tracker[ip].append((now, log.user))
    
    unique_users = len(set([u for _, u in _spray_tracker[ip]]))
    if unique_users >= 10:
        return _make_alert("DET-011", "high", log,
                           f"{unique_users} unique accounts targeted from {log.ip_address} in 10 minutes — classic password spray pattern")
    return None

_last_login_tracker: Dict[str, dict] = {}

def _check_det012(log: LogEntry) -> Optional[Alert]:
    """DET-012: Impossible Travel."""
    if log.event_type != 'successful_login' or not isinstance(log.location, dict) or not log.location.get('country'):
        return None
        
    current_country = log.location.get('country')
    user = log.user
    now_dt = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
    
    last = _last_login_tracker.get(user)
    if not last or not last.get('country') or last['country'] == current_country:
        _last_login_tracker[user] = {'country': current_country, 'timestamp': now_dt}
        return None
        
    time_diff_hours = abs((now_dt - last['timestamp']).total_seconds()) / 3600.0
    
    # If gap is under 2 hours and countries differ — physically impossible
    if time_diff_hours < 2:
        alert = _make_alert("DET-012", "critical", log,
                           f"Login from {current_country} only {time_diff_hours:.1f}h after login from {last['country']} — physically impossible")
        _last_login_tracker[user] = {'country': current_country, 'timestamp': now_dt}
        return alert
        
    _last_login_tracker[user] = {'country': current_country, 'timestamp': now_dt}
    return None

def _check_det009(log: LogEntry) -> Optional[Alert]:
    """DET-009: Malware / Suspicious Execution / Ransomware."""
    msg = log.raw_message.lower()
    
    if log.event_type == "process_execution" and ("suspicious" in msg or "unsigned" in msg or "whitelist" in msg):
        return _make_alert("DET-009", "critical", log, f"Suspicious process execution detected: {log.raw_message}")
        
    if log.event_type == "network_connection" and ("malicious ip" in msg or "c2" in msg or "beacon" in msg):
        return _make_alert("DET-009", "critical", log, f"Outbound connection to suspected C2 server: {log.raw_message}")
        
    if log.event_type in ["file_encryption", "file_creation", "file_access"] and ("ransomware" in msg or "encrypted" in msg or "bulk" in msg):
        return _make_alert("DET-009", "critical", log, f"Potential ransomware / mass file access detected: {log.raw_message}")
        
    return None

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
    _check_det009,
    _check_det010,
    _check_det011,
    _check_det012,
]

def _check_det013(log: LogEntry) -> Optional[Alert]:
    lateral_movement_detector.record_access(log.model_dump())
    result = lateral_movement_detector.detect_lateral_movement(log.model_dump())
    if result:
        return _make_alert("DET-013", result['severity'], log, result['description'])
    return None

_RULES.append(_check_det013)


# ═════════════════════════════════════════════════════════════════════════════
#  ALERT CONSTRUCTION
# ═════════════════════════════════════════════════════════════════════════════

def _make_alert(rule_id: str, severity: str, log: LogEntry, raw_message: str) -> Alert:
    """Create an :class:`Alert` from a detection rule match."""
    # Check Threat Intel
    intel = threat_intel.check_ip(log.ip_address)
    confidence = 0.5
    if intel['is_known_malicious']:
        confidence += 0.3
        raw_message += f" [THREAT INTEL: IP matched in {intel['feed_source']}]"
        severity = "critical" if severity in ["high", "medium"] else severity
        
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
        confidence_score=confidence,
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
    
    # Standalone medium/high/critical / zero-day alerts should trigger an incident immediately
    if alert.severity in ["medium", "high", "critical"] or alert.rule_id == "DET-009":
        should_group = True

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
                "updated_at": datetime.now(timezone.utc).isoformat(),
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
        elif r == "DET-009":
            mitre_tactics_set.update(["Defense Evasion", "Discovery"])

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
        f"Incident correlates {len(all_alert_ids)} alerts involving user {alert.user}. "
        f"Initial severity assessment is {max_sev}."
    )
    }
    
    # Calculate triage score
    alerts_data = [a.model_dump() for a, _ in user_alerts] + [alert.model_dump()]
    
    try:
        triage = triage_engine.score_incident(incident_data, alerts_data, None)
        incident_data["priority"] = triage.priority.value
        incident_data["sla_deadline"] = triage.ack_deadline.isoformat()
        incident_data["triage_score"] = triage.triage_score
        incident_data["triage_data"] = json.dumps(triage.to_dict())
        incident_data["ai_narrative"] += f" Automated triage assessed score {triage.triage_score}/100 and recommended tier {triage.recommended_analyst_tier} analyst."
    except Exception as e:
        logger.error(f"Triage engine failed: {e}")
        incident_data["priority"] = 2
        incident_data["triage_score"] = 0.0
        incident_data["triage_data"] = "{}"

    # Insert the new incident.
    incident_data.update({
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
        "assigned_to": None,
        "priority": 1 if max_sev == "critical" else 2 if max_sev == "high" else 3 if max_sev == "medium" else 4,
        "sla_deadline": (datetime.now(timezone.utc) + timedelta(hours={'critical': 1, 'high': 4, 'medium': 24, 'low': 72}.get(max_sev, 24))).isoformat(),
        "resolution_notes": None,
        "closed_at": None,
    })

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
        "created_at": now_iso,
        "updated_at": now_iso,
        "affected_user": alert.user,
        "affected_ip": alert.ip_address,
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
    from app.services.health_monitor import health_monitor
    start_time = time.time()
    try:
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

        # Submit to background ML Queue for zero-day analysis
        ml_queue.submit(log)
        
        # Update entity persona asynchronously
        try:
            await persona_engine.update_persona(log.model_dump())
        except Exception as e:
            logger.error(f"Persona engine update failed: {e}")

        # 3. Evaluate deterministic detection rules.
        generated_alerts: List[Alert] = []
        for rule_fn in _RULES:
            alert = rule_fn(log)
            if alert is not None:
                # Throttling check: do not fire same rule for same user within 5 minutes
                throttle_key = f"{alert.rule_id}_{alert.user}"
                now = time.time()
                if throttle_key in _recent_fired_rules and (now - _recent_fired_rules[throttle_key] < 300):
                    logger.debug("Throttled alert %s for user %s (fired recently)", alert.rule_id, alert.user)
                    continue
                
                _recent_fired_rules[throttle_key] = now

                # 4a. False-positive evaluation.
                fp_result = await fp_engine.evaluate(alert)
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

                # 4e. Enricht alert with IOC and Persona engines
                try:
                    alert_dict = alert.model_dump()
                    enriched_alert = await ioc_enrichment_engine.enrich_alert(alert_dict)
                    persona_result = await persona_engine.score_against_persona(alert_dict)
                    
                    if persona_result['persona_score'] > 0.6:
                        enriched_alert['confidence'] = min(enriched_alert.get('confidence', 0.5) + 0.15, 1.0)
                        
                    alert.confidence_score = enriched_alert.get('confidence', alert.confidence_score)
                except Exception as e:
                    logger.error(f"Alert enrichment failed: {e}")

                # 4f. Persist alert.
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

    except Exception:
        from app.services.health_monitor import health_monitor
        health_monitor.record_dropped()
        raise
    finally:
        from app.services.health_monitor import health_monitor
        from app.database.db import execute_sql
        processing_time = (time.time() - start_time) * 1000
        health_monitor.record_event(processing_time)
        
        # Get count of suppressed alerts
        try:
            suppressed_res = await execute_sql("SELECT COUNT(*) as count FROM alerts WHERE status='suppressed'")
            suppressed_count = suppressed_res[0]['count']
            last_fp_res = await execute_sql("SELECT fp_reason FROM alerts WHERE status='suppressed' ORDER BY timestamp DESC LIMIT 1")
            last_reason = last_fp_res[0]['fp_reason'] if last_fp_res else None
        except Exception:
            suppressed_count = 0
            last_reason = None
            
        health = health_monitor.compute_health()
        stats = {
            'suppressed_alerts': suppressed_count,
            'ingestion_health': health['health_pct'],
            'health_status': health['status'],
            'events_per_second': health['events_per_second'],
            'llm_available': health['llm_available'],
            'websocket_connected': health['websocket_connected'],
            'last_suppression_reason': last_reason
        }
        await manager.broadcast({'type': 'stats_update', 'data': stats})

    return generated_alerts
async def _fire_zero_day_alert(log: LogEntry, alert: Alert) -> None:
    """Called by the background ML worker when a zero-day is found."""
    # 1. False Positive Engine
    fp_result = await fp_engine.evaluate(alert)
    alert.confidence_score = fp_result.confidence_score
    alert.adjusted_severity = fp_result.adjusted_severity
    alert.fp_reason = fp_result.fp_reason

    if fp_result.suppressed:
        return

    # 2. AI analysis
    try:
        analysis = await ai_reasoning.analyze_alert(alert)
        alert.ai_analysis = analysis
    except Exception as e:
        logger.error(f"AI analysis failed for zero-day: {e}")

    # 3. Persist Alert
    alert_dict = alert.model_dump()
    alert_dict["ai_analysis"] = json.dumps(alert.ai_analysis.model_dump()) if alert.ai_analysis else None
    alert_dict["location"] = json.dumps(alert.location) if alert.location else None
    alert_dict["user_name"] = alert_dict.pop("user")
    
    await insert_row("alerts", alert_dict)
    _bump_risk(alert.severity)
    
    # 4. Handle Incident Correlation
    incident_id = await _try_group_into_incident(alert)
    if incident_id:
        alert.incident_id = incident_id
        alert.status = "in_incident"
    
    # 5. Push to websocket
    await manager.broadcast({
        "type": "new_alert",
        "data": alert.model_dump()
    })
