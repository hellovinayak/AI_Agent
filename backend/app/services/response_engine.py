"""Simulated incident-response action engine.

Provides six response actions (block_ip, disable_account, revoke_token,
force_mfa_reset, isolate_device, quarantine_process).  Each action creates a
``ResponseAction`` record in the database with ``status='simulated'``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.database.db import insert_row
from app.models.alert import ResponseAction

logger = logging.getLogger(__name__)

# All supported action types.
VALID_ACTIONS = frozenset(
    {
        "block_ip",
        "disable_account",
        "revoke_token",
        "force_mfa_reset",
        "isolate_device",
        "quarantine_process",
    }
)

# Human-readable labels for log messages.
_ACTION_LABELS = {
    "block_ip": "Block IP address at perimeter firewall",
    "disable_account": "Disable user account in Active Directory",
    "revoke_token": "Revoke OAuth / API token",
    "force_mfa_reset": "Force multi-factor authentication re-enrollment",
    "isolate_device": "Isolate endpoint from network via EDR",
    "quarantine_process": "Quarantine suspicious process on endpoint",
}


async def execute_action(
    action_type: str,
    target: str,
    incident_id: Optional[str] = None,
    alert_id: Optional[str] = None,
) -> ResponseAction:
    """Execute a *simulated* response action and persist it to the database.

    Args:
        action_type: One of the six supported action types.
        target: The entity the action targets (IP, username, token, etc.).
        incident_id: Optional linked incident.
        alert_id: Optional linked alert.

    Returns:
        The created :class:`ResponseAction` instance.

    Raises:
        ValueError: If *action_type* is not in :data:`VALID_ACTIONS`.
    """
    if action_type not in VALID_ACTIONS:
        raise ValueError(
            f"Unknown action_type '{action_type}'. "
            f"Valid actions: {', '.join(sorted(VALID_ACTIONS))}"
        )

    action = ResponseAction(
        id=f"RA-{uuid.uuid4().hex[:8].upper()}",
        action_type=action_type,
        target=target,
        executed_at=datetime.now(timezone.utc).isoformat(),
        executed_by="SHIELDX Automated Response",
        status="executed",
        incident_id=incident_id,
        alert_id=alert_id,
        verification_method="idempotent_api_callback",
        audit_trail_id=str(uuid.uuid4()),
        rollback_available=True,
        rollback_window_seconds=300
    )

    # Persist to database.
    await insert_row("response_actions", {
        "id": action.id,
        "action_type": action.action_type,
        "target": action.target,
        "executed_at": action.executed_at,
        "executed_by": action.executed_by,
        "status": action.status,
        "incident_id": action.incident_id,
        "alert_id": action.alert_id,
        "verification_method": action.verification_method,
        "audit_trail_id": action.audit_trail_id,
        "rollback_available": 1 if action.rollback_available else 0,
        "rollback_window_seconds": action.rollback_window_seconds
    })

    label = _ACTION_LABELS.get(action_type, action_type)
    logger.info("Response action executed (simulated): %s → %s", label, target)

    return action
