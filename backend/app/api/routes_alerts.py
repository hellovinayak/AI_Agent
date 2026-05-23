"""API routes for security alerts — list, filter, and retrieve with AI analysis."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from app.database.db import fetch_many, fetch_one
from app.models.alert import AIAnalysis, Alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _deserialize_alert(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DB row into a frontend-friendly dict."""
    alert = dict(row)

    # Parse JSON fields.
    if isinstance(alert.get("location"), str):
        try:
            alert["location"] = json.loads(alert["location"])
        except (json.JSONDecodeError, TypeError):
            alert["location"] = {}

    if isinstance(alert.get("ai_analysis"), str):
        try:
            alert["ai_analysis"] = json.loads(alert["ai_analysis"])
        except (json.JSONDecodeError, TypeError):
            alert["ai_analysis"] = None

    # Map DB column `user_name` → API field `user`.
    if "user_name" in alert and "user" not in alert:
        alert["user"] = alert.pop("user_name")

    return alert


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Paginated list of alerts with optional severity/status filters.

    Returns::

        {"alerts": [...], "total": int, "page": int}
    """
    filters: Dict[str, Any] = {}
    if severity:
        filters["severity"] = severity
    if status:
        filters["status"] = status

    rows, total = await fetch_many(
        "alerts",
        page=page,
        page_size=page_size,
        filters=filters,
        order_by="created_at DESC",
    )

    alerts = [_deserialize_alert(r) for r in rows]
    return {"alerts": alerts, "total": total, "page": page}


@router.get("/{alert_id}")
async def get_alert(alert_id: str) -> Dict[str, Any]:
    """Retrieve a single alert by ID, including its AI analysis."""
    row = await fetch_one("alerts", alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    return _deserialize_alert(row)
