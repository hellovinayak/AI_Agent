"""API routes for security alerts — list, filter, and retrieve with AI analysis."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query

from app.database.db import fetch_many, fetch_one, update_row, execute_sql
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


class VerdictPayload(BaseModel):
    verdict: str  # "true_positive" | "false_positive" | "benign_explained"
    analyst_note: Optional[str] = None
    analyst_id: Optional[str] = "analyst-1"

@router.post("/{alert_id}/verdict")
async def submit_verdict(alert_id: str, payload: VerdictPayload) -> Dict[str, Any]:
    """Submit an analyst verdict for an alert (True Positive / False Positive)."""
    row = await fetch_one("alerts", alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
    update_data = {
        "analyst_verdict": payload.verdict,
        # In a real system, we'd also store the note and analyst_id in the DB.
        # "analyst_note": payload.analyst_note,
        # "reviewed_at": datetime.now(timezone.utc).isoformat(),
        # "analyst_id": payload.analyst_id
    }
    
    await update_row("alerts", alert_id, update_data)
    return {"status": "success", "alert_id": alert_id, "verdict": payload.verdict}


@router.get("/metrics/rules")
async def get_rule_metrics() -> Dict[str, Any]:
    """Calculate precision and recall metrics per rule based on analyst verdicts."""
    sql = "SELECT rule_id, analyst_verdict FROM alerts WHERE analyst_verdict IS NOT NULL"
    rows = await execute_sql(sql)
    
    metrics = {}
    for r in rows:
        rule_id = r["rule_id"]
        verdict = r["analyst_verdict"]
        if rule_id not in metrics:
            metrics[rule_id] = {"tp": 0, "fp": 0, "precision": None}
            
        if verdict == "true_positive":
            metrics[rule_id]["tp"] += 1
        elif verdict in ["false_positive", "benign_explained"]:
            metrics[rule_id]["fp"] += 1
            
    for rule_id, stats in metrics.items():
        total = stats["tp"] + stats["fp"]
        if total > 0:
            stats["precision"] = round(stats["tp"] / total, 3)
            
    return {"metrics": metrics}
