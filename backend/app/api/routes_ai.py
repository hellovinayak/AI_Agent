"""API routes for AI analysis and chat."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.database.db import fetch_one, fetch_many, update_row
from app.models.alert import Alert, AIAnalysis
from app.services import ai_reasoning
from app.services.detection_engine import get_risk_score

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ai", tags=["AI"])


# ── Request / response schemas ───────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    alert_id: str


class ChatRequest(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze_alert(req: AnalyzeRequest) -> Dict[str, Any]:
    """Run AI analysis on a specific alert and persist the result.

    Returns the :class:`AIAnalysis` object.
    """
    row = await fetch_one("alerts", req.alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Alert {req.alert_id} not found")

    # Reconstruct the Alert model.
    alert_data = dict(row)
    if isinstance(alert_data.get("location"), str):
        try:
            alert_data["location"] = json.loads(alert_data["location"])
        except (json.JSONDecodeError, TypeError):
            alert_data["location"] = {}
    if "user_name" in alert_data:
        alert_data["user"] = alert_data.pop("user_name")
    # Remove fields not in the Alert model.
    alert_data.pop("ai_analysis", None)
    alert_data.pop("created_at", None)

    alert = Alert(**{k: v for k, v in alert_data.items() if k in Alert.model_fields})
    analysis = await ai_reasoning.analyze_alert(alert)

    # Persist back to DB.
    await update_row("alerts", req.alert_id, {
        "ai_analysis": analysis.model_dump_json(),
    })

    return analysis.model_dump(mode="json")


@router.post("/chat")
async def chat(req: ChatRequest) -> Dict[str, Any]:
    """Free-form analyst chat with SOC context injection.

    The AI receives the last 5 alerts, open incidents, and the current risk
    score as system context.
    """
    # Gather context.
    recent_alerts_rows, _ = await fetch_many(
        "alerts", page=1, page_size=5, order_by="created_at DESC"
    )
    recent_alerts: List[Dict[str, Any]] = []
    for r in recent_alerts_rows:
        a = dict(r)
        a.pop("ai_analysis", None)  # keep context lean
        recent_alerts.append(a)

    open_incidents_rows, _ = await fetch_many(
        "incidents", page=1, page_size=5,
        filters={"status": "open"},
        order_by="updated_at DESC",
    )
    open_incidents = [dict(r) for r in open_incidents_rows]

    # Also include "investigating" incidents.
    investigating_rows, _ = await fetch_many(
        "incidents", page=1, page_size=5,
        filters={"status": "investigating"},
        order_by="updated_at DESC",
    )
    open_incidents.extend([dict(r) for r in investigating_rows])

    risk = get_risk_score()

    incident_id = (req.context or {}).get("incident_id")

    result = await ai_reasoning.chat(
        message=req.message,
        recent_alerts=recent_alerts,
        open_incidents=open_incidents,
        risk_score=risk,
        incident_id=incident_id,
    )
    return result

@router.get("/config")
async def get_ai_config() -> Dict[str, Any]:
    from app.core.config import settings
    return {
        "provider": settings.AI_PROVIDER,
        "openai_configured": bool(settings.OPENAI_API_KEY),
        "claude_configured": bool(settings.ANTHROPIC_API_KEY)
    }
