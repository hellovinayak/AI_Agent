"""API routes for security incidents — list and retrieve correlated alert groups."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from app.database.db import fetch_many, fetch_one

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


def _deserialize_incident(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DB row into a frontend-friendly dict."""
    inc = dict(row)

    json_fields = [
        "alert_ids", "timeline", "mitre_tactics",
        "recommended_actions", "response_actions",
    ]
    for field in json_fields:
        val = inc.get(field)
        if isinstance(val, str):
            try:
                inc[field] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                inc[field] = []

    # Rename response_actions → response_actions_taken for API compatibility.
    if "response_actions" in inc:
        inc["response_actions_taken"] = inc.pop("response_actions")

    return inc


@router.get("")
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """Paginated list of incidents.

    Returns::

        {"incidents": [...], "total": int, "page": int}
    """
    rows, total = await fetch_many(
        "incidents",
        page=page,
        page_size=page_size,
        order_by="updated_at DESC",
    )

    incidents = [_deserialize_incident(r) for r in rows]
    return {"incidents": incidents, "total": total, "page": page}


@router.get("/{incident_id}")
async def get_incident(incident_id: str) -> Dict[str, Any]:
    """Retrieve a single incident by ID with full timeline and metadata."""
    row = await fetch_one("incidents", incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return _deserialize_incident(row)


@router.post("/{incident_id}/report")
async def get_incident_report(incident_id: str) -> Dict[str, Any]:
    """Generate a downloadable PDF-style executive/technical report for an incident."""
    row = await fetch_one("incidents", incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    incident = _deserialize_incident(row)
    from app.services.ai_reasoning import generate_incident_report

    report_content = await generate_incident_report(incident)
    return {"incident_id": incident_id, "report": report_content}
