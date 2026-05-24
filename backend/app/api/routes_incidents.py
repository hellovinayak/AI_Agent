"""API routes for security incidents — list and retrieve correlated alert groups."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query

from app.database.db import fetch_many, fetch_one, update_row

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


def _deserialize_incident(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DB row into a frontend-friendly dict."""
    inc = dict(row)

    for field in ["alert_ids", "timeline", "mitre_tactics", "recommended_actions", "response_actions", "triage_data"]:
        val = inc.get(field)
        if val is not None:
            try:
                inc[field] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                inc[field] = [] if field != "triage_data" else {}

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

class AssignIncidentPayload(BaseModel):
    assigned_to: str
    priority: Optional[int] = None

@router.post("/{incident_id}/assign")
async def assign_incident(incident_id: str, payload: AssignIncidentPayload) -> Dict[str, Any]:
    """Assign an incident to an analyst."""
    row = await fetch_one("incidents", incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    update_data = {"assigned_to": payload.assigned_to}
    if payload.priority:
        update_data["priority"] = payload.priority
        
    await update_row("incidents", incident_id, update_data)
    return {"status": "success", "assigned_to": payload.assigned_to}

class ResolveIncidentPayload(BaseModel):
    resolution_notes: str

@router.post("/{incident_id}/resolve")
async def resolve_incident(incident_id: str, payload: ResolveIncidentPayload) -> Dict[str, Any]:
    """Close an incident with resolution notes."""
    row = await fetch_one("incidents", incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    from datetime import datetime, timezone
    
    update_data = {
        "status": "resolved",
        "resolution_notes": payload.resolution_notes,
        "closed_at": datetime.now(timezone.utc).isoformat()
    }
    
    await update_row("incidents", incident_id, update_data)
    
    from app.websocket.manager import manager
    await manager.broadcast_incident_update({
        "id": incident_id,
        "status": "resolved",
        "closed_at": update_data["closed_at"]
    })
    
    return {"status": "success"}
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


@router.get("/{incident_id}/graph")
async def get_incident_graph(incident_id: str) -> Dict[str, Any]:
    incident_row = await fetch_one("incidents", incident_id)
    if not incident_row:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    incident = _deserialize_incident(incident_row)
    alert_ids = incident.get("alert_ids", [])
    
    alerts = []
    for aid in alert_ids:
        alert_row = await fetch_one("alerts", aid)
        if alert_row:
            alert = dict(alert_row)
            alert["user"] = alert.get("user_name", "unknown")
            alerts.append(alert)

    def extract_entities(alert: dict) -> list:
        entities = []
        if alert.get('user'):
            entities.append({
                'id': f"user:{alert['user']}",
                'label': alert['user'],
                'type': 'user',
                'risk': alert.get('confidence_score', 0.5)
            })
        if alert.get('ip_address'):
            entities.append({
                'id': f"ip:{alert['ip_address']}",
                'label': alert['ip_address'],
                'type': 'ip',
                'risk': 0.9 if alert.get('severity') == 'critical' else 0.5
            })
        if alert.get('device') and alert.get('device') != 'unknown':
            entities.append({
                'id': f"device:{alert['device']}",
                'label': alert['device'],
                'type': 'device',
                'risk': 0.7
            })
        return entities

    if not alerts:
        # Fallback if no alerts
        return {
            'nodes': [{'id': 'user:unknown', 'label': 'unknown', 'type': 'user', 'risk': 0}],
            'edges': [],
            'alerts': []
        }

    entity_map = {}
    edges = []

    for idx, alert in enumerate(alerts):
        # Extract entities from each alert
        for entity in extract_entities(alert):
            if entity['id'] not in entity_map:
                entity_map[entity['id']] = entity

        # Build edges between entities in same alert
        entities = extract_entities(alert)
        for i in range(len(entities) - 1):
            edges.append({
                'source': entities[i]['id'],
                'target': entities[i+1]['id'],
                'type': 'relation',
                'label': alert.get('rule_id', '')
            })
            
        # Add a causal link if it's a kill chain step (mock logic based on rule sequence)
        if idx > 0:
            prev_entities = extract_entities(alerts[idx-1])
            if prev_entities and entities:
                edges.append({
                    'source': prev_entities[0]['id'],
                    'target': entities[0]['id'],
                    'type': 'kill_chain',
                    'label': alert.get('rule_id', '')
                })

    return {
        'nodes': list(entity_map.values()),
        'edges': edges,
        'alerts': [
            {
                'time': idx * 30, # mock timeline
                'label': f"{a.get('rule_id', '')} · {a.get('event_type', '')}",
                'entities': [e['id'] for e in extract_entities(a)]
            }
            for idx, a in enumerate(alerts)
        ]
    }
