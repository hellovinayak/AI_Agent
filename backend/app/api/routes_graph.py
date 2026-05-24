"""API routes for graph visualizations and entity relationships."""

from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["Graph"])

@router.get("/entities/{entity_id}/blast-radius")
async def get_blast_radius(entity_id: str, hops: int = 2) -> Dict[str, Any]:
    from app.services.graph_engine import global_entity_graph, propagate_risk

    # Simulate populating global_entity_graph from recent alerts for demo
    from app.database.db import execute_sql
    rows = await execute_sql("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100")
    for row in rows:
        alert = dict(row)
        alert["user"] = alert.get("user_name", "unknown")
        global_entity_graph.ingest_event(alert)

    blast = global_entity_graph.find_blast_radius(entity_id, hops)
    risk = propagate_risk(global_entity_graph.G, entity_id)

    # categorize by type
    affected_by_type = {"user": 0, "ip": 0, "device": 0, "alert": 0}
    for entity in blast:
        type_prefix = entity.split(":")[0] if ":" in entity else "unknown"
        if type_prefix in affected_by_type:
            affected_by_type[type_prefix] += 1
        else:
            affected_by_type[type_prefix] = 1

    return {
        'entity_id': entity_id,
        'total_affected_entities': len(blast),
        'critical_nodes': risk['critical_nodes'],
        'risk_scores': risk['risk_scores'],
        'affected_by_type': affected_by_type
    }

@router.get("/graph/live")
async def get_live_graph() -> Dict[str, Any]:
    from app.services.graph_engine import global_entity_graph, score_incident_graph

    # Rehydrate graph
    from app.database.db import execute_sql
    rows = await execute_sql("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200")
    for row in rows:
        alert = dict(row)
        alert["user"] = alert.get("user_name", "unknown")
        global_entity_graph.ingest_event(alert)

    nodes = [{"id": n, **data} for n, data in global_entity_graph.G.nodes(data=True)]
    edges = [{"from": u, "to": v, **data} for u, v, data in global_entity_graph.G.edges(data=True)]
    pivot_points = global_entity_graph.find_pivot_points()
    
    return {
        'nodes': nodes,
        'edges': edges,
        'pivot_points': [{"id": n, "centrality": c} for n, c in pivot_points],
    }
