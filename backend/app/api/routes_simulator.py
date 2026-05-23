"""API routes for attack simulation and demo data reset."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict

from fastapi import APIRouter

from app.database.db import delete_all
from app.services import simulator
from app.services.detection_engine import clear_state

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Simulator"])


@router.post("/api/simulate/bruteforce")
async def simulate_bruteforce() -> Dict[str, Any]:
    """Launch a brute-force simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_bruteforce, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "bruteforce"}


@router.post("/api/simulate/malware")
async def simulate_malware() -> Dict[str, Any]:
    """Launch a malware simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_malware, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "malware"}


@router.post("/api/simulate/insider-threat")
async def simulate_insider_threat() -> Dict[str, Any]:
    """Launch an insider-threat simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_insider_threat, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "insider_threat"}


@router.post("/api/simulate/api-abuse")
async def simulate_api_abuse() -> Dict[str, Any]:
    """Launch an API-abuse simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_api_abuse, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "api_abuse"}


@router.delete("/api/demo/reset")
async def demo_reset() -> Dict[str, Any]:
    """Wipe all data and reset in-memory state for a fresh demo."""
    tables = ["alerts", "incidents", "logs", "response_actions"]
    counts: Dict[str, int] = {}
    for table in tables:
        counts[table] = await delete_all(table)

    clear_state()
    logger.info("Demo reset complete: %s", counts)
    return {"cleared": True, "deleted_rows": counts}


async def _run_safe(coro_fn: Any, job_id: str) -> None:
    """Wrapper that catches and logs exceptions from background simulation tasks."""
    try:
        await coro_fn()
        logger.info("Simulation %s completed successfully", job_id)
    except Exception as exc:
        logger.exception("Simulation %s failed: %s", job_id, exc)
