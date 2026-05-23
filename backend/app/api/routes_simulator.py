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


@router.post("/api/simulate/ransomware")
async def simulate_ransomware() -> Dict[str, Any]:
    """Launch a ransomware simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_ransomware, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "ransomware"}


@router.post("/api/simulate/ddos")
async def simulate_ddos() -> Dict[str, Any]:
    """Launch a DDoS simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_ddos, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "ddos"}


@router.post("/api/simulate/sqli")
async def simulate_sqli() -> Dict[str, Any]:
    """Launch a SQLi simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_sqli, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "sqli"}


@router.post("/api/simulate/password-spraying")
async def simulate_password_spraying() -> Dict[str, Any]:
    """Launch a password spraying simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_password_spraying, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "password_spraying"}


@router.post("/api/simulate/impossible-travel")
async def simulate_impossible_travel() -> Dict[str, Any]:
    """Launch an impossible travel simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_impossible_travel, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "impossible_travel"}


@router.post("/api/simulate/beaconing")
async def simulate_beaconing() -> Dict[str, Any]:
    """Launch a beaconing simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_beaconing, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "beaconing"}


@router.post("/api/simulate/dns-tunneling")
async def simulate_dns_tunneling() -> Dict[str, Any]:
    """Launch a DNS tunneling simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_dns_tunneling, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "dns_tunneling"}


@router.post("/api/simulate/cloud-metadata")
async def simulate_cloud_metadata() -> Dict[str, Any]:
    """Launch a cloud metadata abuse simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_cloud_metadata_abuse, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "cloud_metadata_abuse"}


@router.post("/api/simulate/iam-privilege")
async def simulate_iam_privilege() -> Dict[str, Any]:
    """Launch an IAM privilege escalation simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_iam_privilege_escalation, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "iam_privilege_escalation"}


@router.post("/api/simulate/staging-exfiltration")
async def simulate_staging_exfiltration() -> Dict[str, Any]:
    """Launch a staging before exfiltration simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_staging_before_exfiltration, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "staging_exfiltration"}


@router.post("/api/simulate/slow-drip")
async def simulate_slow_drip() -> Dict[str, Any]:
    """Launch a slow-drip exfiltration simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_slow_drip_exfiltration, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "slow_drip_exfiltration"}


@router.post("/api/simulate/honeypot")
async def simulate_honeypot() -> Dict[str, Any]:
    """Launch a honeypot access simulation as a background task."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    asyncio.create_task(_run_safe(simulator.run_honeypot_access, job_id))
    return {"job_id": job_id, "status": "started", "scenario": "honeypot_access"}

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
