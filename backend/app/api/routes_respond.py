"""API routes for incident response actions."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services import response_engine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/respond", tags=["Response"])


class ActionRequest(BaseModel):
    """Request body for executing a response action."""

    action_type: str
    target: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None


@router.post("/action")
async def execute_response_action(req: ActionRequest) -> Dict[str, Any]:
    """Execute a simulated response action.

    Supported action types:
      - ``block_ip``
      - ``disable_account``
      - ``revoke_token``
      - ``force_mfa_reset``
      - ``isolate_device``
      - ``quarantine_process``
    """
    try:
        action = await response_engine.execute_action(
            action_type=req.action_type,
            target=req.target,
            incident_id=req.incident_id,
            alert_id=req.alert_id,
        )
        return action.model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
