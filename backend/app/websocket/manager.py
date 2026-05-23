"""WebSocket connection manager for real-time event broadcasting.

Manages a set of active WebSocket connections and provides helpers to broadcast
typed JSON messages (new_log, new_alert, incident_update, risk_score_update,
fp_suppressed) to every connected frontend client.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Keeps track of all active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and register it."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "WebSocket connected — %d active connection(s)",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from the active list."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            "WebSocket disconnected — %d active connection(s)",
            len(self.active_connections),
        )

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Send a JSON message to every connected client.

        Silently drops connections that have gone stale.

        Args:
            message: A dict with at least a ``type`` key. Example::

                {"type": "new_alert", "data": { ... }}
        """
        stale: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                stale.append(connection)
        for ws in stale:
            self.disconnect(ws)

    async def broadcast_new_log(self, log_data: Dict[str, Any]) -> None:
        """Convenience: broadcast a ``new_log`` event."""
        await self.broadcast({"type": "new_log", "data": log_data})

    async def broadcast_new_alert(self, alert_data: Dict[str, Any]) -> None:
        """Convenience: broadcast a ``new_alert`` event."""
        await self.broadcast({"type": "new_alert", "data": alert_data})

    async def broadcast_incident_update(self, incident_data: Dict[str, Any]) -> None:
        """Convenience: broadcast an ``incident_update`` event."""
        await self.broadcast({"type": "incident_update", "data": incident_data})

    async def broadcast_risk_score(self, score: float) -> None:
        """Convenience: broadcast a ``risk_score_update`` event."""
        await self.broadcast({"type": "risk_score_update", "data": {"risk_score": score}})

    async def broadcast_fp_suppressed(self, alert_data: Dict[str, Any]) -> None:
        """Convenience: broadcast a ``fp_suppressed`` event."""
        await self.broadcast({"type": "fp_suppressed", "data": alert_data})


# Global singleton — imported by services and routes.
manager = ConnectionManager()
