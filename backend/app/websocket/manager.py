"""WebSocket connection manager for real-time event broadcasting.

Manages a set of active WebSocket connections and provides helpers to broadcast
typed JSON messages (new_log, new_alert, incident_update, risk_score_update,
fp_suppressed) to every connected frontend client.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Keeps track of all active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []
        self._message_queue = asyncio.Queue(maxsize=5000)
        self._worker_task = None

    def start_worker(self):
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._broadcast_worker())

    async def _broadcast_worker(self):
        while True:
            try:
                # We fetch all available messages to batch them or just send them out quickly
                # This ensures we don't block the caller (detection engine)
                messages = []
                # Block until at least one message is ready
                messages.append(await self._message_queue.get())
                
                # Drain the queue up to 50 messages
                while not self._message_queue.empty() and len(messages) < 50:
                    messages.append(self._message_queue.get_nowait())
                    
                # Broadcast the batch or individual messages
                stale: List[WebSocket] = []
                for connection in self.active_connections:
                    try:
                        for msg in messages:
                            await connection.send_json(msg)
                    except Exception:
                        if connection not in stale:
                            stale.append(connection)
                
                for ws in stale:
                    self.disconnect(ws)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"WebSocket broadcast worker error: {e}")

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
        """Send a JSON message to every connected client via background queue.

        Silently drops messages if the queue is full (backpressure).
        """
        try:
            self._message_queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("WebSocket broadcast queue full, dropping message")

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
