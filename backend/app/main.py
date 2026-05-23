"""SentinelAI FastAPI Application Entrypoint.

Registers CORS middleware, DB connection lifecycle handlers, API routers,
and the WebSocket endpoint for real-time alert streaming.
"""

from __future__ import annotations

import time
import logging
from contextlib import asynccontextmanager

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database.db import init_db, close_db
from app.websocket.manager import manager
from app.api.routes_alerts import router as alerts_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_ai import router as ai_router
from app.api.routes_simulator import router as simulator_router
from app.api.routes_respond import router as respond_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Track startup time for uptime metric
START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the FastAPI application."""
    logger.info("Starting SentinelAI Backend...")
    # Initialise the database schema
    await init_db()
    yield
    # Close the database connection gracefully on shutdown
    logger.info("Shutting down SentinelAI Backend...")
    await close_db()


app = FastAPI(
    title="SentinelAI API",
    description="Autonomous AI-powered Security Operations Center (SOC) analyst backend.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(ai_router)
app.include_router(simulator_router)
app.include_router(respond_router)


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Retrieve system health and status."""
    uptime = time.time() - START_TIME
    return {
        "status": "healthy",
        "db": "connected",
        "uptime": uptime,
        "version": "1.0.0",
    }


@app.websocket("/ws/live-alerts")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for streaming raw logs and high-severity security alerts."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection open by listening for any text
            # Clients do not need to send messages in the current design,
            # but we receive them to detect client disconnection.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("WebSocket connection encountered an error: %s", exc)
        manager.disconnect(websocket)
