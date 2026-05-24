"""SHIELDX FastAPI Application Entrypoint.

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
from app.api.routes_graph import router as graph_router
from app.api.routes_ingest import router as ingest_router

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
    logger.info("Starting SHIELDX Backend...")
    # Initialise the database schema
    await init_db()
    manager.start_worker()
    
    from app.services.ioc_enrichment import ioc_enrichment_engine
    ioc_enrichment_engine.start()
    
    # Start the background stats broadcast loop
    import asyncio
    from app.services.health_monitor import health_monitor
    from app.database.db import execute_sql
    
    async def broadcast_stats_loop():
        while True:
            try:
                suppressed_res = await execute_sql("SELECT COUNT(*) as count FROM alerts WHERE status='suppressed'")
                suppressed_count = suppressed_res[0]['count']
                last_fp_res = await execute_sql("SELECT fp_reason FROM alerts WHERE status='suppressed' ORDER BY timestamp DESC LIMIT 1")
                last_reason = last_fp_res[0]['fp_reason'] if last_fp_res else None
            except Exception:
                suppressed_count = 0
                last_reason = None
                
            health = health_monitor.compute_health()
            stats = {
                'suppressed_alerts': suppressed_count,
                'ingestion_health': health['health_pct'],
                'health_status': health['status'],
                'events_per_second': health['events_per_second'],
                'llm_available': health['llm_available'],
                'websocket_connected': health['websocket_connected'],
                'last_suppression_reason': last_reason
            }
            await manager.broadcast({'type': 'stats_update', 'data': stats})
            await asyncio.sleep(1.0)
            
    loop_task = asyncio.create_task(broadcast_stats_loop())
    
    yield
    loop_task.cancel()
    # Close the database connection gracefully on shutdown
    logger.info("Shutting down SHIELDX Backend...")
    await close_db()


app = FastAPI(
    title="SHIELDX API",
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
app.include_router(graph_router)
app.include_router(ingest_router)


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
