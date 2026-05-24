from fastapi import APIRouter, Request, HTTPException
from datetime import datetime, timezone
from typing import Dict, Any
from app.models.alert import LogEntry
from app.services.detection_engine import process_log

router = APIRouter(prefix="/api/ingest", tags=["Ingestion"])

def parse_syslog(raw_msg: str) -> dict:
    """Very basic syslog parser for demo purposes."""
    parts = raw_msg.split(maxsplit=4)
    # expected: <PRI> TIMESTAMP HOSTNAME APP MESSAGE
    # Real parsers are much more complex
    if len(parts) >= 5:
        return {
            "timestamp": parts[1],
            "hostname": parts[2],
            "app": parts[3],
            "message": parts[4]
        }
    return {"message": raw_msg, "hostname": "unknown"}

def classify_syslog(parsed: dict) -> str:
    msg = parsed.get("message", "").lower()
    if "failed password" in msg:
        return "failed_login"
    elif "accepted password" in msg:
        return "successful_login"
    elif "error" in msg:
        return "system_error"
    return "syslog_event"

@router.post("/syslog")
async def ingest_syslog(request: Request):
    """Accept real syslog over HTTP POST — works with rsyslog omhttp module"""
    body = await request.body()
    decoded = body.decode(errors="replace")
    parsed = parse_syslog(decoded)
    
    log = LogEntry(
        event_type=classify_syslog(parsed),
        raw_message=parsed['message'],
        ip_address=parsed.get('hostname', '127.0.0.1'),
        timestamp=datetime.now(timezone.utc).isoformat(),
        device=parsed.get('hostname', 'unknown'),
        location="Unknown",
        severity="low",
        user="unknown"
    )
    
    await process_log(log)
    return {'status': 'ingested', 'type': 'syslog'}

@router.post("/webhook")
async def ingest_webhook(payload: dict):
    """Generic JSON webhook — works with Zapier, n8n, custom SIEM forwarders"""
    log = LogEntry(
        event_type=payload.get("event_type", "webhook_event"),
        raw_message=str(payload),
        ip_address=payload.get("ip_address", "127.0.0.1"),
        timestamp=payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
        device=payload.get("device", "webhook"),
        location=payload.get("location", "Unknown"),
        severity=payload.get("severity", "low"),
        user=payload.get("user", "system")
    )
    
    await process_log(log)
    return {'status': 'ingested', 'type': 'webhook'}
