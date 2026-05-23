import pytest
import time
import numpy as np
import json
import asyncio
from datetime import datetime, timezone

from app.services.detection_engine import _check_det001, _compute_velocity_score, _recent_fired_rules, process_log
from app.services.zero_day_engine import _extract_features
from app.models.alert import LogEntry
from app.database.db import get_db, init_db, fetch_one, execute_sql

# Test 1: Deduplication / Throttling
@pytest.mark.asyncio
async def test_alert_throttle():
    await init_db()
    
    _recent_fired_rules.clear()
    
    event = LogEntry(
        timestamp=str(time.time()),
        user="test_user",
        ip_address="192.168.1.1",
        device="test_device",
        event_type="login_failed",
        severity="medium",
        raw_message="failed login attempt"
    )
    
    alerts_generated = 0
    for _ in range(10):
        alerts = await process_log(event, simulation_type="test")
        alerts_generated += len(alerts)
        
    # Should only generate 1 alert due to the 5-minute throttling window
    # Actually wait, DET-001 requires 5 failed logins to trigger once,
    # so out of 10 events, the rule might trigger at the 5th event.
    # Then the 6th to 10th events will trigger the rule again (score > 2.5), 
    # but the throttle should block them.
    assert alerts_generated == 1


# Test 2: Cyclical proximity
def test_time_encoding_proximity():
    class DummyLog:
        def __init__(self, t):
            self.timestamp = t
            self.raw_message = ""
            self.event_type = ""
            
    # Mocking time for the features extraction
    t_11pm = time.mktime((2023, 1, 1, 23, 0, 0, 0, 1, -1))
    t_1am = time.mktime((2023, 1, 2, 1, 0, 0, 0, 2, -1))
    t_noon = time.mktime((2023, 1, 2, 12, 0, 0, 0, 2, -1))
    
    f_11pm = np.array(_extract_features(DummyLog(t_11pm)))
    f_1am = np.array(_extract_features(DummyLog(t_1am)))
    f_noon = np.array(_extract_features(DummyLog(t_noon)))
    
    # Cyclical features are at index 0 and 1 (hour_sin, hour_cos)
    dist_overnight = np.linalg.norm(f_11pm[0:2] - f_1am[0:2])
    dist_daytime = np.linalg.norm(f_1am[0:2] - f_noon[0:2])
    
    assert dist_overnight < dist_daytime


# Test 4: Verdict write and read
@pytest.mark.asyncio
async def test_analyst_verdict_roundtrip():
    await init_db()
    
    # We use a dummy alert_id
    alert_id = "ALT-TEST-1234"
    
    # Insert a dummy alert first
    await execute_sql("INSERT OR REPLACE INTO alerts (id, timestamp, rule_id) VALUES (?, ?, ?)", [alert_id, str(time.time()), "DET-001"])
    
    from app.api.routes_alerts import submit_verdict, VerdictPayload
    
    payload = VerdictPayload(verdict="true_positive", analyst_note="confirmed via logs")
    await submit_verdict(alert_id, payload)
    
    result = await fetch_one("alerts", alert_id)
    assert result["analyst_verdict"] == "true_positive"
