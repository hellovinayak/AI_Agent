"""Pydantic models for security alerts, AI analysis output, log entries, and
response actions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AIAnalysis(BaseModel):
    """Structured output produced by the AI reasoning service for a single alert."""

    explanation: str = Field(
        ..., description="Detailed human-readable explanation of what happened."
    )
    narrative: str = Field(
        ..., description="Attacker-perspective story of the incident."
    )
    severity_reasoning: str = Field(
        ..., description="Why this severity level was assigned."
    )
    mitre_tactics: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics observed (e.g. Initial Access).",
    )
    mitre_techniques: List[Dict[str, str]] = Field(
        default_factory=list,
        description='List of {"id": "T1110", "name": "Brute Force"} dicts.',
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Ordered list of recommended analyst actions.",
    )
    business_impact: str = Field(
        ..., description="Plain-language description of the potential business impact."
    )
    next_step_prediction: str = Field(
        ..., description="Predicted next move by the attacker if unmitigated."
    )
    generated_by: Literal["openai", "claude", "mock"] = "mock"
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class Alert(BaseModel):
    """A single security alert produced by the detection engine."""

    id: str
    timestamp: str
    rule_id: str
    event_type: str
    user: str
    ip_address: str
    location: Dict[str, str] = Field(default_factory=dict)
    device: str
    severity: Literal["critical", "high", "medium", "low"]
    raw_message: str
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.5)
    adjusted_severity: Optional[str] = None
    fp_reason: Optional[str] = None
    status: Literal["open", "suppressed", "in_incident"] = "open"
    ai_analysis: Optional[AIAnalysis] = None
    incident_id: Optional[str] = None


class ResponseAction(BaseModel):
    """A simulated or executed response action taken on an alert/incident."""

    id: str
    action_type: str
    target: str
    executed_at: str
    executed_by: str = "SentinelAI Automated Response"
    status: Literal["simulated", "pending", "executed", "failed"] = "simulated"
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    
    # Verification details for the audit trail
    verification_method: str = "idempotent_api_callback"
    audit_trail_id: Optional[str] = None
    rollback_available: bool = True
    rollback_window_seconds: int = 300


class LogEntry(BaseModel):
    """A raw log event ingested from the environment or simulator."""

    timestamp: str
    user: str
    ip_address: str
    location: Dict[str, str] = Field(
        default_factory=lambda: {"country": "US", "city": "New York"}
    )
    device: str
    event_type: str
    severity: str
    raw_message: str
