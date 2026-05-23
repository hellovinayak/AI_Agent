"""Pydantic models for security incidents (correlated groups of alerts)."""

from __future__ import annotations

from typing import List, Literal, Optional

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

from app.models.alert import ResponseAction


class TimelineEvent(BaseModel):
    """A single event on an incident's timeline."""

    timestamp: str
    event_type: str
    description: str
    severity: str
    alert_id: Optional[str] = None


class Incident(BaseModel):
    """A security incident composed of one or more correlated alerts."""

    id: str
    title: str
    severity: str
    status: Literal["open", "investigating", "resolved"] = "open"
    created_at: str
    updated_at: str
    affected_user: str
    affected_ip: str
    alert_ids: List[str] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    ai_narrative: str = ""
    mitre_tactics: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    business_impact: str = ""
    response_actions_taken: List[ResponseAction] = Field(default_factory=list)
