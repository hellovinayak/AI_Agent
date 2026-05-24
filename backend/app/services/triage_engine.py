from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Dict, Any, Optional

class TriagePriority(Enum):
    P1_CRITICAL  = 1   # 15 min acknowledge, 1h resolve
    P2_HIGH      = 2   # 1h acknowledge, 4h resolve
    P3_MEDIUM    = 3   # 4h acknowledge, 24h resolve
    P4_LOW       = 4   # 24h acknowledge, 72h resolve

SLA_MINUTES = {
    TriagePriority.P1_CRITICAL: {'ack': 15,   'resolve': 60},
    TriagePriority.P2_HIGH:     {'ack': 60,   'resolve': 240},
    TriagePriority.P3_MEDIUM:   {'ack': 240,  'resolve': 1440},
    TriagePriority.P4_LOW:      {'ack': 1440, 'resolve': 4320},
}

@dataclass
class TriageScore:
    incident_id: str
    priority: TriagePriority
    triage_score: float         # 0–100
    score_breakdown: Dict[str, float]
    ack_deadline: datetime
    resolve_deadline: datetime
    recommended_analyst_tier: str   # L1 | L2 | L3
    auto_actions_triggered: List[str]
    escalation_path: List[str]

    def to_dict(self):
        return {
            'incident_id': self.incident_id,
            'priority': self.priority.name,
            'triage_score': self.triage_score,
            'score_breakdown': self.score_breakdown,
            'ack_deadline': self.ack_deadline.isoformat(),
            'resolve_deadline': self.resolve_deadline.isoformat(),
            'recommended_analyst_tier': self.recommended_analyst_tier,
            'auto_actions_triggered': self.auto_actions_triggered,
            'escalation_path': self.escalation_path
        }

class TriageEngine:
    def score_incident(self, incident: Dict[str, Any],
                       alerts: List[Dict[str, Any]],
                       persona_scores: Dict[str, Any] = None) -> TriageScore:
        if persona_scores is None:
            persona_scores = {}
            
        score = 0.0
        breakdown = {}

        # ── Factor 1: Severity composition ─────────────────────────────
        sev_weights = {'critical': 40, 'high': 25, 'medium': 10, 'low': 3}
        sev_score = sum(sev_weights.get(a.get('severity', 'low'), 0) for a in alerts)
        sev_score = min(sev_score, 40)
        score += sev_score
        breakdown['severity_composition'] = sev_score

        # ── Factor 2: Kill chain completion ────────────────────────────
        tactics = incident.get('mitre_tactics', [])
        kc_score = min(len(tactics) / 4.0, 1.0) * 25
        score += kc_score
        breakdown['kill_chain_completion'] = round(kc_score, 1)

        # ── Factor 3: Persona deviation ────────────────────────────────
        persona_max = max(
            (persona_scores.get(a.get('user'), {}).get('persona_score', 0) for a in alerts),
            default=0
        )
        persona_contrib = persona_max * 15
        score += persona_contrib
        breakdown['persona_deviation'] = round(persona_contrib, 1)

        # ── Factor 4: IOC confirmation ─────────────────────────────────
        ioc_confirmed = any(a.get('confidence_score', 0) >= 0.8 or 'THREAT INTEL' in str(a.get('raw_message', '')) for a in alerts)
        ioc_score = 15 if ioc_confirmed else 0
        score += ioc_score
        breakdown['ioc_confirmed'] = ioc_score

        # ── Factor 5: Asset criticality ────────────────────────────────
        targets = set(a.get('user') for a in alerts if a.get('user'))
        admin_count = sum(1 for t in targets if any(k in str(t).lower() for k in ['admin', 'root', 'svc', 'service']))
        asset_score = min(admin_count * 15, 15)  # Make it 15 if any admin is involved
        score += asset_score
        breakdown['asset_criticality'] = asset_score

        # ── Factor 6: Recency and velocity ─────────────────────────────
        alert_span_mins = self._compute_alert_span(alerts)
        velocity = len(alerts) / max(alert_span_mins, 1)
        vel_score = min(velocity * 10, 5)
        score += vel_score
        breakdown['alert_velocity'] = round(vel_score, 1)

        score = min(round(score, 1), 100)

        # Determine priority
        priority = (
            TriagePriority.P1_CRITICAL if score >= 70 else
            TriagePriority.P2_HIGH     if score >= 45 else
            TriagePriority.P3_MEDIUM   if score >= 20 else
            TriagePriority.P4_LOW
        )

        sla = SLA_MINUTES[priority]
        now = datetime.now(timezone.utc)

        # Determine analyst tier
        tier = 'L3' if score >= 80 else 'L2' if score >= 50 else 'L1'

        # Auto-trigger actions for P1
        auto_actions = []
        if priority == TriagePriority.P1_CRITICAL:
            if ioc_confirmed:
                auto_actions.append('block_ip_auto')
            if admin_count > 0:
                auto_actions.append('force_mfa_reset')
            auto_actions.append('notify_on_call')

        return TriageScore(
            incident_id=incident.get('id', 'unknown'),
            priority=priority,
            triage_score=score,
            score_breakdown=breakdown,
            ack_deadline=now + timedelta(minutes=sla['ack']),
            resolve_deadline=now + timedelta(minutes=sla['resolve']),
            recommended_analyst_tier=tier,
            auto_actions_triggered=auto_actions,
            escalation_path=self._build_escalation_path(priority, tier)
        )

    def _compute_alert_span(self, alerts: List[Dict[str, Any]]) -> float:
        if len(alerts) < 2:
            return 1.0
        times = []
        for a in alerts:
            if t_str := a.get('created_at'):
                try:
                    times.append(datetime.fromisoformat(t_str))
                except Exception:
                    pass
        if len(times) < 2:
            return 1.0
        times = sorted(times)
        return (times[-1] - times[0]).total_seconds() / 60

    def _build_escalation_path(self, priority: TriagePriority, tier: str) -> List[str]:
        paths = {
            TriagePriority.P1_CRITICAL: [
                'Auto-block triggered',
                'L3 analyst paged',
                'CISO notified at T+15min if unacknowledged',
                'Incident commander assigned at T+30min'
            ],
            TriagePriority.P2_HIGH: [
                'L2 analyst assigned',
                'L3 escalation at T+60min if unresolved',
                'Manager notified at T+2h'
            ],
            TriagePriority.P3_MEDIUM: [
                'L1 analyst queue',
                'L2 escalation at T+4h if unresolved'
            ],
            TriagePriority.P4_LOW: [
                'L1 analyst queue — next business day acceptable'
            ]
        }
        return paths.get(priority, [])

triage_engine = TriageEngine()
