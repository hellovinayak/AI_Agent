from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Dict, List, Set, Any, Optional

from app.database.db import get_db

logger = logging.getLogger(__name__)

@dataclass
class EntityPersona:
    entity_id: str
    entity_type: str  # user | ip | device
    
    # Behavioral fingerprint
    typical_hours: List[float] = field(default_factory=list)
    typical_day_of_week: List[int] = field(default_factory=list)
    known_peers: Set[str] = field(default_factory=set)
    known_destinations: Set[str] = field(default_factory=set)
    known_actions: Dict[str, int] = field(default_factory=dict)
    
    # Velocity fingerprint
    avg_events_per_hour: float = 0.0
    avg_data_volume_mb: float = 0.0
    avg_unique_resources: float = 0.0
    
    # Risk history
    confirmed_incidents: int = 0
    false_positive_rate: float = 0.0
    last_anomaly_at: Optional[datetime] = None
    
    # Peer group
    role: str = 'unknown'
    department: str = 'unknown'
    peer_group_id: Optional[str] = None
    
    # Metadata
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    observation_days: int = 0

class PersonaEngine:
    def __init__(self):
        self._personas: Dict[str, EntityPersona] = {}
        self._peer_groups: Dict[str, List[EntityPersona]] = defaultdict(list)
        self._loaded = False

    async def _ensure_loaded(self):
        if not self._loaded:
            await self._load_from_db()
            self._loaded = True

    async def update_persona(self, log_entry: Dict[str, Any]) -> None:
        """Called on every log event — updates the entity's behavioral model"""
        await self._ensure_loaded()
        entity_id = log_entry.get('user_id') or log_entry.get('source_ip') or log_entry.get('user_name')
        if not entity_id:
            return

        persona = self._personas.setdefault(
            entity_id,
            EntityPersona(
                entity_id=entity_id,
                entity_type='user' if log_entry.get('user_id') or log_entry.get('user_name') else 'ip'
            )
        )

        try:
            ts = datetime.fromisoformat(log_entry.get('timestamp', datetime.now(timezone.utc).isoformat()))
        except Exception:
            ts = datetime.now(timezone.utc)

        # Update temporal patterns
        hour = ts.hour
        persona.typical_hours.append(hour)
        if len(persona.typical_hours) > 1000:
            persona.typical_hours = persona.typical_hours[-1000:]

        # Update resource access patterns
        if dest := log_entry.get('destination_ip'):
            persona.known_destinations.add(dest)

        # Update action frequency
        action = log_entry.get('event_type', 'unknown')
        persona.known_actions[action] = persona.known_actions.get(action, 0) + 1

        persona.last_updated = datetime.now(timezone.utc)
        persona.observation_days = max(
            persona.observation_days,
            (datetime.now(timezone.utc) - persona.first_seen).days
        )
        await self._persist_persona(persona)

    async def score_against_persona(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns a deviation score and human-readable explanation.
        0.0 = perfectly normal, 1.0 = completely unprecedented
        """
        await self._ensure_loaded()
        entity_id = log_entry.get('user_id') or log_entry.get('source_ip') or log_entry.get('user_name')
        persona = self._personas.get(entity_id)

        # Fast-track learning phase - be lenient if less than 3 events
        if not persona or len(persona.typical_hours) < 3:
            return {
                'entity_id': entity_id,
                'persona_score': 0.1,
                'confidence': 'low',
                'reason': 'insufficient_history',
                'deviations': [],
                'explanation': 'Insufficient behavioral history to determine deviation.'
            }

        try:
            ts = datetime.fromisoformat(log_entry.get('timestamp', datetime.now(timezone.utc).isoformat()))
        except Exception:
            ts = datetime.now(timezone.utc)

        deviations = []
        score = 0.0

        # ── Temporal deviation ──────────────────────────────────────────
        current_hour = ts.hour
        hour_array = np.array(persona.typical_hours)
        hour_sin = np.sin(2 * np.pi * hour_array / 24)
        hour_cos = np.cos(2 * np.pi * hour_array / 24)
        current_sin = np.sin(2 * np.pi * current_hour / 24)
        current_cos = np.cos(2 * np.pi * current_hour / 24)

        mean_sin = np.mean(hour_sin)
        mean_cos = np.mean(hour_cos)
        temporal_dist = np.sqrt((current_sin - mean_sin)**2 + (current_cos - mean_cos)**2)

        if temporal_dist > 1.2:
            deviation_hours = abs(current_hour - self._modal_hour(persona.typical_hours))
            score += 0.25
            deviations.append({
                'type': 'temporal',
                'severity': 'high',
                'description': (
                    f'Activity at {current_hour:02d}:00 — '
                    f'{deviation_hours:.0f}h outside normal window '
                    f'(usual: {self._format_hour_range(persona.typical_hours)})'
                )
            })

        # ── New destination deviation ───────────────────────────────────
        dest = log_entry.get('destination_ip')
        if dest and dest not in persona.known_destinations and len(persona.known_destinations) > 2:
            score += 0.20
            deviations.append({
                'type': 'new_destination',
                'severity': 'medium',
                'description': (
                    f'First-ever connection to {dest} — '
                    f'entity has {len(persona.known_destinations)} known destinations'
                )
            })

        # ── Action rarity ───────────────────────────────────────────────
        action = log_entry.get('event_type', '')
        total_actions = sum(persona.known_actions.values())
        action_freq = persona.known_actions.get(action, 0) / max(total_actions, 1)
        if action_freq < 0.05 and total_actions > 10:
            score += 0.20
            deviations.append({
                'type': 'rare_action',
                'severity': 'medium',
                'description': (
                    f'Action "{action}" accounts for <5% of this entity\'s historical behavior'
                )
            })

        # ── Peer group deviation ────────────────────────────────────────
        peer_score = self._score_vs_peer_group(ts, persona)
        if peer_score > 0.7:
            score += 0.25
            deviations.append({
                'type': 'peer_group_outlier',
                'severity': 'high',
                'description': f'Behavior is an outlier among {persona.role} peers'
            })

        # ── Recency of prior anomalies ──────────────────────────────────
        if persona.last_anomaly_at:
            hours_since = (datetime.now(timezone.utc) - persona.last_anomaly_at).total_seconds() / 3600
            if hours_since < 24:
                score += 0.10
                deviations.append({
                    'type': 'repeated_anomaly',
                    'severity': 'medium',
                    'description': f'Entity had anomalous activity {hours_since:.1f}h ago — escalating pattern'
                })

        return {
            'entity_id': entity_id,
            'persona_score': min(round(score, 3), 1.0),
            'confidence': 'high' if len(persona.typical_hours) > 20 else 'medium',
            'observation_days': persona.observation_days,
            'deviations': deviations,
            'peer_group': persona.peer_group_id,
            'explanation': self._build_explanation(deviations, score)
        }

    def _score_vs_peer_group(self, ts: datetime, persona: EntityPersona) -> float:
        if not persona.peer_group_id:
            return 0.0
        peers = self._peer_groups.get(persona.peer_group_id, [])
        if len(peers) < 3:
            return 0.0

        current_hour = ts.hour
        peer_hours = [h for p in peers for h in p.typical_hours[-100:]]
        if not peer_hours:
            return 0.0

        peer_hour_dist = np.histogram(peer_hours, bins=24, range=(0, 24))[0]
        peer_hour_prob = peer_hour_dist[current_hour] / max(peer_hour_dist.sum(), 1)
        return 1.0 - peer_hour_prob

    def _modal_hour(self, hours: List[float]) -> int:
        if not hours:
            return 12
        return int(np.bincount([int(h) for h in hours]).argmax())

    def _format_hour_range(self, hours: List[float]) -> str:
        if not hours:
            return 'unknown'
        arr = np.array([int(h) for h in hours])
        lo = int(np.percentile(arr, 10))
        hi = int(np.percentile(arr, 90))
        return f'{lo:02d}:00–{hi:02d}:00'

    def _build_explanation(self, deviations: list, score: float) -> str:
        if not deviations:
            return 'Behavior consistent with historical persona.'
        parts = [d['description'] for d in deviations]
        severity = 'CRITICAL' if score > 0.7 else 'HIGH' if score > 0.4 else 'MEDIUM'
        return f'{severity} persona deviation: ' + '. '.join(parts) + '.'

    async def get_riskiest_entities(self, top_n: int = 10) -> list:
        await self._ensure_loaded()
        scored = []
        for entity_id, persona in self._personas.items():
            risk = (
                min(persona.confirmed_incidents * 0.2, 0.4) +
                (0.2 if persona.last_anomaly_at and (datetime.now(timezone.utc) - persona.last_anomaly_at).days < 1 else 0) +
                (1 - persona.false_positive_rate) * 0.4
            )
            scored.append({
                'entity_id': entity_id,
                'entity_type': persona.entity_type,
                'risk_score': round(min(risk, 1.0), 3),
                'confirmed_incidents': persona.confirmed_incidents,
                'observation_days': persona.observation_days,
                'last_anomaly_at': persona.last_anomaly_at.isoformat() if persona.last_anomaly_at else None
            })
        return sorted(scored, key=lambda x: x['risk_score'], reverse=True)[:top_n]

    async def _persist_persona(self, persona: EntityPersona):
        try:
            db = await get_db()
            await db.execute("""
                INSERT OR REPLACE INTO entity_personas
                (entity_id, entity_type, typical_hours, known_destinations,
                 known_actions, avg_events_per_hour, confirmed_incidents,
                 observation_days, last_updated, peer_group_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                persona.entity_id, persona.entity_type,
                json.dumps(persona.typical_hours[-200:]),
                json.dumps(list(persona.known_destinations)),
                json.dumps(persona.known_actions),
                persona.avg_events_per_hour,
                persona.confirmed_incidents,
                persona.observation_days,
                persona.last_updated.isoformat(),
                persona.peer_group_id
            ))
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to persist persona {persona.entity_id}: {e}")

    async def _load_from_db(self):
        try:
            db = await get_db()
            rows = await db.execute("SELECT * FROM entity_personas")
            rows = await rows.fetchall()
            for row in rows:
                row_dict = dict(row)
                p = EntityPersona(
                    entity_id=row_dict['entity_id'],
                    entity_type=row_dict['entity_type'],
                    typical_hours=json.loads(row_dict['typical_hours'] or '[]'),
                    known_destinations=set(json.loads(row_dict['known_destinations'] or '[]')),
                    known_actions=json.loads(row_dict['known_actions'] or '{}'),
                    confirmed_incidents=row_dict['confirmed_incidents'] or 0,
                    observation_days=row_dict['observation_days'] or 0,
                    peer_group_id=row_dict.get('peer_group_id')
                )
                self._personas[row_dict['entity_id']] = p
                if p.peer_group_id:
                    self._peer_groups[p.peer_group_id].append(p)
        except Exception as e:
            logger.error(f"Failed to load personas: {e}")

persona_engine = PersonaEngine()
