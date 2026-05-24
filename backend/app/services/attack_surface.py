import sqlite3
from typing import Dict, List, Any
from app.core.config import settings

def _get_db():
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn

class AttackSurfaceScorer:
    """Pre-attack surface scoring to identify risky users."""
    
    def score_user(self, user_id: str) -> dict:
        conn = _get_db()
        try:
            # Get user's alert history
            cursor = conn.execute(
                "SELECT rule_id, status, severity FROM alerts WHERE user = ? ORDER BY timestamp DESC LIMIT 100", 
                (user_id,)
            )
            history = [dict(r) for r in cursor.fetchall()]
            
            # Baseline (mocked for demo purposes if not existing)
            baseline = {
                'mfa_enrolled': user_id not in ['sa_backup', 'admin', 'test_user'], # just a mock logic
                'is_admin': user_id in ['admin', 'root', 'sa_backup']
            }
            
            score = 0.0
            factors = []

            if not baseline.get('mfa_enrolled'):
                score += 0.3
                factors.append('No MFA enrolled (+30%)')

            if baseline.get('is_admin'):
                score += 0.2
                factors.append('Admin privileges (+20%)')

            # Since we don't have analyst_verdict yet, we just check open/in_incident alerts
            prior_incidents = len([h for h in history if h['status'] in ['open', 'in_incident']])
            if prior_incidents > 0:
                score += min(prior_incidents * 0.1, 0.3)
                factors.append(f'{prior_incidents} prior active alerts')

            geo_anomaly_count = len([h for h in history if h['rule_id'] == 'DET-002'])
            if geo_anomaly_count > 2:
                score += 0.15
                factors.append(f'{geo_anomaly_count} geo anomalies in 30 days')

            return {
                'user_id': user_id,
                'attack_surface_score': min(score, 1.0),
                'risk_factors': factors,
                'recommendation': self._recommend(score)
            }
        finally:
            conn.close()
            
    def _recommend(self, score: float) -> str:
        if score > 0.7:
            return "Immediate remediation required: Enforce MFA and review privileges."
        elif score > 0.4:
            return "Monitor closely. Consider step-up authentication."
        return "Risk within acceptable limits."
        
    def get_leaderboard(self) -> List[dict]:
        """Get the top risky users across the platform."""
        conn = _get_db()
        try:
            # Find all unique users in alerts
            cursor = conn.execute("SELECT DISTINCT user FROM alerts WHERE user != 'unknown'")
            users = [r['user'] for r in cursor.fetchall()]
            
            scores = []
            for u in users:
                scores.append(self.score_user(u))
                
            # Sort by highest score first
            scores.sort(key=lambda x: x['attack_surface_score'], reverse=True)
            return scores[:10]
        finally:
            conn.close()

attack_surface_scorer = AttackSurfaceScorer()
