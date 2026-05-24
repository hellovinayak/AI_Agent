import networkx as nx
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

class LateralMovementDetector:
    def __init__(self):
        self._access_graph = nx.DiGraph()
        self._access_timestamps = defaultdict(list)
        self._baseline_graph: Optional[nx.DiGraph] = None

    def record_access(self, log: Dict[str, Any]):
        """Record every authenticated resource access as a graph edge"""
        user = log.get('user_id') or log.get('user_name')
        resource = log.get('target_resource') or log.get('destination_ip')
        if not user or not resource:
            return

        edge_key = (user, resource)
        try:
            ts = datetime.fromisoformat(log.get('timestamp', datetime.now(timezone.utc).isoformat()))
        except Exception:
            ts = datetime.now(timezone.utc)
            
        self._access_timestamps[edge_key].append(ts)

        # Edge weight = access frequency (higher = more normal)
        current_weight = self._access_graph.get_edge_data(user, resource, default={'weight': 0})['weight']
        self._access_graph.add_edge(
            user, resource,
            weight=current_weight + 1,
            last_access=ts.isoformat()
        )

    def detect_lateral_movement(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        user = log.get('user_id') or log.get('user_name')
        resource = log.get('target_resource') or log.get('destination_ip')
        if not user or not resource:
            return None

        signals = []
        score = 0.0

        # ── Signal 1: New resource access (first hop) ──────────────────
        if not self._access_graph.has_edge(user, resource):
            signals.append({
                'type': 'new_resource_access',
                'description': f'{user} accessing {resource} for first time'
            })
            score += 0.25

        # ── Signal 2: Rapid hop expansion ─────────────────────────────
        recent_new = self._count_new_accesses_in_window(user, hours=1)
        if recent_new > 5:
            signals.append({
                'type': 'rapid_hop_expansion',
                'description': f'{user} accessed {recent_new} new resources in the last hour — recon pattern'
            })
            score += 0.30

        # ── Signal 3: Path length anomaly ─────────────────────────────
        if self._baseline_graph:
            path_anomaly = self._detect_path_anomaly(user, resource)
            if path_anomaly > 2:
                signals.append({
                    'type': 'access_path_anomaly',
                    'description': f'Resource is {path_anomaly:.1f} hops outside {user}\'s normal access neighborhood'
                })
                score += 0.25

        # ── Signal 4: Credential sharing pattern ──────────────────────
        source_ip = log.get('source_ip')
        if source_ip:
            same_ip_users = self._find_same_ip_users(source_ip, resource)
            if len(same_ip_users) > 2:
                signals.append({
                    'type': 'credential_sharing_suspected',
                    'description': f'{len(same_ip_users)} different users accessed {resource} from {source_ip} — possible credential sharing or pivot'
                })
                score += 0.35

        # ── Signal 5: Service account lateral access ───────────────────
        if str(user).startswith('svc_') or 'service' in str(user).lower():
            if log.get('event_type') == 'interactive_login':
                signals.append({
                    'type': 'service_account_interactive',
                    'description': f'Service account {user} created interactive session — highly unusual'
                })
                score += 0.40

        if score >= 0.40 and signals:
            return {
                'rule_id': 'DET-013',
                'alert_type': 'Lateral Movement',
                'severity': 'critical' if score >= 0.70 else 'high',
                'confidence': min(score, 0.95),
                'user_id': user,
                'target_resource': resource,
                'lateral_signals': signals,
                'description': f'Lateral movement detected: {len(signals)} signals across {user} → {resource}. ' + signals[0]['description'],
                'mitre_technique': 'T1021',
                'graph_snapshot': self._export_subgraph(user)
            }
        return None

    def _count_new_accesses_in_window(self, user: str, hours: int = 1) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        count = 0
        for (u, r), timestamps in self._access_timestamps.items():
            if u != user:
                continue
            first_access = min(timestamps)
            recent_accesses = [t for t in timestamps if t > cutoff]
            if recent_accesses and first_access > cutoff:
                count += 1
        return count

    def _detect_path_anomaly(self, user: str, resource: str) -> float:
        if not self._baseline_graph or user not in self._baseline_graph:
            return 0.0
        neighbors = set(self._baseline_graph.successors(user))
        if not neighbors:
            return 0.0
        if resource in neighbors:
            return 0.0
        min_dist = float('inf')
        for neighbor in list(neighbors)[:20]:
            try:
                d = nx.shortest_path_length(self._baseline_graph, neighbor, resource)
                min_dist = min(min_dist, d)
            except nx.NetworkXNoPath:
                continue
        return min_dist if min_dist != float('inf') else 3.0

    def _find_same_ip_users(self, ip: str, resource: str) -> set:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
        users = set()
        for (u, r), timestamps in self._access_timestamps.items():
            if r == resource:
                recent = [t for t in timestamps if t > cutoff]
                if recent:
                    users.add(u)
        return users

    def _export_subgraph(self, user: str, depth: int = 2) -> dict:
        nodes_to_include = {user}
        for _ in range(depth):
            neighbors = set()
            for n in nodes_to_include:
                if n in self._access_graph:
                    neighbors.update(self._access_graph.successors(n))
                    neighbors.update(self._access_graph.predecessors(n))
            nodes_to_include.update(neighbors)

        sub = self._access_graph.subgraph(nodes_to_include)
        return {
            'nodes': [{'id': n, 'type': 'user' if '@' in str(n) else 'resource'} for n in sub.nodes()],
            'edges': [{'source': u, 'target': v, 'weight': d.get('weight', 1)} for u, v, d in sub.edges(data=True)]
        }

    def snapshot_baseline(self):
        """Call nightly to establish what normal access looks like"""
        self._baseline_graph = self._access_graph.copy()

lateral_movement_detector = LateralMovementDetector()
