import uuid
from datetime import datetime
from typing import Dict, List, Any
import networkx as nx
from dataclasses import dataclass

# Define known kill chains as graph paths
KILL_CHAIN_GRAPH = {
    'DET-001': ['DET-002', 'DET-003', 'DET-008'],  # BruteForce -> GeoAnomaly or AdminTarget or PrivEsc
    'DET-002': ['DET-007', 'DET-008'],             # GeoAnomaly -> TokenReuse or PrivEsc
    'DET-003': ['DET-008', 'DET-005', 'DET-006'],  # AdminTarget -> PrivEsc or DataAccess
    'DET-008': ['DET-005', 'DET-006'],             # PrivEsc -> DBQuery or Exfil
    'DET-005': ['DET-006'],                        # DBQuery -> Exfil
    'DET-009': ['DET-006', 'DET-008']              # ZeroDay -> anything
}

# MITRE ATT&CK stage mapping
KILL_CHAIN_STAGES = {
    'DET-001': 'Initial Access / Credential Access',
    'DET-002': 'Defense Evasion',
    'DET-003': 'Privilege Escalation',
    'DET-004': 'Discovery',
    'DET-005': 'Collection',
    'DET-006': 'Exfiltration',
    'DET-007': 'Lateral Movement',
    'DET-008': 'Privilege Escalation',
    'DET-009': 'Unknown / Zero-Day'
}

class AttackProgressionGraph:
    def __init__(self):
        self.graph = {}
        self.edges = []

    def add_alert(self, alert: dict):
        node_id = alert['id']
        self.graph[node_id] = {
            'type': 'alert',
            'rule': alert['rule_id'],
            'severity': alert['severity'],
            'timestamp': alert['timestamp'],
            'user': alert['user'],
            'ip': alert['ip_address'],
            'confidence': alert['confidence_score']
        }

    def add_causal_edge(self, from_alert_id: str, to_alert_id: str, reason: str):
        self.edges.append({
            'from': from_alert_id,
            'to': to_alert_id,
            'reason': reason,
            'weight': self._edge_weight(reason)
        })

    def _edge_weight(self, reason: str) -> float:
        return {
            'kill_chain_step': 1.0,
            'same_user': 0.8,
            'same_ip': 0.6,
            'temporal_sequence': 0.4
        }.get(reason, 0.3)


class EntityGraph:
    def __init__(self):
        self.G = nx.MultiDiGraph()

    def ingest_event(self, event: dict):
        user_node = f"user:{event['user']}"
        ip_node = f"ip:{event['ip_address']}"
        device_node = f"device:{event.get('device', 'unknown')}"

        self.G.add_node(user_node, type='user', label=event['user'])
        self.G.add_node(ip_node, type='ip', label=event['ip_address'])
        self.G.add_node(device_node, type='device', label=event.get('device', 'unknown'))

        self.G.add_edge(
            user_node,
            ip_node,
            relation='connected_from',
            timestamp=event['timestamp'],
            alert_id=event.get('id')
        )
        self.G.add_edge(
            user_node,
            device_node,
            relation='used_device',
            timestamp=event['timestamp'],
            alert_id=event.get('id')
        )

    def find_blast_radius(self, compromised_entity: str, hops: int = 2) -> list:
        if not self.G.has_node(compromised_entity):
            return []
        try:
            return list(nx.single_source_shortest_path(self.G, compromised_entity, cutoff=hops).keys())
        except Exception:
            return []

    def find_shared_infrastructure(self, ip: str) -> list:
        ip_node = f"ip:{ip}"
        if not self.G.has_node(ip_node):
            return []
        return [
            n for n in self.G.predecessors(ip_node)
            if self.G.nodes[n].get('type') == 'user'
        ]

    def find_pivot_points(self) -> list:
        centrality = nx.betweenness_centrality(self.G)
        return sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:10]

def score_incident_graph(G: nx.DiGraph) -> dict:
    try:
        longest_chain = nx.dag_longest_path_length(G) if nx.is_directed_acyclic_graph(G) else 0
        critical_path = nx.dag_longest_path(G) if nx.is_directed_acyclic_graph(G) else []
    except Exception:
        longest_chain = 0
        critical_path = []

    return {
        'longest_chain': longest_chain,
        'max_blast_radius': max(dict(G.out_degree()).values(), default=0),
        'entry_points': len([n for n in G.nodes if G.in_degree(n) == 0]),
        'attack_density': nx.density(G) if len(G.nodes) > 0 else 0,
        'critical_path': critical_path
    }

def _predict_next(last_rule: str) -> dict:
    possible_next = KILL_CHAIN_GRAPH.get(last_rule, [])
    if not possible_next:
        return {'prediction': 'unknown', 'confidence': 0.0}
    return {
        'prediction': possible_next[0],
        'stage': KILL_CHAIN_STAGES.get(possible_next[0], 'unknown'),
        'confidence': 0.72,
        'recommendation': f"Pre-emptively monitor for {possible_next[0]}"
    }

def match_kill_chain(alert_sequence: list[str]) -> dict:
    matched_chains = []
    for i in range(len(alert_sequence) - 1):
        current = alert_sequence[i]
        next_alert = alert_sequence[i + 1]
        if next_alert in KILL_CHAIN_GRAPH.get(current, []):
            matched_chains.append({
                'from_rule': current,
                'to_rule': next_alert,
                'from_stage': KILL_CHAIN_STAGES.get(current, 'Unknown'),
                'to_stage': KILL_CHAIN_STAGES.get(next_alert, 'Unknown'),
                'confidence': 0.85
            })

    completion = len(matched_chains) / max(len(alert_sequence) - 1, 1) if alert_sequence else 0
    predicted = _predict_next(alert_sequence[-1]) if alert_sequence else {'prediction': 'unknown', 'confidence': 0.0}
    return {
        'matched_steps': matched_chains,
        'kill_chain_completion': round(completion, 2),
        'is_confirmed_chain': completion > 0.6,
        'predicted_next_step': predicted
    }

@dataclass
class TemporalEdge:
    source: str
    target: str
    relation: str
    timestamp: datetime
    alert_id: str
    severity: str

class TemporalAttackGraph:
    def __init__(self):
        self.edges: list[TemporalEdge] = []

    def add_event(self, event: dict):
        try:
            ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        except Exception:
            ts = datetime.now()

        self.edges.append(TemporalEdge(
            source=f"user:{event['user']}",
            target=f"ip:{event['ip_address']}",
            relation=event['rule_id'],
            timestamp=ts,
            alert_id=event['id'],
            severity=event['severity']
        ))

    def snapshot_at(self, t: datetime) -> dict:
        active_edges = [e for e in self.edges if e.timestamp <= t]
        nodes = set()
        for e in active_edges:
            nodes.add(e.source)
            nodes.add(e.target)
        
        return {
            'nodes': [{'id': n, 'label': n} for n in nodes],
            'edges': [{'from': e.source, 'to': e.target, 'reason': e.relation} for e in active_edges],
        }

    def to_animation_frames(self, interval_seconds: int = 30) -> list:
        if not self.edges:
            return []
        start = min(e.timestamp for e in self.edges)
        end = max(e.timestamp for e in self.edges)
        frames = []
        current = start
        while current <= end:
            frames.append(self.snapshot_at(current))
            current = datetime.fromtimestamp(current.timestamp() + interval_seconds)
        # Always include final state
        frames.append(self.snapshot_at(end))
        return frames

def propagate_risk(entity_graph: nx.DiGraph, compromised_node: str, initial_risk: float = 1.0, decay: float = 0.6) -> dict:
    risk_scores = {compromised_node: initial_risk}
    visited = {compromised_node}
    queue = [(compromised_node, initial_risk)]

    while queue:
        node, risk = queue.pop(0)
        for neighbor in entity_graph.successors(node):
            if neighbor not in visited:
                edge_data = entity_graph.get_edge_data(node, neighbor) or {}
                # Handle MultiDiGraph edge data format
                if isinstance(edge_data, dict) and 0 in edge_data:
                    edge_data = edge_data[0]
                    
                edge_weight = edge_data.get('weight', 0.5)
                centrality = nx.degree_centrality(entity_graph).get(neighbor, 0.1)
                propagated_risk = risk * decay * edge_weight * (1 + centrality)
                
                risk_scores[neighbor] = min(propagated_risk, risk_scores.get(neighbor, 0) + propagated_risk)
                visited.add(neighbor)
                
                if propagated_risk > 0.1:
                    queue.append((neighbor, propagated_risk))

    return {
        'risk_scores': risk_scores,
        'critical_nodes': [node for node, score in risk_scores.items() if score > 0.7],
        'total_affected_entities': len(risk_scores),
        'max_propagated_risk': max(risk_scores.values(), default=0)
    }

def determine_edge_reason(alert1: dict, alert2: dict) -> str:
    if alert2['rule_id'] in KILL_CHAIN_GRAPH.get(alert1['rule_id'], []):
        return 'kill_chain_step'
    if alert1['user'] == alert2['user']:
        return 'same_user'
    if alert1['ip_address'] == alert2['ip_address']:
        return 'same_ip'
    return 'temporal_sequence'

def build_networkx_graph(entity_graph: EntityGraph, progression_graph: AttackProgressionGraph) -> nx.DiGraph:
    G = nx.DiGraph()
    # Add nodes from entity graph
    for node, data in entity_graph.G.nodes(data=True):
        G.add_node(node, **data)
    
    # Add edges from progression graph, linking alerts and entities where possible
    # We will map alerts to their users/ips
    for node_id, data in progression_graph.graph.items():
        G.add_node(node_id, **data)
        G.add_edge(f"user:{data['user']}", node_id, reason='triggered_by')
        G.add_edge(f"ip:{data['ip']}", node_id, reason='originated_from')
        
    for edge in progression_graph.edges:
        G.add_edge(edge['from'], edge['to'], reason=edge['reason'], weight=edge['weight'])
        
    return G

# Global instance for live graph
global_entity_graph = EntityGraph()
